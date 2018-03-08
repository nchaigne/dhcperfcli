/*
 * dhcperfcli.c
 */

#include "dhcperfcli.h"
#include "dpc_packet_list.h"
#include "dpc_util.h"


static char const *prog_version = "(FreeRADIUS version " RADIUSD_VERSION_STRING ")"
#ifdef RADIUSD_VERSION_COMMIT
" (git #" STRINGIFY(RADIUSD_VERSION_COMMIT) ")"
#endif
", built on " __DATE__ " at " __TIME__;


/*
 *	Global variables.
 */
TALLOC_CTX *autofree = NULL;

struct timeval tv_start; /* Program execution start time. */
int	dpc_debug_lvl = 0;

static char const *progname = NULL;
static char const *radius_dir = RADDBDIR;
static char const *dict_dir = DICTDIR;
static fr_dict_t *dict = NULL;
static int packet_trace_lvl = -1; /* If unspecified, figure out something automatically. */

static dpc_packet_list_t *pl = NULL; /* List of outgoing packets. */
static fr_event_list_t *event_list = NULL;

static char const *file_vps_in = NULL;
static dpc_input_list_t vps_list_in = { 0 };
static bool with_template = false;
static dpc_input_t *template_invariant = NULL;
static dpc_input_t *template_variable = NULL;

static fr_ipaddr_t server_ipaddr = { .af = AF_INET, .prefix = 32 };
static fr_ipaddr_t client_ipaddr = { .af = AF_INET, .prefix = 32 };
static uint16_t server_port = DHCP_PORT_SERVER;
static uint16_t client_port = DHCP_PORT_CLIENT;
static dpc_endpoint_t *gateway = NULL;
static int force_af = AF_INET; // we only do DHCPv4.
static int packet_code = FR_CODE_UNDEFINED;
static int workflow_code = DPC_WORKFLOW_NONE;

static float timeout = 3.0;
static struct timeval tv_timeout;
static uint32_t base_xid = 0;
static uint32_t session_max_active = 1;
static uint32_t session_max_num = 0; /* Default: consume all input (or in template mode, no limit). */
static bool start_sessions_flag =  true; /* Allow starting new sessions. */

static uint32_t session_num = 0; /* Number of sessions initialized. */
static uint32_t input_num = 0; /* Number of input entries read. (They may not all be valid.) */
static bool job_done = false;
static bool signal_done = false;

static uint32_t session_num_active = 0; /* Number of active sessions. */

static const FR_NAME_NUMBER request_types[] = {
	{ "discover",    FR_DHCPV4_DISCOVER },
	{ "request",     FR_DHCPV4_REQUEST },
	{ "decline",     FR_DHCPV4_DECLINE },
	{ "release",     FR_DHCPV4_RELEASE },
	{ "inform",      FR_DHCPV4_INFORM },
	{ "lease_query", FR_DHCPV4_LEASE_QUERY },
	{ "auto",        FR_CODE_UNDEFINED },
	{ NULL, 0}
};

static const FR_NAME_NUMBER workflow_types[] = {
	{ "dora",        DPC_WORKFLOW_DORA },
	{ NULL, 0}
};


/*
 *	Static functions declaration.
 */
static void usage(int);

static void dpc_request_timeout(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, void *uctx);
static void dpc_event_add_request_timeout(dpc_session_ctx_t *session);

static int dpc_send_one_packet(RADIUS_PACKET **packet_p);
static int dpc_recv_one_packet(struct timeval *tv_wait_time);
static bool dpc_recv_post_action(dpc_session_ctx_t *session);
static RADIUS_PACKET *dpc_request_init(TALLOC_CTX *ctx, dpc_input_t *input);
static int dpc_dhcp_encode(RADIUS_PACKET *packet);

static dpc_input_t *dpc_gen_input_from_template(TALLOC_CTX *ctx);
static dpc_input_t *dpc_get_input(void);
static dpc_session_ctx_t *dpc_session_init(TALLOC_CTX *ctx);
static void dpc_session_finish(dpc_session_ctx_t *session);

static void dpc_loop_recv(void);
static void dpc_loop_start_sessions(void);
static bool dpc_loop_check_done(void);
static void dpc_main_loop(void);

static bool dpc_parse_input(dpc_input_t *input);
static void dpc_handle_input(dpc_input_t *input, dpc_input_list_t *list);
static void dpc_input_load_from_fd(TALLOC_CTX *ctx, FILE *file_in, dpc_input_list_t *list);
static int dpc_input_load(TALLOC_CTX *ctx);

static void dpc_dict_init(TALLOC_CTX *ctx);
static void dpc_event_list_init(TALLOC_CTX *ctx);
static void dpc_packet_list_init(TALLOC_CTX *ctx);
static void dpc_host_addr_resolve(char *host_arg, fr_ipaddr_t *host_ipaddr, uint16_t *host_port);
static void dpc_command_parse(char const *command);
static void dpc_options_parse(int argc, char **argv);


/*
 *	Event callback: request timeout.
 */
static void dpc_request_timeout(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, void *uctx)
{
	dpc_session_ctx_t *session = talloc_get_type_abort(uctx, dpc_session_ctx_t);

	DPC_DEBUG_TRACE("Request timed out");

	if (packet_trace_lvl >= 1) dpc_packet_header_print(fr_log_fp, session->packet, DPC_PACKET_TIMEOUT);

	/* Finish the session. */
	dpc_session_finish(session);
}

/*
 *	Add timer event: request timeout.
 */
static void dpc_event_add_request_timeout(dpc_session_ctx_t *session)
{
	struct timeval tv_event;
	gettimeofday(&tv_event, NULL);

	struct timeval *my_timeout = &tv_timeout;

	timeradd(&tv_event, my_timeout, &tv_event);

	if (fr_event_timer_insert(session, event_list, &session->event,
	                          &tv_event, dpc_request_timeout, session) < 0) {
		ERROR("Failed inserting request timeout event");
	}
}

/*
 *	Send one packet.
 *	Grab a socket, insert packet in the packet list (and obtain an id), encode DHCP packet, and send it.
 */
static int dpc_send_one_packet(RADIUS_PACKET **packet_p)
// note: we need a 'RADIUS_PACKET **' for dpc_packet_list_id_alloc.
{
	RADIUS_PACKET *packet = *packet_p;

	DPC_DEBUG_TRACE("Preparing to send one packet");

	int my_sockfd = dpc_socket_provide(pl, &packet->src_ipaddr, packet->src_port);
	if (my_sockfd < 0) {
		ERROR("Failed to provide a suitable socket");
		return -1;
	}

	if (packet->id == DPC_PACKET_ID_UNASSIGNED) {
		/* Need to assign an xid to this packet. */
		bool rcode;

		/* Get DHCP-Transaction-Id from input, if set use it. */
		VALUE_PAIR *vp_xid;
		if ((vp_xid = dpc_pair_find_dhcp(packet->vps, FR_DHCPV4_TRANSACTION_ID, TAG_ANY))) {
			packet->id = vp_xid->data.vb_uint32; /* Note: packet->id will be reset if allocation fails. */
			DPC_DEBUG_TRACE("Allocate xid (prefered value: %u)", packet->id);
		} else {
			DPC_DEBUG_TRACE("Allocate xid (don't care which)");
		}

		rcode = dpc_packet_list_id_alloc(pl, my_sockfd, packet_p);
		if (!rcode) {
			ERROR("Failed to allocate xid");
			return -1;
		}
	}

	assert(packet->id != DPC_PACKET_ID_UNASSIGNED);
	assert(packet->data == NULL);

	/*
	 *	Encode the packet.
	 */
	DPC_DEBUG_TRACE("Encoding and sending packet");
	if (dpc_dhcp_encode(packet) < 0) {
		ERROR("Failed encoding request packet");
		exit(EXIT_FAILURE);
	}
	fr_strerror(); /* Clear the error buffer */

	/*
	 *	Send the packet.
	 */
	gettimeofday(&packet->timestamp, NULL); /* Store packet send time. */
	// shouldn't FreeRADIUS lib do that ? TODO.
	// (on receive, reply timestamp is set by fr_dhcpv4_udp_packet_recv.)

	dpc_packet_print(fr_log_fp, packet, DPC_PACKET_SENT, packet_trace_lvl); /* Print request packet. */

	packet->sockfd = my_sockfd;
	if (fr_dhcpv4_udp_packet_send(packet) < 0) { /* Send using a connectionless UDP socket (sendfromto). */
		ERROR("Failed to send packet: %s", fr_syserror(errno));
		exit(EXIT_FAILURE);
	}

	return 0;
}

/*
 *	Receive one packet, maybe.
 *	If tv_wait_time is not NULL, spend at most this time waiting for a packet. Otherwise do not wait.
 *	If a packet is received, it has to be a reply to something we sent. Look for that request in the packet list.
 *	Returns: -1 = error, 0 = nothing to receive, 1 = one packet received.
 */
static int dpc_recv_one_packet(struct timeval *tv_wait_time)
{
	fd_set set;
	struct timeval  tv;
	RADIUS_PACKET *reply = NULL, **packet_p;
	dpc_session_ctx_t *session;
	int max_fd;

	/* Wait for reply, timing out as necessary */
	FD_ZERO(&set);

	max_fd = dpc_packet_list_fd_set(pl, &set);
	if (max_fd < 0) {
		/* no sockets to listen on! */
		return 0;
	}

	if (NULL == tv_wait_time) {
		timerclear(&tv);
	} else {
		tv.tv_sec = tv_wait_time->tv_sec;
		tv.tv_usec = tv_wait_time->tv_usec;
	}

	/*
	 *	No packet was received.
	 */
	if (select(max_fd, &set, NULL, NULL, &tv) <= 0) {
		return 0;
	}

	/*
	 *	Fetch one incoming packet.
	 */
	reply = dpc_packet_list_recv(pl, &set); // warning: reply is allocated on NULL context.
	if (!reply) {
		PERROR("Received bad packet");
		return -1;
	}

	char from_to_buf[DPC_FROM_TO_STRLEN] = "";
	DPC_DEBUG_TRACE("Received packet %s, id: %u (0x%08x)",
	                dpc_print_packet_from_to(from_to_buf, reply, false), reply->id, reply->id);

	/*
	 *	Query the packet list to get the original packet to which this is a reply.
	 */
	packet_p = dpc_packet_list_find_byreply(pl, reply);
	if (!packet_p) {
		DEBUG("Received reply to unknown packet, id: %u (0x%08x)", reply->id, reply->id);
		fr_radius_free(&reply);
		return -1;
	}

	/*
	 *	Retrieve the session to which belongs the original packet.
	 *	To do so we use fr_packet2myptr, this is a magical macro defined in include/packet.h
	 */
	session = fr_packet2myptr(dpc_session_ctx_t, packet, packet_p);

	DPC_DEBUG_TRACE("Packet belongs to session id: %d", session->id);

	/*
	 *	Decode the reply packet.
	 */
	if (fr_dhcpv4_packet_decode(reply) < 0) {
		ERROR("Failed to decode reply packet (xid: %u)", reply->id);
		fr_radius_free(&reply);
		return -1;
	}

	session->reply = reply;
	talloc_steal(session, reply); /* Reparent reply packet (allocated on NULL context) so we don't leak. */

	/* Compute rtt. */
	struct timeval rtt;
	timersub(&session->reply->timestamp, &session->packet->timestamp, &rtt);
	DPC_DEBUG_TRACE("Packet response time: %.6f", dpc_timeval_to_float(&rtt));

	dpc_packet_print(fr_log_fp, reply, DPC_PACKET_RECEIVED, packet_trace_lvl); /* print reply packet. */

	/*
	 *	Perform post reception actions, and determine if session should be finished.
	 */
	if (!dpc_recv_post_action(session)) {
		dpc_session_finish(session);
	}

	return 1;
}

/*
 *	Perform actions after reception of a reply.
 *	Returns true if we're not done with the session (so it should not be terminated yet), false otherwise.
 */
static bool dpc_recv_post_action(dpc_session_ctx_t *session)
{
	int ret;

	if (!session || !session->reply) return false;

	/*
	 *	If dealing with a DORA transaction, after a valid Offer we need to send a Request.
	 */
	if (session->state == DPC_STATE_DORA_EXPECT_OFFER) {
		VALUE_PAIR *vp_xid, *vp_yiaddr, *vp_server_id, *vp_requested_ip;
		RADIUS_PACKET *packet;

		if (session->reply->code != FR_DHCPV4_OFFER) { /* Not an Offer. */
			DEBUG2("Session DORA: expected Offer reply, instead got: %d", session->reply->code);
			return false;
		}

		/* Get the Offer xid. */
		vp_xid = fr_pair_find_by_num(session->reply->vps, DHCP_MAGIC_VENDOR, FR_DHCPV4_TRANSACTION_ID, TAG_ANY);
		if (!vp_xid) { /* Should never happen (DHCP field). */
			return false;
		}

		/* Offer must provide yiaddr (DHCP-Your-IP-Address). */
		vp_yiaddr = fr_pair_find_by_num(session->reply->vps, DHCP_MAGIC_VENDOR, FR_DHCPV4_YOUR_IP_ADDRESS, TAG_ANY);
		if (!vp_yiaddr || vp_yiaddr->vp_ipv4addr == 0) {
			DEBUG2("Session DORA: no yiaddr provided in Offer reply");
			return false;
		}

		/* Offer must contain option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
		vp_server_id = fr_pair_find_by_num(session->reply->vps, DHCP_MAGIC_VENDOR, FR_DHCPV4_DHCP_SERVER_IDENTIFIER, TAG_ANY);
		if (!vp_server_id || vp_server_id->vp_ipv4addr == 0) {
			DEBUG2("Session DORA: no option 54 (server id) provided in Offer reply");
			return false;
		}

		/*
		 *	Prepare a new DHCP Request packet.
		 */
		DPC_DEBUG_TRACE("DORA: received valid Offer, now preparing Request");

		packet = dpc_request_init(session, session->input);
		if (!packet) return false;

		packet->code = FR_DHCPV4_REQUEST;
		session->state = DPC_STATE_EXPECT_REPLY;

		/*
		 *	Use information from the Offer reply to complete the new packet.
		 */

		/* Add option 50 Requested IP Address (DHCP-Requested-IP-Address) = yiaddr */
		vp_requested_ip = radius_pair_create(packet, &packet->vps, FR_DHCPV4_REQUESTED_IP_ADDRESS, DHCP_MAGIC_VENDOR);
		//vp_requested_ip->vp_ipv4addr = vp_yiaddr->vp_ipv4addr; // not good enough.
		fr_value_box_copy(vp_requested_ip, &vp_requested_ip->data, &vp_yiaddr->data);

		/* Add option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
		fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_server_id));

		/* Remove xid if there was one in input. Add xid from Offer reply instead. */
		fr_pair_delete_by_num(&packet->vps, DHCP_MAGIC_VENDOR, FR_DHCPV4_TRANSACTION_ID, TAG_ANY);
		fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_xid));

		/*
		 *	New packet is ready. Free old packet and its reply. Then use the new packet.
		 */
		talloc_free(session->reply);
		session->reply = NULL;

		if (!dpc_packet_list_id_free(pl, session->packet, true)) {
			WARN("Failed to free from packet list, id: %u", session->packet->id);
		}
		talloc_free(session->packet);
		session->packet = packet;

		/*
		 *	Encode and send packet.
		 */
		ret = dpc_send_one_packet(&session->packet);
		if (ret < 0) {
			ERROR("Error sending packet");
			return false;
		}

		/*
		 *	Arm request timeout.
		 */
		dpc_event_add_request_timeout(session);

		/* All good. */
		return true;
	}

	return false;
}

/*
 *	Initialize a DHCP packet from an input item.
 */
static RADIUS_PACKET *dpc_request_init(TALLOC_CTX *ctx, dpc_input_t *input)
{
	RADIUS_PACKET *request;

	MEM(request = fr_radius_alloc(ctx, true)); /* Note: this sets id to -1. */

	DPC_DEBUG_TRACE("New packet allocated");

	/* Fill in the packet value pairs. */
	dpc_pair_list_append(request, &request->vps, input->vps);

	/*
	 *	Use values prepared earlier.
	 */
	request->code = input->code;
	request->src_port = input->src_port;
	request->dst_port = input->dst_port;
	request->src_ipaddr = input->src_ipaddr;
	request->dst_ipaddr = input->dst_ipaddr;

	return request;
}

/*
 *	Encode a DHCP packet.
 */
static int dpc_dhcp_encode(RADIUS_PACKET *packet)
{
	int r;

	/*
	 *	Reset DHCP-Transaction-Id to xid allocated (it may not be what was asked for,
	 *	the requested id may not have been available).
	 */
	fr_pair_delete_by_num(&packet->vps, DHCP_MAGIC_VENDOR, FR_DHCPV4_TRANSACTION_ID, TAG_ANY);
	VALUE_PAIR *vp_xid = fr_pair_afrom_num(packet, DHCP_MAGIC_VENDOR, FR_DHCPV4_TRANSACTION_ID);
	vp_xid->data.vb_uint32 = packet->id;
	fr_pair_add(&packet->vps, vp_xid);

	/*
	 *	We've been told to handle sent packets as if relayed through a gateway.
	 *	This means:
	 *	- packet source IP / port = gateway IP / port (those we've already set)
	 *	- giaddr = gateway IP
	 *	- hops = 1 (arbitrary)
	 *	All of these can be overriden (entirely or partially) through input vps.
	 *	Note: the DHCP server will respond to the giaddr, not the packet source IP. Normally they are the same.
	 */
	if (gateway) {
		VALUE_PAIR *vp_giaddr, *vp_hops;

		/* set giaddr if not specified in input vps (DHCP-Gateway-IP-Address). */
		vp_giaddr = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, FR_DHCPV4_GATEWAY_IP_ADDRESS, TAG_ANY);
		if (!vp_giaddr) {
			vp_giaddr = radius_pair_create(packet, &packet->vps, FR_DHCPV4_GATEWAY_IP_ADDRESS, DHCP_MAGIC_VENDOR);
			vp_giaddr->vp_ipv4addr = gateway->ipaddr.addr.v4.s_addr;
			vp_giaddr->vp_ip.af = AF_INET;
			vp_giaddr->vp_ip.prefix = 32;
		}

		/* set hops if not specified in input vps (DHCP-Hop-Count). */
		vp_hops = fr_pair_find_by_num(packet->vps, DHCP_MAGIC_VENDOR, FR_DHCPV4_HOP_COUNT, TAG_ANY);
		if (!vp_hops) {
			vp_hops = radius_pair_create(packet, &packet->vps, FR_DHCPV4_HOP_COUNT, DHCP_MAGIC_VENDOR);
			vp_hops->vp_uint8 = 1;
		}
	}

	r = fr_dhcpv4_packet_encode(packet);
	fr_strerror(); /* Clear the error buffer */

	return r;
}

/*
 *	Dynamically generate an input item from template.
 */
static dpc_input_t *dpc_gen_input_from_template(TALLOC_CTX *ctx)
{
	if (!template_invariant && !template_variable) return NULL;

	dpc_input_t *input = NULL;
	dpc_input_t *transport = template_invariant ? template_invariant : template_variable;

	MEM(input = talloc_zero(ctx, dpc_input_t));

	// these should probably be in a separate struct... TODO.
	input->code = transport->code;
	input->src_port = transport->src_port;
	input->dst_port = transport->dst_port;
	input->src_ipaddr = transport->src_ipaddr;
	input->dst_ipaddr = transport->dst_ipaddr;

	/*
	 *	Fill input with template invariant attributes.
	 */
	if (template_invariant) {
		dpc_pair_list_append(input, &input->vps, template_invariant->vps);
	}

	/*
	 *	Append input with template variable attributes, then update them for next generation.
	 */
	if (template_variable) {
		dpc_pair_list_append(input, &input->vps, template_variable->vps);

		vp_cursor_t cursor;
		VALUE_PAIR *vp;
		unsigned int i;

		for (vp = fr_pair_cursor_init(&cursor, &template_variable->vps);
			vp;
			vp = fr_pair_cursor_next(&cursor)) {

			switch (vp->da->type) {
			case FR_TYPE_UINT8:
				vp->vp_uint8 += 1;
				break;

			case FR_TYPE_UINT16:
				vp->vp_uint16 += 1;
				break;

			case FR_TYPE_UINT32:
				vp->vp_uint32 += 1;
				break;

			case FR_TYPE_STRING: /* Circular shift on the left, e.g.: abcd -> bcda */
			{
				char *buff;
				int len = vp->vp_length;

				buff = talloc_zero_array(vp, char, len + 1);
				for (i = 0; i < vp->vp_length; i ++) {
					buff[i] = vp->vp_strvalue[(i + 1) % len];
				}
				fr_pair_value_strsteal(vp, (char *)buff);
			}
				break;

			case FR_TYPE_OCTETS: /* +1 on each octet */
			{
				uint8_t *buff;

				buff = talloc_array(vp, uint8_t, vp->vp_length);
				memcpy(buff, vp->vp_octets, vp->vp_length);
				for (i = 0; i < vp->vp_length; i ++) {
					buff[i] ++;
				}
				fr_pair_value_memsteal(vp, buff);
			}
				break;

			case FR_TYPE_IPV4_ADDR:
				vp->vp_ipv4addr = htonl(ntohl(vp->vp_ipv4addr) + 1);
				break;

			case FR_TYPE_ETHERNET:
			{
				/* Hackish way to increment the 6 octets of hwaddr. */
				uint64_t hwaddr = 0;
				memcpy(&hwaddr, vp->vp_ether, 6);
				hwaddr = ntohll(hwaddr) + (1 << 16);
				hwaddr = htonll(hwaddr);
				memcpy(vp->vp_ether, &hwaddr, 6);
				break;
			}

			default: /* Not handled, so this will be treated as invariant/ */
				break;
			}
		}
	}

	return input;
}

/*
 *	Get an input item. If using a template, dynamically generate a new item.
 */
static dpc_input_t *dpc_get_input()
{
	if (!with_template) {
		return dpc_get_input_list_head(&vps_list_in);
	} else {
		return dpc_gen_input_from_template(autofree);
	}
}

/*
 *	Initialize a new session.
 */
static dpc_session_ctx_t *dpc_session_init(TALLOC_CTX *ctx)
{
	dpc_input_t *input = NULL;
	dpc_session_ctx_t *session = NULL;
	RADIUS_PACKET *packet = NULL;

	DPC_DEBUG_TRACE("Initializing a new session (id: %u)", session_num);

	input = dpc_get_input();
	if (!input) { /* No input: cannot create new session. */
		return NULL;
	}

	/*
	 *	Prepare a DHCP packet to send for this session.
	 */
	packet = dpc_request_init(ctx, input);
	if (packet) {
		MEM(session = talloc_zero(ctx, dpc_session_ctx_t));
		session->id = session_num ++;

		session->packet = packet;
		talloc_steal(session, packet);

		session->input = input;
		talloc_steal(session, input);

		/*
		 *	Prepare dealing with reply and workflow sequence.
		 */
		session->reply_expected = true; /* First assume we're expecting a reply. */

		if (input->workflow == DPC_WORKFLOW_DORA) {
			session->state = DPC_STATE_DORA_EXPECT_OFFER;
		} else {
			/*
			 *	These kind of packets do not get a reply, so don't wait for one.
			 */
			if ((packet->code == FR_DHCPV4_RELEASE) || (packet->code == FR_DHCPV4_DECLINE)) {
				session->reply_expected = false;
				session->state = DPC_STATE_NO_REPLY;
			} else {
				session->state = DPC_STATE_EXPECT_REPLY;
			}
		}

		/* Store session start time. */
		gettimeofday(&session->tv_start, NULL);

		session_num_active ++;
	}

	/* Free this input now if we could not initialize a session from it. */
	if (!session) {
		talloc_free(input);
	}

	return session;
}

/*
 *	One session is finished.
 */
static void dpc_session_finish(dpc_session_ctx_t *session)
{
	if (!session) return;

	DPC_DEBUG_TRACE("Terminating session (id: %u)", session->id);

	/* Remove the packet from the list, and free the id we've been using. */
	if (session->packet && session->packet->id != DPC_PACKET_ID_UNASSIGNED) {
		if (!dpc_packet_list_id_free(pl, session->packet, true)) {
			WARN("Failed to free from packet list, id: %u", session->packet->id);
		}
	}

	/* Clear the event timer if it is armed. */
	if (session->event) {
		fr_event_timer_delete(event_list, &session->event);
		session->event = NULL;
	}

	talloc_free(session);
	session_num_active --;
}

/*
 *	Receive and handle reply packets.
 */
static void dpc_loop_recv(void)
{
	bool done = false;

	while (!done) {
		/*
		 *	Receive and process packets (no waiting) until there's nothing left incoming.
		 */
		if (dpc_recv_one_packet(NULL) < 1) break;
	}
}

/*
 *	Start new sessions.
 */
static void dpc_loop_start_sessions(void)
{
	bool done = false;
	int ret;

 	/* If we've flagged that sessions should be be started anymore, return immediately. */
	if (!start_sessions_flag) return;

	while (!done) {
		/* Max session limit reached. */
		if (session_max_num && session_num >= session_max_num) {
			if (start_sessions_flag) {
				DEBUG("Maximum number of sessions reached (%u): stop starting new sessions", session_max_num);
			}
			start_sessions_flag = false;
			break;
		}

		/* No more input. */
		if (!with_template && vps_list_in.size == 0) {
			start_sessions_flag = false;
			break;
		}

		/* Max active session reached. Try again later when we've finished some ongoing sessions. */
		if (session_num_active >= session_max_active) break;

		/*
		 *	Initialize a new session and send the packet.
		 */
		dpc_session_ctx_t *session = dpc_session_init(autofree);
		if (!session) continue;

		ret = dpc_send_one_packet(&session->packet);
		if (ret < 0) {
			ERROR("Error sending packet");
			dpc_session_finish(session);
			continue;
		}

		if (session->reply_expected) {
			/*
			 *	Arm request timeout.
			 */
			dpc_event_add_request_timeout(session);
		} else {
			/* We've sent a packet to which no reply is expected. So this session ends right now. */
			dpc_session_finish(session);
		}
	}
}

/*
 *	Handle timer events.
 */
static void dpc_loop_timer_events(void)
{
	int nb_processed = 0; /* Number of timers events triggered. */
	struct timeval when;

	if (fr_event_list_num_timers(event_list) <= 0) return;

	gettimeofday(&when, NULL); /* Now. */
	while (fr_event_timer_run(event_list, &when)) {
		nb_processed ++;
	}

}

/*
 *	Check if we're done with the main processing loop.
 */
static bool dpc_loop_check_done(void)
{
	/* There are still ongoing requests, to which we expect a reply or wait for a timeout. */
	if (dpc_packet_list_num_elements(pl) > 0) return false;

	/* There are still events to process. */
	if (fr_event_list_num_timers(event_list) > 0) return false;

	/* We still have sessions to start. */
	if (start_sessions_flag) return false;

	/* No more work. */
	job_done = true;
	return true;
}

/*
 *	Main processing loop.
 */
static void dpc_main_loop(void)
{
	job_done = false;

	while (!job_done) {
		/* Handle timer events. */
		dpc_loop_timer_events();

		/* Receive and process reply packets. */
		dpc_loop_recv();

		/* Start new sessions. */
		dpc_loop_start_sessions();

		/* Check if we're done. */
		dpc_loop_check_done();
	}
}

/*
 *	Parse an input item and prepare information necessary to build a packet.
 */
static bool dpc_parse_input(dpc_input_t *input)
{
	vp_cursor_t cursor;
	VALUE_PAIR *vp;
	static bool warn_inaddr_any = true;

	input->code = FR_CODE_UNDEFINED;

	/*
	 *	Loop over input value pairs.
	 */
	for (vp = fr_pair_cursor_init(&cursor, &input->vps);
	     vp;
	     vp = fr_pair_cursor_next(&cursor)) {
		/*
		 *	Allow to set packet type using DHCP-Message-Type
		 */
		if (vp->da->vendor == DHCP_MAGIC_VENDOR && vp->da->attr == FR_DHCPV4_MESSAGE_TYPE) {
			input->code = vp->vp_uint32 + FR_DHCPV4_OFFSET;
		} else if (!vp->da->vendor) switch (vp->da->attr) {
		/*
		 *	Also allow to set packet type using Packet-Type
		 *	(this takes precedence over the command argument.)
		 */
		case FR_PACKET_TYPE:
			input->code = vp->vp_uint32;
			break;

		case FR_PACKET_DST_PORT:
			input->dst_port = vp->vp_uint16;
			break;

		case FR_PACKET_DST_IP_ADDRESS:
		case FR_PACKET_DST_IPV6_ADDRESS:
			memcpy(&input->dst_ipaddr, &vp->vp_ip, sizeof(input->src_ipaddr));
			break;

		case FR_PACKET_SRC_PORT:
			input->src_port = vp->vp_uint16;
			break;

		case FR_PACKET_SRC_IP_ADDRESS:
		case FR_PACKET_SRC_IPV6_ADDRESS:
			memcpy(&input->src_ipaddr, &vp->vp_ip, sizeof(input->src_ipaddr));
			break;

		default:
			break;
		} /* switch over the attribute */

	} /* loop over the input vps */

	/*
	 *	If not specified in input vps, use default values.
	 */
	if (input->code == FR_CODE_UNDEFINED) {
		/* Handling a workflow, which determines the packet type. */
		if (workflow_code == DPC_WORKFLOW_DORA) {
			input->workflow = workflow_code;
			input->code = FR_DHCPV4_DISCOVER;
		}
	}
	if (input->code == FR_CODE_UNDEFINED) input->code = packet_code;

	/*
	 *	If source (addr / port) is not defined in input vps, use gateway if one is specified.
	 *	If nothing goes, fall back to default.
	 */
	if (!input->src_port) {
		if (gateway) input->src_port = gateway->port;
		else input->src_port = client_port;
	}
	if (input->src_ipaddr.af == AF_UNSPEC) {
		if (gateway) input->src_ipaddr = gateway->ipaddr;
		else input->src_ipaddr = client_ipaddr;
	}

	if (!input->dst_port) input->dst_port = server_port;
	if (input->dst_ipaddr.af == AF_UNSPEC) input->dst_ipaddr = server_ipaddr;

	if (input->code == FR_CODE_UNDEFINED) {
		WARN("No packet type specified in inputs vps or command line, discarding input (id: %u)", input->id);
		return false;
	}

	/*
	 *	Allocate the socket now. If we can't, stop.
	 */
	int my_sockfd = dpc_socket_provide(pl, &input->src_ipaddr, input->src_port);
	if (my_sockfd < 0) {
		char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
		ERROR("Failed to provide a suitable socket (input id: %u, requested socket src: %s:%u)", input->id,
		      fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &input->src_ipaddr), input->src_port);
		exit(EXIT_FAILURE);
	}

	/*
	 *	If we're using INADDR_ANY, make sure we know what we're doing.
	 */
	if (warn_inaddr_any && fr_ipaddr_is_inaddr_any(&input->src_ipaddr)) {
		WARN("You didn't specify a source IP address. Consequently, a socket was allocated with INADDR_ANY (0.0.0.0)."
		     " Please make sure this is really what you intended.");
		warn_inaddr_any = false; /* Once is enough. */
	}

	/* All good. */
	return true;
}

/*
 *	Handle a list of input vps we've just read.
 */
static void dpc_handle_input(dpc_input_t *input, dpc_input_list_t *list)
{
	input->id = input_num ++;

	// for now, just trace what we've read.
	if (dpc_debug_lvl > 1) {
		DEBUG2("Input (id: %u) vps read:", input->id);
		fr_pair_list_fprint(fr_log_fp, input->vps);
	}

	if (!dpc_parse_input(input)) {
		/*
		 *	Invalid item. Discard.
		 */
		talloc_free(input);
		return;
	}

	/*
	 *	Add it to the list of input items.
	 */
	dpc_input_item_add(list, input);
}

/*
 *	Load input vps.
 */
static void dpc_input_load_from_fd(TALLOC_CTX *ctx, FILE *file_in, dpc_input_list_t *list)
{
	bool file_done = false;
	dpc_input_t *input;

	/*
	 *	Loop until the file is done.
	 */
	do {
 		/* Template needs two input items only, ignore if there are more. */
		if (with_template && list->size >= 2) break;

		MEM(input = talloc_zero(ctx, dpc_input_t));

		if (fr_pair_list_afrom_file(input, &input->vps, file_in, &file_done) < 0) {
			ERROR("Error parsing input vps");
			talloc_free(input);
			break;
		}
		if (NULL == input->vps) {
			/* Last line might be empty, in this case we will obtain a NULL vps pointer. Silently ignore this. */
			talloc_free(input);
			break;
		}
		fr_strerror(); /* Clear the error buffer */
		/*
		 *	After calling fr_pair_list_afrom_file we get weird things in FreeRADIUS error buffer, e.g.
		 *	"Invalid character ':' in attribute name". This happens apparently when handling an ethernet address
		 *	(which is a value, not an attribute name).
		 *	Just ignore this.
		*/

		dpc_handle_input(input, list);

		/* Stop reading if we know we won't need it. */
		if (session_max_num && list->size >= session_max_num) break;

	} while (!file_done);

}

/*
 *	Load input vps, either from a file if specified, or stdin otherwise.
 */
static int dpc_input_load(TALLOC_CTX *ctx)
{
	FILE *file_in = NULL;

	/*
	 *	If there's something on stdin, read it.
	 */
	if (dpc_stdin_peek()) {
		DEBUG("Reading input from stdin");
		dpc_input_load_from_fd(ctx, stdin, &vps_list_in);
	} else {
		DPC_DEBUG_TRACE("Nothing to read on stdin");
	}

	/*
	 *	Determine where to read the vps from.
	 */
	if (file_vps_in && strcmp(file_vps_in, "-") != 0) {
		DEBUG("Reading input from file: %s", file_vps_in);

		file_in = fopen(file_vps_in, "r");
		if (!file_in) {
			ERROR("Error opening %s: %s", file_vps_in, strerror(errno));
			exit(EXIT_FAILURE);
		}

		dpc_input_load_from_fd(ctx, file_in, &vps_list_in);

		fclose(file_in);
	}

	/*
	 *	Ensure we have something to work with.
	 */
	if (vps_list_in.size == 0) {
		WARN("No valid input loaded, nothing to do");
		exit(0);
	}

	DEBUG("Done reading input, list size: %d", vps_list_in.size);

	/* Template: keep track of the two input items we'll need. */
	if (with_template) {
		template_invariant = vps_list_in.head;
		template_variable = vps_list_in.tail;

		/* If only one input item provided: this will be the variable list (no invariant). */
		if (vps_list_in.size < 2) template_invariant = NULL;
	}

	return 0;
}

/*
 *	Load dictionaries.
 */
static void dpc_dict_init(TALLOC_CTX *ctx)
{
	fr_dict_attr_t const *da;

	DEBUG("Including dictionary file: %s/%s", dict_dir, FR_DICTIONARY_FILE);
	if (fr_dict_from_file(ctx, &dict, dict_dir, FR_DICTIONARY_FILE, progname) < 0) {
		fr_perror("dhcperfcli");
		exit(EXIT_FAILURE);
	}

	DEBUG("Including dictionary file: %s/%s", radius_dir, FR_DICTIONARY_FILE);
	if (fr_dict_read(dict, radius_dir, FR_DICTIONARY_FILE) == -1) {
		fr_log_perror(&default_log, L_ERR, "Failed to initialize the dictionaries");
		exit(EXIT_FAILURE);
	}
	fr_strerror(); /* Clear the error buffer */

	/*
	 *	Ensure that dictionary.dhcp is loaded.
	 */
	da = fr_dict_attr_by_name(NULL, "DHCP-Message-Type");
	if (!da) {
		if (fr_dict_read(dict, dict_dir, "dictionary.dhcp") < 0) {
			ERROR("Failed reading dictionary.dhcp");
			exit(EXIT_FAILURE);
		}
	}
}

/*
 *	Initialize event list.
 */
static void dpc_event_list_init(TALLOC_CTX *ctx)
{
	event_list = fr_event_list_alloc(ctx, NULL, NULL);
	if (!event_list) {
		ERROR("Failed to create event list");
		exit(EXIT_FAILURE);
	}
}

/*
 *	Initialize the packet list.
 */
static void dpc_packet_list_init(TALLOC_CTX *ctx)
{
	pl = dpc_packet_list_create(ctx, base_xid);
	if (!pl) {
		ERROR("Failed to create packet list");
		exit(EXIT_FAILURE);
	}
}

/*
 *	Resolve host address and port.
 */
static void dpc_host_addr_resolve(char *host_arg, fr_ipaddr_t *host_ipaddr, uint16_t *host_port)
{
	if (!host_arg || !host_ipaddr || !host_port) return;

	uint16_t port;

	if (fr_inet_pton_port(host_ipaddr, &port, host_arg, -1, force_af, true, true) < 0) {
		ERROR("Failed to parse host address");
		exit(EXIT_FAILURE);
	}

	if (port != 0) { /* If a port is specified, use it. Otherwise, keep default. */
		*host_port = port;
	}
}

/*
 *	See what kind of request we want to send, or workflow to handle.
 */
static void dpc_command_parse(char const *command)
{
	/* If an integer, assume this is the packet type (1 = discover, ...) */
	if (is_integer(command)) {
		packet_code = atoi(command) + FR_DHCPV4_OFFSET;
		return;
	}

	/* Maybe it's a workflow. */
	workflow_code = fr_str2int(workflow_types, command, DPC_WORKFLOW_NONE);
	if (workflow_code != DPC_WORKFLOW_NONE) return;
	// TODO: define an internal attribute so we can specify this in input vps.

	/* Or a packet type. */
	packet_code = fr_str2int(request_types, command, -1);
	if (packet_code != -1) return;

	/* Nothing goes. */
	ERROR("Unrecognised command \"%s\"", command);
	usage(1);
}

/*
 *	Process command line options and arguments.
 */
static void dpc_options_parse(int argc, char **argv)
{
	int argval;
	bool debug_fr =  false;

	while ((argval = getopt(argc, argv, "f:g:hi:N:p:P:t:TvxX")) != EOF) {
		switch (argval) {
		case 'f':
			file_vps_in = optarg;
			break;

		case 'g':
			MEM(gateway = talloc_zero(autofree, dpc_endpoint_t));
			gateway->port = DHCP_PORT_RELAY;
			dpc_host_addr_resolve(optarg, &gateway->ipaddr, &gateway->port);
			break;

		case 'h':
			usage(0);
			break;

		case 'i':
			if (!is_integer(optarg)) { // lib/util/misc.c
				ERROR("Invalid value for option -i (integer expected)");
				usage(1);
			}
			base_xid = atoi(optarg);
			break;

		case 'N':
			if (!is_integer(optarg)) {
				ERROR("Invalid value for option -N (integer expected)");
				usage(1);
			}
			session_max_num = atoi(optarg);
			break;

		case 'p':
			if (!is_integer(optarg)) {
				ERROR("Invalid value for option -p (integer expected)");
				usage(1);
			}
			session_max_active = atoi(optarg);
			if (session_max_active == 0) session_max_active = 1;
			break;

		case 'P':
			if (!is_integer(optarg)) {
				ERROR("Invalid value for option -P (integer expected)");
				usage(1);
			}
			packet_trace_lvl = atoi(optarg);
			break;

		case 't':
			if (!dpc_str_to_float(&timeout, optarg)) {
				ERROR("Invalid value for option -t (floating point number expected)");
				usage(1);
			}
			break;

		case 'T':
			with_template = true;
			break;

		case 'v':
			printf("%s %s\n", progname, prog_version);
			exit(0);

		case 'x':
			dpc_debug_lvl ++;
			break;

		case 'X':
			debug_fr = true;
			break;

		default:
			usage(1);
			break;
		}
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	if (debug_fr) fr_debug_lvl = dpc_debug_lvl;

	/* If packet trace level is unspecified, figure out something automatically. */
	if (packet_trace_lvl == -1) {
		if (session_max_num == 1 || (!with_template && vps_list_in.size < 2)) {
			/* Only one request: full packet print. */
			packet_trace_lvl = 2;
		} else if (session_max_active == 1) {
			/* Several requests but no parallelism: print packet headers. */
			packet_trace_lvl = 1;
		} else {
			/* Several request in parallel: no packet print. */
			packet_trace_lvl = 0;
		}
	}

	/*
	 *	Resolve server host address and port.
	 */
	if (argc - 1 >= 1 && strcmp(argv[1], "-") != 0) {
		dpc_host_addr_resolve(argv[1], &server_ipaddr, &server_port);
		client_ipaddr.af = server_ipaddr.af;
		client_ipaddr.prefix = server_ipaddr.prefix;
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (argc - 1 >= 2) {
		dpc_command_parse(argv[2]);
	}

	dpc_float_to_timeval(&tv_timeout, timeout);

}

/*
 *	Signal handler.
 */
static void dpc_signal(int sig)
{
	if (!signal_done) {
		/* Allow ongoing sessions to be finished gracefully. */
		INFO("Received signal [%d] (%s): No more session will be started.", sig, strsignal(sig));
		INFO("Send another signal if you wish to abort immediately.");
		signal_done = true;
		start_sessions_flag = false;
	} else {
		/* ... unless someone's getting really impatient. */
		INFO("Received signal [%d] (%s): Aborting.", sig, strsignal(sig));
		exit(0);
	}
}


/*
 *	The main guy.
 */
int main(int argc, char **argv)
{
	char *p;

	fr_debug_lvl = 0; /* FreeRADIUS libraries debug. */
	dpc_debug_lvl = 0; /* Our own debug. */
	fr_log_fp = stdout; /* Both will go there. */

	gettimeofday(&tv_start, NULL);

	/* Get program name from argv. */
	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		progname = argv[0];
	} else {
		progname = p + 1;
	}

	dpc_options_parse(argc, argv);

	dpc_dict_init(autofree);

	dpc_event_list_init(autofree);
	dpc_packet_list_init(autofree);

	if (gateway) {
		/*
		 *	Allocate the socket now. If we can't, stop.
		 */
		int my_sockfd = dpc_socket_provide(pl, &gateway->ipaddr, gateway->port);
		if (my_sockfd < 0) {
			char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
			ERROR("Failed to provide a suitable socket for gateway (requested socket src: %s:%u)",
			      fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &gateway->ipaddr), gateway->port);
			exit(EXIT_FAILURE);
		}
	}

	/*
	 *	Set signal handler.
	 */
	if ( (fr_set_signal(SIGHUP, dpc_signal) < 0) ||
	     (fr_set_signal(SIGINT, dpc_signal) < 0) ||
	     (fr_set_signal(SIGTERM, dpc_signal) < 0))
	{
		PERROR("Failed installing signal handler");
		exit(EXIT_FAILURE);
	}

	/* Load input data used to build the packets. */
	dpc_input_load(autofree);

	/* Execute the main processing loop. */
	dpc_main_loop();

	exit(0);
}

/*
 *	Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *fd = status ? stderr : stdout;

	fprintf(fd, "Usage: %s [options] [<server>[:<port>] [<command>]]\n", progname);
	fprintf(fd, "  <server>:<port>  The DHCP server. If omitted, it must be specified in inputs vps.\n");
	fprintf(fd, "  <command>        One of (packet type): discover, request, decline, release, inform.\n");
	fprintf(fd, "                   Or (workflow): dora.\n");
	fprintf(fd, "                   If omitted, packet type must be specified in input vps.\n");
	fprintf(fd, " Options:\n");
	fprintf(fd, "  -f <file>        Read input vps from <file>, in addition to stdin\n");
	fprintf(fd, "  -g <gw>[:port]   Handle sent packets as if relayed through giaddr <gw> (hops: 1, src: giaddr:port).\n");
	fprintf(fd, "  -h               Print this help message.\n");
	fprintf(fd, "  -i <num>         Start generating xid values with <num>.\n");
	fprintf(fd, "  -N <num>         Start at most <num> sessions (in template mode: generate <num> sessions).\n");
	fprintf(fd, "  -p <num>         Send up to <num> session packets in parallel.\n");
	fprintf(fd, "  -P <num>         Packet trace level (0: none, 1: header, 2: +attributes).\n");
	fprintf(fd, "  -t <timeout>     Wait at most <timeout> seconds for a reply (may be a floating point number).\n");
	fprintf(fd, "  -T               Template mode. Sessions input is generated from invariant and variable input vps.\n");
	fprintf(fd, "  -v               Print version information.\n");
	fprintf(fd, "  -x               Turn on additional debugging. (-xx gives more debugging).\n");
	fprintf(fd, "  -X               Turn on FreeRADIUS libraries debugging (use this in conjunction with -x).\n");

	exit(status);
}
