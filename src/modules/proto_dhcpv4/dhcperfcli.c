/*
 * dhcperfcli.c
 */

#include "dhcperfcli.h"
#include "ncc_util.h"
#include "dpc_packet_list.h"
#include "dpc_util.h"

static char const *prog_version = RADIUSD_VERSION_STRING_BUILD("FreeRADIUS");


/*
 *	Global variables.
 */
TALLOC_CTX *autofree = NULL;

struct timeval tv_start; /* Program execution start timestamp. */
int dpc_debug_lvl = 0;

fr_dict_attr_t const *attr_packet_dst_ip_address = NULL;
fr_dict_attr_t const *attr_packet_dst_port = NULL;
fr_dict_attr_t const *attr_packet_src_ip_address = NULL;
fr_dict_attr_t const *attr_packet_src_port = NULL;
fr_dict_attr_t const *attr_encoded_data = NULL;
fr_dict_attr_t const *attr_authorized_server = NULL;
fr_dict_attr_t const *attr_workflow_type = NULL;
fr_dict_attr_t const *attr_dhcp_hop_count = NULL;
fr_dict_attr_t const *attr_dhcp_transaction_id = NULL;
fr_dict_attr_t const *attr_dhcp_client_ip_address = NULL;
fr_dict_attr_t const *attr_dhcp_your_ip_address = NULL;
fr_dict_attr_t const *attr_dhcp_gateway_ip_address = NULL;
fr_dict_attr_t const *attr_dhcp_server_identifier = NULL;
fr_dict_attr_t const *attr_dhcp_requested_ip_address = NULL;
fr_dict_attr_t const *attr_dhcp_message_type = NULL;

static char const *progname = NULL;

/*
 *	Dictionaries and attributes.
 */
static char alt_dict_dir[PATH_MAX + 1] = ""; /* Alternate directory for dictionaries. */
static char const *dict_dir = DICTDIR;
static char const *dict_fn_freeradius = "dictionary.freeradius.internal";
//static char const *dict_fn_dhcp = "dictionary.dhcpv4";
static char const *dict_fn_dhcperfcli = "dictionary.dhcperfcli.internal";

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_dhcperfcli;
static fr_dict_t *dict_dhcpv4;

extern fr_dict_autoload_t dpc_dict_autoload[];
fr_dict_autoload_t dpc_dict_autoload[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ .out = &dict_dhcperfcli, .proto = "dhcperfcli" },
	{ NULL }
};

extern fr_dict_attr_autoload_t dpc_dict_attr_autoload[];
fr_dict_attr_autoload_t dpc_dict_attr_autoload[] = {

	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },

	{ .out = &attr_encoded_data, .name = "DHCP-Encoded-Data", .type = FR_TYPE_OCTETS, .dict = &dict_dhcperfcli },
	{ .out = &attr_authorized_server, .name = "DHCP-Authorized-Server", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcperfcli },
	{ .out = &attr_workflow_type, .name = "DHCP-Workflow-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcperfcli },

	{ .out = &attr_dhcp_hop_count, .name = "DHCP-Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_transaction_id, .name = "DHCP-Transaction-Id", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_client_ip_address, .name = "DHCP-Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_your_ip_address, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_gateway_ip_address, .name = "DHCP-Gateway-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },

	{ .out = &attr_dhcp_server_identifier, .name = "DHCP-DHCP-Server-Identifier", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_requested_ip_address, .name = "DHCP-Requested-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },

	{ NULL }
};

static int packet_trace_lvl = -1; /* If unspecified, figure out something automatically. */

static dpc_packet_list_t *pl = NULL; /* List of outgoing packets. */
static fr_event_list_t *event_list = NULL;

static bool with_stdin_input = false; /* Whether we have something from stdin or not. */
static char const *file_vps_in = NULL;
static dpc_input_list_t vps_list_in = { 0 };
static bool with_template = false;
static dpc_input_t *template_invariant = NULL;
static dpc_input_t *template_variable = NULL;
static dpc_templ_var_t templ_var = DPC_TEMPL_VAR_INCREMENT;
static uint32_t input_num_use = 1;

static ncc_endpoint_t server_ep = {
	.ipaddr = { .af = AF_INET, .prefix = 32 },
	.port = DHCP_PORT_SERVER
};
static ncc_endpoint_t client_ep = {
	.ipaddr = { .af = AF_INET, .prefix = 32 },
	.port = DHCP_PORT_CLIENT
};

static unsigned int gateway_num = 0; /* Number of gateways. */
static unsigned int gateway_next = 0; /* Next gateway to be used. */
static ncc_endpoint_t *gateway_list = NULL; /* List of gateways. */
static fr_ipaddr_t allowed_server = { 0 }; /* Only allow replies from a specific server. */

static int force_af = AF_INET; // we only do DHCPv4.
static int packet_code = FR_CODE_UNDEFINED;
static int workflow_code = DPC_WORKFLOW_NONE;

static float timeout = 3.0;
static struct timeval tv_timeout;
static uint32_t base_xid = 0;
static uint32_t session_max_active = 1;
static uint32_t session_max_num = 0; /* Default: consume all input (or in template mode, no limit). */
static bool start_sessions_flag =  true; /* Allow starting new sessions. */
static struct timeval tv_job_start; /* Job start timestamp. */
static struct timeval tv_job_end; /* Job end timestamp. */
static float duration_max = 0; /* Default: unlimited. */
static float rate_limit = 0; /* Try to enforce a rate limit (reply /s, all transactions combined). */

static uint32_t session_num = 0; /* Number of sessions initialized. */
static uint32_t input_num = 0; /* Number of input entries read. (They may not all be valid.) */
static bool job_done = false;
static bool signal_done = false;

static uint32_t session_num_active = 0; /* Number of active sessions. */
static dpc_statistics_t stat_ctx = { 0 }; /* Statistics. */
fr_event_timer_t const *ev_progress_stats = NULL;
static float progress_interval = 10.0; /* Periodically produce progress statistics summary. */
struct timeval tv_progress_interval;
struct timeval tv_progress_stat = { 0 }; /* When next ongoing statistics is supposed to fire. */

struct timeval tv_loop_max_time = { .tv_usec = 50000 }; /* Max time spent in each iteration of the start loop. */

static bool multi_offer = false;
#ifdef HAVE_LIBPCAP
static fr_pcap_t *pcap;
static char *iface;
#endif

/*
 *	More concise version of dhcp_message_types defined in protocols/dhcpv4/base.c
 *	(Stripped of the "DHCP-" prefix. We only do DHCP.)
 */
char const *dpc_message_types[DHCP_MAX_MESSAGE_TYPE] = {
	"",
	"Discover",
	"Offer",
	"Request",
	"Decline",
	"Ack",
	"NAK",
	"Release",
	"Inform",
	"Force-Renew",
	"Lease-Query",
	"Lease-Unassigned",
	"Lease-Unknown",
	"Lease-Active",
	"Bulk-Lease-Query",
	"Lease-Query-Done"
};

static const FR_NAME_NUMBER request_types[] = {
	{ "discover",    FR_DHCP_DISCOVER },
	{ "request",     FR_DHCP_REQUEST },
	{ "decline",     FR_DHCP_DECLINE },
	{ "release",     FR_DHCP_RELEASE },
	{ "inform",      FR_DHCP_INFORM },
	{ "lease_query", FR_DHCP_LEASE_QUERY },
	{ "auto",        FR_CODE_UNDEFINED },
	{ "-",           FR_CODE_UNDEFINED },
	{ NULL, 0}
};

static const FR_NAME_NUMBER workflow_types[] = {
	{ "dora",        DPC_WORKFLOW_DORA },
	{ "doradec",     DPC_WORKFLOW_DORA_DECLINE },
	{ "dorarel",     DPC_WORKFLOW_DORA_RELEASE },
	{ NULL, 0}
};

/* Transaction type labels. */
static char const *transaction_types[DPC_TR_MAX] = {
	"(All)",
	"Discover:Offer",
	"Discover:Ack",
	"Request:Ack",
	"Request:Nak",
	"Lease-Query:Unassigned",
	"Lease-Query:Unknown",
	"Lease-Query:Active",
	"<DORA>"
};
#define LG_PAD_TR_TYPES 23 /* Longest of transaction_types + 1 */
#define LG_PAD_STATS    20

char elapsed_buf[DPC_TIME_STRLEN];
#define ELAPSED dpc_delta_time_sprint(elapsed_buf, &tv_job_start, NULL, DPC_DELTA_TIME_DECIMALS)


/*
 *	Static functions declaration.
 */
static void usage(int);
static void version_print(void);

static void dpc_progress_stats_fprint(FILE *fp);
static float dpc_job_elapsed_time_get(void);
static float dpc_get_tr_rate(dpc_transaction_type_t i);
static float dpc_get_msg_rate(uint8_t i);
static void dpc_tr_stats_fprint(FILE *fp);
static void dpc_stats_fprint(FILE *fp);
static void dpc_tr_stats_update(dpc_transaction_type_t tr_type, struct timeval *rtt);
static void dpc_statistics_update(RADIUS_PACKET *request, RADIUS_PACKET *reply);

static void dpc_progress_stats(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, void *uctx);
static void dpc_event_add_progress_stats(void);
static void dpc_request_timeout(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, void *uctx);
static void dpc_event_add_request_timeout(dpc_session_ctx_t *session, struct timeval *timeout_in);

static int dpc_send_one_packet(dpc_session_ctx_t *session, RADIUS_PACKET **packet_p);
static int dpc_recv_one_packet(struct timeval *tv_wait_time);
static bool dpc_session_handle_reply(dpc_session_ctx_t *session, RADIUS_PACKET *reply);
static bool dpc_session_dora_request(dpc_session_ctx_t *session);
static bool dpc_session_dora_release(dpc_session_ctx_t *session);
static bool dpc_session_dora_decline(dpc_session_ctx_t *session);
static void dpc_request_gateway_handle(RADIUS_PACKET *packet, ncc_endpoint_t *gateway);
static RADIUS_PACKET *dpc_request_init(TALLOC_CTX *ctx, dpc_input_t *input);
static int dpc_dhcp_encode(RADIUS_PACKET *packet);

static dpc_input_t *dpc_gen_input_from_template(TALLOC_CTX *ctx);
static dpc_input_t *dpc_get_input(void);
static dpc_session_ctx_t *dpc_session_init(TALLOC_CTX *ctx);
static void dpc_session_finish(dpc_session_ctx_t *session);

static void dpc_loop_recv(void);
static bool dpc_rate_limit_calc(uint32_t *max_new_sessions);
static uint32_t dpc_loop_start_sessions(void);
static bool dpc_loop_check_done(void);
static void dpc_main_loop(void);

static bool dpc_parse_input(dpc_input_t *input);
static void dpc_handle_input(dpc_input_t *input, dpc_input_list_t *list);
static void dpc_input_load_from_fd(TALLOC_CTX *ctx, FILE *file_in, dpc_input_list_t *list, char const *filename);
static int dpc_input_load(TALLOC_CTX *ctx);

static int dpc_get_alt_dir(void);
static void dpc_dict_init(TALLOC_CTX *ctx);
static void dpc_event_list_init(TALLOC_CTX *ctx);
static void dpc_packet_list_init(TALLOC_CTX *ctx);
static int dpc_command_parse(char const *command);
static void dpc_gateway_add(char *addr);
static void dpc_gateway_parse(char const *param);
static void dpc_options_parse(int argc, char **argv);

static void dpc_signal(int sig);
static void dpc_end(void);


/*
 *	Print ongoing job statistics summary.
 *	E.g.:
 *	t(8.001) (80.0%) sessions: [started: 39259 (31.8%), ongoing: 10], rate (/s): 4905.023
 */
static void dpc_progress_stats_fprint(FILE *fp)
{
	/* Elapsed time. */
	fprintf(fp, "t(%s)", ELAPSED);
	if (duration_max) {
		/* And percentage of max duration (if set). */
		float duration_progress = 100 * dpc_job_elapsed_time_get() / duration_max;
		fprintf(fp, " (%.1f%%)", duration_progress);
	}

	/* Number of started sessions. */
	fprintf(fp, " sessions: [started: %u", session_num);
	if (session_max_num) {
		/* And percentage of max number of sessions (if set). */
		float session_progress = 100 * (float)session_num / session_max_num;
		fprintf(fp, " (%.1f%%)", session_progress);
	}

	/* Ongoing (active) sessions. (== number of packets to which we're waiting for a reply) */
	fprintf(fp, ", ongoing: %u", session_num_active);

	/* Packets lost (for which a reply was expected, but we didn't get one. */
	if (stat_ctx.num_packet_lost[0] > 0) {
		fprintf(fp, ", lost: %u", stat_ctx.num_packet_lost[0]);
	}

	/* NAK replies. */
	if (stat_ctx.num_packet_recv[6] > 0) {
		fprintf(fp, ", %s: %u", dpc_message_types[6], stat_ctx.num_packet_recv[6]);
	}

	fprintf(fp, "]");

	/* Print rate if job elapsed time is at least 1 s. */
	if (dpc_job_elapsed_time_get() >= 1.0) {
		float reply_rate = dpc_get_tr_rate(DPC_TR_ALL);
		if (reply_rate > 0) {
			fprintf(fp, ", reply rate (/s): %.3f", dpc_get_tr_rate(DPC_TR_ALL));
		} else {
			/*
			 *	If we do not have any transaction, it means that all packets are lost (no reply received),
			 *	or we're not expecting any reply (e.g. sending only Release messages).
			 *
			 *	In such a case, display the packets send rate instead.
			 *	Note: this will be fluctuating in case of "all packets are lost" - because of timeout.
			 */
			fprintf(fp, ", send rate (/s): %.3f", dpc_get_msg_rate(0));
		}
	}
	fprintf(fp, "\n");
}

/*
 *	Obtain the job (either ongoing or finished) elapsed time.
 */
static float dpc_job_elapsed_time_get(void)
{
	float elapsed;
	struct timeval tv_elapsed;

	/*
	 *	If job is finished, get elapsed time from start to end.
	 *	Otherwise, get elapsed time from start to now.
	 */
	if (timerisset(&tv_job_end)) {
		timersub(&tv_job_end, &tv_job_start, &tv_elapsed);
	} else {
		struct timeval tv_now;
		gettimeofday(&tv_now, NULL);
		timersub(&tv_now, &tv_job_start, &tv_elapsed);
	}
	elapsed = dpc_timeval_to_float(&tv_elapsed);

	return elapsed;
}

/*
 *	Compute the effective rate (reply per second) of a given transaction type (or all).
 *	Note: for a workflow (DORA), this is based on the final reply (Ack).
 */
static float dpc_get_tr_rate(dpc_transaction_type_t i)
{
	dpc_assert(i < DPC_TR_MAX);

	dpc_transaction_stats_t *my_stats = &stat_ctx.tr_stats[i];
	float elapsed = dpc_job_elapsed_time_get();

	if (elapsed <= 0) return 0; /* Should not happen. */
	return (float)my_stats->num / elapsed;
}

/*
 *	Compute the rate (packets sent per second) of a given message type (or all).
 */
static float dpc_get_msg_rate(uint8_t i)
{
	dpc_assert(i < DHCP_MAX_MESSAGE_TYPE);

	float elapsed = dpc_job_elapsed_time_get();

	if (elapsed <= 0) return 0; /* Should not happen. */
	return (float)stat_ctx.num_packet_sent[i] / elapsed;
}

/*
 *	Print per-transaction type statistics.
 */
static void dpc_tr_stats_fprint(FILE *fp)
{
	int i;
	int i_start = 0;
	int num_stat = 0;
	unsigned int pad_len = 0;

	/* Check the number of statistics types with actual data. */
	for (i = 1; i < DPC_TR_MAX; i ++) {
		if (stat_ctx.tr_stats[i].num > 0) {
			num_stat ++;
			if (strlen(transaction_types[i]) > pad_len) pad_len = strlen(transaction_types[i]);
		}
	}
	if (num_stat == 0) return; /* If we got nothing, do nothing. */

	fprintf(fp, "*** Statistics (per-transaction):\n");

	if (num_stat == 1) i_start = 1; /* only print "All" if we have more than one (otherwise it's redundant). */
	pad_len ++;

	for (i = i_start; i < DPC_TR_MAX; i++) {
		dpc_transaction_stats_t *my_stats = &stat_ctx.tr_stats[i];

		if (my_stats->num == 0) continue;

		float rtt_avg = 1000 * dpc_timeval_to_float(&my_stats->rtt_cumul) / my_stats->num;
		float rtt_min = 1000 * dpc_timeval_to_float(&my_stats->rtt_min);
		float rtt_max = 1000 * dpc_timeval_to_float(&my_stats->rtt_max);

		fprintf(fp, "\t%-*.*s:  num: %d, RTT (ms): [avg: %.3f, min: %.3f, max: %.3f]",
		        pad_len, pad_len, transaction_types[i], my_stats->num, rtt_avg, rtt_min, rtt_max);

		/* Print rate if job elapsed time is at least 1 s. */
		if (dpc_job_elapsed_time_get() >= 1.0) {
			fprintf(fp, ", rate (avg/s): %.3f", dpc_get_tr_rate(i));
		}

		fprintf(fp, "\n");
	}
}

/*
 *	Print global statistics.
 */
static void dpc_stats_fprint(FILE *fp)
{
	if (!fp) return;

	char messages[DPC_MSG_NUM_STRLEN];

	fprintf(fp, "*** Statistics (global):\n");

	/* Job elapsed time, from start to end. */
	fprintf(fp, "\t%-*.*s: %s\n", LG_PAD_STATS, LG_PAD_STATS, "Elapsed time (s)",
		dpc_delta_time_sprint(elapsed_buf, &tv_job_start, &tv_job_end, DPC_DELTA_TIME_DECIMALS));

	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Sessions", session_num);

	/* Packets sent (total, and of each message type). */
	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets sent", stat_ctx.num_packet_sent[0]);
	if (stat_ctx.num_packet_sent[0] > 0) {
		fprintf(fp, " (%s)", dpc_num_message_type_sprint(messages, stat_ctx.num_packet_sent));
	}
	fprintf(fp, "\n");

	/* Packets received (total, and of each message type - if any). */
	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets received", stat_ctx.num_packet_recv[0]);
	if (stat_ctx.num_packet_recv[0] > 0) {
		fprintf(fp, " (%s)", dpc_num_message_type_sprint(messages, stat_ctx.num_packet_recv));
	}
	fprintf(fp, "\n");

	/* Packets to which no response was received. */
	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Packets lost", stat_ctx.num_packet_lost[0]);

	/* Packets received but which were not expected (timed out, sent to the wrong address, or whatever. */
	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Replies unexpected",
		stat_ctx.num_packet_recv_unexpected);
}

/*
 *	Update statistics for a type of transaction: number of transactions, cumulated rtt, min/max rtt.
 */
static void dpc_tr_stats_update(dpc_transaction_type_t tr_type, struct timeval *rtt)
{
	if (tr_type < 0 || tr_type >= DPC_TR_MAX) return;
	if (!rtt) return;

	dpc_transaction_stats_t *my_stats = &stat_ctx.tr_stats[tr_type]; /* For easier access. */

	/* Update 'rtt_min'. */
	if ((my_stats->num == 0) || (timercmp(rtt, &my_stats->rtt_min, <))) {
		my_stats->rtt_min = *rtt;
	}

	/* Update 'rtt_max'. */
	if ((my_stats->num == 0) || (timercmp(rtt, &my_stats->rtt_max, >=))) {
		my_stats->rtt_max = *rtt;
	}

	/* Update 'rtt_cumul' and 'num'. */
	timeradd(&my_stats->rtt_cumul, rtt, &my_stats->rtt_cumul);
	my_stats->num ++;

	DPC_DEBUG_TRACE("Updated transaction stats: type: %d, num: %d, this rtt: %.6f, min: %.6f, max: %.6f",
	                tr_type, my_stats->num, dpc_timeval_to_float(rtt),
	                dpc_timeval_to_float(&my_stats->rtt_min), dpc_timeval_to_float(&my_stats->rtt_max));
}

/*
 *	Update statistics.
 */
static void dpc_statistics_update(RADIUS_PACKET *request, RADIUS_PACKET *reply)
{
	if (!request || !reply) return;

	dpc_transaction_type_t tr_type = -1;
	struct timeval rtt;
	int request_code = request->code;
	int reply_code = reply->code;

	/* Identify the transaction (request / reply). */
	if (request_code == FR_DHCP_DISCOVER) {
		if (reply_code == FR_DHCP_OFFER) tr_type = DPC_TR_DISCOVER_OFFER;
		else if (reply_code == FR_DHCP_ACK) tr_type = DPC_TR_DISCOVER_ACK;
	}
	else if (request_code == FR_DHCP_REQUEST) {
		if (reply_code == FR_DHCP_ACK) tr_type = DPC_TR_REQUEST_ACK;
		else if (reply_code == FR_DHCP_NAK) tr_type = DPC_TR_REQUEST_NAK;
	}
	else if (request_code == FR_DHCP_LEASE_QUERY) {
		if (reply_code == FR_DHCP_LEASE_UNASSIGNED) tr_type = DPC_TR_LEASE_QUERY_UNASSIGNED;
		else if (reply_code == FR_DHCP_LEASE_UNKNOWN) tr_type = DPC_TR_LEASE_QUERY_UNKNOWN;
		else if (reply_code == FR_DHCP_LEASE_ACTIVE) tr_type = DPC_TR_LEASE_QUERY_ACTIVE;
	}

	timersub(&reply->timestamp, &request->timestamp, &rtt);

	/* Update statistics for that kind of transaction. */
	dpc_tr_stats_update(tr_type, &rtt);

	/* Also update for 'All'. */
	dpc_tr_stats_update(DPC_TR_ALL, &rtt);
}

/*
 *	Event callback: progress statistics summary.
 */
static void dpc_progress_stats(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, UNUSED void *uctx)
{
	/* Do statistics summary. */
	dpc_progress_stats_fprint(stdout);

	/* ... and schedule next time. */
	dpc_event_add_progress_stats();
}

/*
 *	Add timer event: progress statistics summary.
 */
static void dpc_event_add_progress_stats(void)
{
	if (!timerisset(&tv_progress_interval)) return;

	/*
	 *	Generate uniformly spaced out statistics.
	 *	To avoid drifting, schedule next event relatively to the expected trigger of previous one.
	 */
	if (!timerisset(&tv_progress_stat)) {
		gettimeofday(&tv_progress_stat, NULL);
	}
	timeradd(&tv_progress_stat, &tv_progress_interval, &tv_progress_stat);

	if (fr_event_timer_insert(autofree, event_list, &ev_progress_stats,
	                          &tv_progress_stat, dpc_progress_stats, NULL) < 0) {
		ERROR("Failed inserting progress statistics event");
	}
}

/*
 *	Event callback: request timeout.
 */
static void dpc_request_timeout(UNUSED fr_event_list_t *el, UNUSED struct timeval *when, void *uctx)
{
	dpc_session_ctx_t *session = talloc_get_type_abort(uctx, dpc_session_ctx_t);

	if (session->state == DPC_STATE_WAIT_OTHER_REPLIES) {
		/*
		 *	We have received at least one reply. We've been waiting for more from other DHCP servers.
		 *	So do not track this as "packet lost".
		 */
		DPC_DEBUG_TRACE("Stop waiting for more replies");
	} else {
		DPC_DEBUG_TRACE("Request timed out");

		if (packet_trace_lvl >= 1) dpc_packet_header_fprint(fr_log_fp, session, session->packet, DPC_PACKET_TIMEOUT);

		/* Statistics. */
		STAT_INCR_PACKET_LOST(session->packet->code);
	}

	/* Finish the session. */
	dpc_session_finish(session);
}

/*
 *	Add timer event: request timeout.
 *	Note: even if timeout = 0 we do insert an event (in this case it will be triggered immediately).
 *	If timeout_in is not NULL: use this as timeout. Otherwise, use fixed global timeout tv_timeout.
 */
static void dpc_event_add_request_timeout(dpc_session_ctx_t *session, struct timeval *timeout_in)
{
	struct timeval tv_event;
	gettimeofday(&tv_event, NULL);
	timeradd(&tv_event, (timeout_in ? timeout_in : &tv_timeout), &tv_event);

	/* If there is an active event timer for this session, clear it before arming a new one. */
	if (session->event) {
		fr_event_timer_delete(event_list, &session->event);
		session->event = NULL;
	}

	if (fr_event_timer_insert(session, event_list, &session->event,
	                          &tv_event, dpc_request_timeout, session) < 0) {
		ERROR("Failed inserting request timeout event");
	}
}

/*
 *	Send one packet.
 *	Grab a socket, insert packet in the packet list (and obtain an id), encode DHCP packet, and send it.
 *	Returns: 0 = success, -1 = error.
 */
static int dpc_send_one_packet(dpc_session_ctx_t *session, RADIUS_PACKET **packet_p)
// note: we need a 'RADIUS_PACKET **' for dpc_packet_list_id_alloc.
{
	RADIUS_PACKET *packet = *packet_p;
	int my_sockfd;
	int ret;

	DPC_DEBUG_TRACE("Preparing to send one packet");

	/*
	 *	Get a socket to send this over.
	 */
#ifdef HAVE_LIBPCAP
	if (session->input->ext.with_pcap) {
		my_sockfd = pcap->fd;
	} else
#endif
	{
		my_sockfd = dpc_socket_provide(pl, &packet->src_ipaddr, packet->src_port);
	}
	if (my_sockfd < 0) {
		SPERROR("Failed to provide a suitable socket");
		return -1;
	}

	if (packet->id == DPC_PACKET_ID_UNASSIGNED) {
		/* Need to assign an xid to this packet. */
		bool rcode;

		/*
		 *	Set packet->id to prefered value (if any). Note: it will be reset if allocation fails.
		 */
		packet->id = session->input->ext.xid;

		/*
		 *	Allocate an id, and prepare the packet (socket fd, src addr)
		 */
		rcode = dpc_packet_list_id_alloc(pl, my_sockfd, packet_p);
		if (!rcode) {
			SERROR("Failed to allocate packet xid");
			return -1;
		}
	}

	dpc_assert(packet->id != DPC_PACKET_ID_UNASSIGNED);
	dpc_assert(packet->data == NULL);

	/*
	 *	Encode the packet.
	 */
	DPC_DEBUG_TRACE("Encoding and sending packet");
	if (dpc_dhcp_encode(packet) < 0) { /* Should never happen. */
		SERROR("Failed encoding request packet");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Send the packet.
	 */
	gettimeofday(&packet->timestamp, NULL); /* Store packet send time. */
	// shouldn't FreeRADIUS lib do that ? TODO.
	// on receive, reply timestamp is set by fr_dhcpv4_udp_packet_recv
	// - actual value is obtained from recvfromto, from a gettimeofday right before returning

	packet->sockfd = my_sockfd;

#ifdef HAVE_LIBPCAP
	if (session->input->ext.with_pcap) {
		/* Send using pcap raw socket. */
		packet->if_index = pcap->if_index; /* So we can trace it. */
		ret = fr_dhcpv4_pcap_send(pcap, eth_bcast, packet);
		/*
		 *	Note: we're sending from our real Ethernet source address (from the selected interface,
		 *	set by fr_pcap_open / fr_pcap_mac_addr), *not* field 'chaddr' from the DHCP packet
		 *	(which is a fake hardware address).
		 *	This because we want replies (sent by the DHCP server to our Ethernet address) to reach us.
		 */
	} else
#endif
	{
		/* Send using a connectionless UDP socket (sendfromto). */
		ret = fr_dhcpv4_udp_packet_send(packet);
	}
	if (ret < 0) {
		SPERROR("Failed to send packet");
		return -1;
	}

	dpc_packet_fprint(fr_log_fp, session, packet, DPC_PACKET_SENT, packet_trace_lvl); /* Print request packet. */

	/* Statistics. */
	STAT_INCR_PACKET_SENT(packet->code);

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
	struct timeval tv;
	RADIUS_PACKET *reply = NULL, **packet_p;
	VALUE_PAIR *vp;
	dpc_session_ctx_t *session;
	int max_fd;
	char from_to_buf[DPC_FROM_TO_STRLEN] = "";

	/* Wait for reply, timing out as necessary */
	FD_ZERO(&set);

	max_fd = dpc_packet_list_fd_set(pl, &set);
	if (max_fd < 0) {
		/* no sockets to listen on! */
		return 0;
	}

	if (tv_wait_time == NULL || !timerisset(tv_wait_time)) {
		timerclear(&tv);
	} else {
		tv = *tv_wait_time;
		DPC_DEBUG_TRACE("Max wait time: %.6f", dpc_timeval_to_float(&tv));
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

	DPC_DEBUG_TRACE("Received packet %s, id: %u (0x%08x)",
	                dpc_packet_from_to_sprint(from_to_buf, reply, false), reply->id, reply->id);

	if (ipaddr_defined(allowed_server)) {
		/*
		 *	Only allow replies from a specific server (overall policy set through option -a).
		 */
		if (fr_ipaddr_cmp(&reply->src_ipaddr, &allowed_server) != 0) {
			DEBUG("Received packet Id %u (0x%08x) from unauthorized server (%s): ignored.",
			      reply->id, reply->id, fr_inet_ntop(from_to_buf, sizeof(from_to_buf), &reply->src_ipaddr));
			fr_radius_packet_free(&reply);
			return -1;
		}
	}

	/*
	 *	Query the packet list to get the original packet to which this is a reply.
	 */
	packet_p = dpc_packet_list_find_byreply(pl, reply);
	if (!packet_p) {
		/*
		 *	We did not find the packet in the packet list. This can happen in several situations:
		 *	- The initial packet timed out and we receive the response later (likely the DHCP server is overloaded)
		 *	- The IP address to which the reply was sent does not match (maybe giaddr / source IP address mixup)
		 *	- The transaction ID does not match (DHCP server is broken)
		 */
		DEBUG("Received unexpected packet Id %u (0x%08x) %s length %zu",
		      reply->id, reply->id, dpc_packet_from_to_sprint(from_to_buf, reply, false), reply->data_len);

		stat_ctx.num_packet_recv_unexpected ++;
		fr_radius_packet_free(&reply);
		return -1;
	}

	/*
	 *	Retrieve the session to which belongs the original packet.
	 *	To do so we use fr_packet2myptr, this is a magical macro defined in include/packet.h
	 */
	session = fr_packet2myptr(dpc_session_ctx_t, packet, packet_p);

	DPC_DEBUG_TRACE("Packet belongs to session id: %d", session->id);

	if ((vp = ncc_pair_find_by_da(session->packet->vps, attr_authorized_server))) {
		/*
		 *	Only allow replies from a specific server (per-packet policy set through attribute).
		 */
		if (fr_ipaddr_cmp(&reply->src_ipaddr, &vp->vp_ip) != 0) {
			SDEBUG("Received packet Id %u (0x%08x) from unauthorized server (%s): ignored.",
			       reply->id, reply->id, fr_inet_ntop(from_to_buf, sizeof(from_to_buf), &reply->src_ipaddr));
			fr_radius_packet_free(&reply);
			return -1;
		}
		// note: we can get "unexpected packets" with this.
		// TODO: keep a context of broadcast packets for a little while so we can wait for all responses ?
	}

	/*
	 *	Decode the reply packet.
	 */
	if (fr_dhcpv4_packet_decode(reply) < 0) {
		SPERROR("Failed to decode reply packet (id: %u)", reply->id);
		fr_radius_packet_free(&reply);
		/*
		 *	Don't give hope and kill the session now. Maybe we'll receive something better.
		 *	If not, well... the timeout event will do its dirty job.
		 */
		return -1;
	}

	/* Statistics. */
	STAT_INCR_PACKET_RECV(reply->code);

	/*
	 *	Handle the reply, and decide if the session is finished or not yet.
	 */
	if (!dpc_session_handle_reply(session, reply)) {
		dpc_session_finish(session);
	}

	return 1;
}

/*
 *	Handle a reply which belongs to a given ongoing session.
 *	Returns true if we're not done with the session (so it should not be terminated yet), false otherwise.
 */
static bool dpc_session_handle_reply(dpc_session_ctx_t *session, RADIUS_PACKET *reply)
{
	struct timeval rtt;

	if (!session || !reply) return false;

	if (   (session->state == DPC_STATE_DORA_EXPECT_OFFER && reply->code != FR_DHCP_OFFER)
		|| (session->state == DPC_STATE_DORA_EXPECT_ACK && reply->code != FR_DHCP_ACK) ) {
		/*
		 *	This is *not* a reply we've been expecting.
		 *	This can happen legitimately if, when handling a DORA, we've sent the Request and are
		 *	now expecting an Ack, but then we receive another Offer (from another DHCP server).
		 */
		DPC_DEBUG_TRACE("Discarding received reply code %d (session state: %d)", reply->code, session->state);

		dpc_packet_header_fprint(fr_log_fp, session, reply, DPC_PACKET_RECEIVED_DISCARD);
		fr_radius_packet_free(&reply);

		return true; /* Session is not finished. */
	}

	session->reply = reply;
	talloc_steal(session, reply); /* Reparent reply packet (allocated on NULL context) so we don't leak. */

	/* Compute rtt. */
	timersub(&session->reply->timestamp, &session->packet->timestamp, &rtt);
	DPC_DEBUG_TRACE("Packet response time: %.6f", dpc_timeval_to_float(&rtt));

	dpc_packet_fprint(fr_log_fp, session, reply, DPC_PACKET_RECEIVED, packet_trace_lvl); /* print reply packet. */

	/* Update statistics. */
	dpc_statistics_update(session->packet, session->reply);

	/*
	 *	If dealing with a DORA transaction, after a valid Offer we need to send a Request.
	 */
	if (session->state == DPC_STATE_DORA_EXPECT_OFFER && session->reply->code == FR_DHCP_OFFER) {
		return dpc_session_dora_request(session);
	}

	/*
	 *	We've just completed a DORA transaction.
	 */
	if (session->state == DPC_STATE_DORA_EXPECT_ACK && session->reply->code == FR_DHCP_ACK) {
		/*
		 *	Update statistics for DORA workflows.
		 */
		timersub(&session->reply->timestamp, &session->tv_start, &rtt);
		dpc_tr_stats_update(DPC_TR_DORA, &rtt);

		/*
		 *	Maybe send a Decline or Release now.
		 */
		if (session->input->ext.workflow == DPC_WORKFLOW_DORA_DECLINE) {
			return dpc_session_dora_decline(session);
		} else if (session->input->ext.workflow == DPC_WORKFLOW_DORA_RELEASE) {
			return dpc_session_dora_release(session);
		}

		return false; /* Session is done. */
	}

	/*
	 *	There may be more Offer replies, from other DHCP servers. Wait for them.
	 */
	if (multi_offer && session->input->ext.with_pcap && session->reply->code == FR_DHCP_OFFER) {
		DPC_DEBUG_TRACE("Waiting for more replies from other DHCP servers");
		session->state = DPC_STATE_WAIT_OTHER_REPLIES;
		/* Note: there is no need to arm a new event timeout. The initial timer is still running. */

		return true; /* Session is not finished. */
	}

	return false; /* Session is done. */
}

/*
 *	Handling of a DORA workflow. After receiving an Offer, try and build a Request.
 *	Encode and send the packet, then wait for the reply.
 *	Returns: true if Request was sent, false otherwise.
 */
static bool dpc_session_dora_request(dpc_session_ctx_t *session)
{
	VALUE_PAIR *vp_xid, *vp_yiaddr, *vp_server_id, *vp_requested_ip;
	RADIUS_PACKET *packet;

	/* Get the Offer xid. */
	vp_xid = fr_pair_find_by_da(session->reply->vps, attr_dhcp_transaction_id, TAG_ANY);
	if (!vp_xid) { /* Should never happen (DHCP field). */
		return false;
	}

	/* Offer must provide yiaddr (DHCP-Your-IP-Address). */
	vp_yiaddr = fr_pair_find_by_da(session->reply->vps, attr_dhcp_your_ip_address, TAG_ANY);
	if (!vp_yiaddr || vp_yiaddr->vp_ipv4addr == 0) {
		DEBUG2("Session DORA: no yiaddr provided in Offer reply");
		return false;
	}

	/* Offer must contain option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	vp_server_id = fr_pair_find_by_da(session->reply->vps, attr_dhcp_server_identifier, TAG_ANY);
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

	packet->code = FR_DHCP_REQUEST;
	session->state = DPC_STATE_DORA_EXPECT_ACK;

	/*
	 *	Use information from the Offer reply to complete the new packet.
	 */

	/*
	 *	Add option 50 Requested IP Address (DHCP-Requested-IP-Address) = yiaddr
	 *	First remove previous option 50 if one was provided (server may have offered a different lease).
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_requested_ip_address);
	vp_requested_ip = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_requested_ip_address);
	fr_value_box_copy(vp_requested_ip, &vp_requested_ip->data, &vp_yiaddr->data);

	/* Add option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_server_id));

	/* Reset input xid to value obtained from the Offer reply. */
	session->input->ext.xid = vp_xid->vp_uint32;

	/*
	 *	New packet is ready. Free old packet and its reply. Then use the new packet.
	 */
	talloc_free(session->reply);
	session->reply = NULL;

	if (!dpc_packet_list_id_free(pl, session->packet)) { /* Should never fail. */
		SERROR("Failed to free from packet list, id: %u", session->packet->id);
	}
	talloc_free(session->packet);
	session->packet = packet;

	/*
	 *	Encode and send packet.
	 */
	if (dpc_send_one_packet(session, &session->packet) < 0) {
		return false;
	}

	/*
	 *	Arm request timeout.
	 */
	dpc_event_add_request_timeout(session, NULL);

	return true; /* Session is not finished. */
}

/*
 *	Handling of a DORA workflow. After receiving an Ack, try and build a Release.
 *	Encode and send the packet. (no reply is expected)
 */
static bool dpc_session_dora_release(dpc_session_ctx_t *session)
{
	VALUE_PAIR *vp_yiaddr, *vp_server_id, *vp_ciaddr;
	RADIUS_PACKET *packet;

	/* Ack provides IP address assigned to client in field yiaddr (DHCP-Your-IP-Address). */
	vp_yiaddr = fr_pair_find_by_da(session->reply->vps, attr_dhcp_your_ip_address, TAG_ANY);
	if (!vp_yiaddr || vp_yiaddr->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Release: no yiaddr provided in Ack reply");
		return false;
	}

	/* Ack must contain option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	vp_server_id = fr_pair_find_by_da(session->reply->vps, attr_dhcp_server_identifier, TAG_ANY);
	if (!vp_server_id || vp_server_id->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Release: no option 54 (server id) provided in Ack reply");
		return false;
	}

	/*
	 *	Prepare a new DHCP Release packet.
	 */
	DPC_DEBUG_TRACE("DORA-Release: received valid Ack, now preparing Release");

	packet = dpc_request_init(session, session->input);
	if (!packet) return false;

	packet->code = FR_DHCP_RELEASE;
	session->state = DPC_STATE_NO_REPLY;

	/*
	 *	Use information from the Ack reply to complete the new packet.
	 */

	/* Add field ciaddr (DHCP-Client-IP-Address) = yiaddr */
	vp_ciaddr = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_client_ip_address);
	fr_value_box_copy(vp_ciaddr, &vp_ciaddr->data, &vp_yiaddr->data);

	/*
	 *	Remove eventual option 50 Requested IP Address.
	 *	(it may be provided for Discover, but must *not* be in Release)
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_requested_ip_address);

	/* Add option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_server_id));

	/* xid is supposed to be selected by client. Let the program pick a new one. */
	session->input->ext.xid = DPC_PACKET_ID_UNASSIGNED;

	/*
	 *	New packet is ready. Free old packet and its reply. Then use the new packet.
	 */
	talloc_free(session->reply);
	session->reply = NULL;

	if (!dpc_packet_list_id_free(pl, session->packet)) { /* Should never fail. */
		SERROR("Failed to free from packet list, id: %u", session->packet->id);
	}
	talloc_free(session->packet);
	session->packet = packet;

	/*
	 *	Encode and send packet.
	 */
	if (dpc_send_one_packet(session, &session->packet) < 0) {
		return false;
	}
	// Note: if the DORA was broadcast, we're also broadcasting the Release. It works. But...
	// According to RFC 2131, a Release is supposed to be unicast. For this to work we would need the
	// IP address to be configured. Which is probably not the case. So it's better to just broadcast anyway.

	return false; /* Session is done. */
}

/*
 *	Handling of a DORA workflow. After receiving an Ack, try and build a Decline.
 *	Encode and send the packet. (no reply is expected)
 */
static bool dpc_session_dora_decline(dpc_session_ctx_t *session)
{
	VALUE_PAIR *vp_yiaddr, *vp_server_id, *vp_ciaddr, *vp_requested_ip;
	RADIUS_PACKET *packet;

	/* Ack provides IP address assigned to client in field yiaddr (DHCP-Your-IP-Address). */
	vp_yiaddr = fr_pair_find_by_da(session->reply->vps, attr_dhcp_your_ip_address, TAG_ANY);
	if (!vp_yiaddr || vp_yiaddr->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Decline: no yiaddr provided in Ack reply");
		return false;
	}

	/* Ack must contain option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	vp_server_id = fr_pair_find_by_da(session->reply->vps, attr_dhcp_server_identifier, TAG_ANY);
	if (!vp_server_id || vp_server_id->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Decline: no option 54 (server id) provided in Ack reply");
		return false;
	}

	/*
	 *	Prepare a new DHCP Decline packet.
	 */
	DPC_DEBUG_TRACE("DORA-Decline: received valid Ack, now preparing Decline");

	packet = dpc_request_init(session, session->input);
	if (!packet) return false;

	packet->code = FR_DHCP_DECLINE;
	session->state = DPC_STATE_NO_REPLY;

	/*
	 *	Use information from the Ack reply to complete the new packet.
	 */

	/* Add field ciaddr (DHCP-Client-IP-Address) = yiaddr */
	vp_ciaddr = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_client_ip_address);
	fr_value_box_copy(vp_ciaddr, &vp_ciaddr->data, &vp_yiaddr->data);

	/*
	 *	Add option 50 Requested IP Address (DHCP-Requested-IP-Address) = yiaddr
	 *	First remove previous option 50 if one was provided (server may have offered a different lease).
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_requested_ip_address);
	vp_requested_ip = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_requested_ip_address);
	fr_value_box_copy(vp_requested_ip, &vp_requested_ip->data, &vp_yiaddr->data);

	/* Add option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_server_id));

	/* xid is supposed to be selected by client. Let the program pick a new one. */
	session->input->ext.xid = DPC_PACKET_ID_UNASSIGNED;

	/*
	 *	New packet is ready. Free old packet and its reply. Then use the new packet.
	 */
	talloc_free(session->reply);
	session->reply = NULL;

	if (!dpc_packet_list_id_free(pl, session->packet)) { /* Should never fail. */
		SERROR("Failed to free from packet list, id: %u", session->packet->id);
	}
	talloc_free(session->packet);
	session->packet = packet;

	/*
	 *	Encode and send packet.
	 */
	if (dpc_send_one_packet(session, &session->packet) < 0) {
		return false;
	}

	return false; /* Session is done. */
}

/*
 *	Prepare a request to be sent as if relayed through a gateway.
 */
static void dpc_request_gateway_handle(RADIUS_PACKET *packet, ncc_endpoint_t *gateway)
{
	if (!gateway) return;

	DPC_DEBUG_TRACE("Assigning packet to gateway");

	/*
	 *	We've been told to handle sent packets as if relayed through a gateway.
	 *	This means:
	 *	- packet source IP / port = gateway IP / port (those we've already set)
	 *	- giaddr = gateway IP
	 *	- hops = 1 (arbitrary)
	 *	All of these can be overriden (entirely or partially) through input vps.
	 *	Note: the DHCP server will respond to the giaddr, not the packet source IP. Normally they are the same.
	 */
	VALUE_PAIR *vp_giaddr, *vp_hops;

	/* set giaddr if not specified in input vps (DHCP-Gateway-IP-Address). */
	vp_giaddr = fr_pair_find_by_da(packet->vps, attr_dhcp_gateway_ip_address, TAG_ANY);
	if (!vp_giaddr) {
		vp_giaddr = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_gateway_ip_address);
		vp_giaddr->vp_ipv4addr = gateway->ipaddr.addr.v4.s_addr;
		vp_giaddr->vp_ip.af = AF_INET;
		vp_giaddr->vp_ip.prefix = 32;
	}

	/* set hops if not specified in input vps (DHCP-Hop-Count). */
	vp_hops = fr_pair_find_by_da(packet->vps, attr_dhcp_hop_count, TAG_ANY);
	if (!vp_hops) {
		vp_hops = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_hop_count);
		vp_hops->vp_uint8 = 1;
	}
}

/*
 *	Initialize a DHCP packet from an input item.
 */
static RADIUS_PACKET *dpc_request_init(TALLOC_CTX *ctx, dpc_input_t *input)
{
	RADIUS_PACKET *request;

	MEM(request = fr_radius_alloc(ctx, true)); /* Note: this sets id to -1. */

	/* Fill in the packet value pairs. */
	dpc_pair_list_append(request, &request->vps, input->vps);

	/* Prepare gateway handling. */
	dpc_request_gateway_handle(request, input->ext.gateway);

	/*
	 *	Use values prepared earlier.
	 */
	request->code = input->ext.code;
	request->src_port = input->ext.src.port;
	request->dst_port = input->ext.dst.port;
	request->src_ipaddr = input->ext.src.ipaddr;
	request->dst_ipaddr = input->ext.dst.ipaddr;

	char from_to_buf[DPC_FROM_TO_STRLEN] = "";
	DPC_DEBUG_TRACE("New packet allocated (code: %u, %s)", request->code,
	                dpc_packet_from_to_sprint(from_to_buf, request, false));

	return request;
}

/*
 *	Encode a DHCP packet.
 */
static int dpc_dhcp_encode(RADIUS_PACKET *packet)
{
	int r;
	VALUE_PAIR *vp;

	/*
	 *	If DHCP encoded data is provided, use it as is. Do not call fr_dhcpv4_packet_encode.
	 */
	if ((vp = ncc_pair_find_by_da(packet->vps, attr_encoded_data))) {
		packet->data_len = vp->vp_length;
		packet->data = talloc_zero_array(packet, uint8_t, packet->data_len);
		memcpy(packet->data, vp->vp_octets, vp->vp_length);

		/* Overwrite xid in packet data with id allocated. */
		if (packet->data_len >= 8) {
			uint32_t lvalue = htonl(packet->id);
			uint8_t *p = packet->data + 4;
			memcpy(p, &lvalue, 4);
		}
		return 0;
	}

	/*
	 *	Reset DHCP-Transaction-Id to xid allocated (it may not be what was asked for,
	 *	the requested id may not have been available).
	 *	Note: function fr_dhcpv4_packet_encode uses this to (re)write packet->id.
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_transaction_id);
	vp = fr_pair_afrom_da(packet, attr_dhcp_transaction_id);
	vp->vp_uint32 = packet->id;
	fr_pair_add(&packet->vps, vp);

	r = fr_dhcpv4_packet_encode(packet); /* This always returns 0. */
	/* Note: fr_dhcpv4_packet_encode encodes a NAK if there is no message type provided. */

	fr_strerror(); /* Clear the error buffer */

	/*
	 *	Note: if packet data len < 300 (DEFAULT_PACKET_SIZE), fr_dhcpv4_packet_encode will pad with
	 *	zeroes at the end of the packet data to fill up 300 octets.
	 *	From protocols/dhcpv4/dhcpv4.h: "Some clients silently ignore responses less than 300 bytes."
	 *	(We are a client, but not that dumb.)
	 */

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

	/* Copy pre-parsed information from template. */
	input->ext = transport->ext;

	/*
	 *	Associate input to gateway, if one is defined (or several).
	 */
	if (!ipaddr_defined(input->ext.src.ipaddr) && gateway_list) {
		input->ext.gateway = &gateway_list[gateway_next];
		gateway_next = (gateway_next + 1) % gateway_num;

		input->ext.src = *(input->ext.gateway);
	}

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

		fr_cursor_t cursor;
		VALUE_PAIR *vp;

		for (vp = fr_cursor_init(&cursor, &template_variable->vps);
		     vp;
		     vp = fr_cursor_next(&cursor))
		{
			/* Only DHCP attributes can be variable. */
			if (fr_dict_vendor_num_by_da(vp->da) != DHCP_MAGIC_VENDOR) continue;

			/* Update value according to template variable mode. */
			switch (templ_var) {
			case DPC_TEMPL_VAR_INCREMENT:
				dpc_pair_value_increment(vp);
				break;
			case DPC_TEMPL_VAR_RANDOM:
				dpc_pair_value_randomize(vp);
				break;
			default:
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
	 *	If not using a template, copy this input item if it has to be used again.
	 */
	input->num_use ++;
	if (!with_template && input->num_use < input_num_use) {
		DPC_DEBUG_TRACE("Input (id: %u) will be reused (num use: %u, max: %u)",
		                input->id, input->num_use, input_num_use);
		dpc_input_t *input_dup = dpc_input_item_copy(ctx, input);
		if (input_dup) {
			/*
			 *	Add it to the list of input items.
			 */
			dpc_input_item_add(&vps_list_in, input_dup);
		}
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
		session->reply_expected = is_dhcp_reply_expected(packet->code); /* Some messages do not get a reply. */

		if (input->ext.workflow) {
			session->state = DPC_STATE_DORA_EXPECT_OFFER; /* All workflows start with a Discover. */
		} else {
			session->state = (session->reply_expected ? DPC_STATE_EXPECT_REPLY : DPC_STATE_NO_REPLY);
		}

		/* Store session start time. */
		gettimeofday(&session->tv_start, NULL);

		session_num_active ++;
		SDEBUG2("New session initialized - active sessions: %u", session_num_active);
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
		if (!dpc_packet_list_id_free(pl, session->packet)) { /* Should never fail. */
			SERROR("Failed to free from packet list, id: %u", session->packet->id);
		}
	}

	/* Clear the event timer if it is armed. */
	if (session->event) {
		fr_event_timer_delete(event_list, &session->event);
		session->event = NULL;
	}

	session_num_active --;
	SDEBUG2("Session terminated - active sessions: %u", session_num_active);
	talloc_free(session);
}

/*
 *	Receive and handle reply packets.
 */
static void dpc_loop_recv(void)
{
	bool done = false;

	while (!done) {
		/*
		 *	Allow to block waiting until the next scheduled event.
		 *	We know we don't have anything else to do until then. It will avoid needlessly hogging one full CPU.
		 */
		struct timeval now, when, wait_max = { 0 };

		if (session_num_active >= session_max_active && fr_event_timer_peek(event_list, &when)) {
			gettimeofday(&now, NULL);
			if (timercmp(&when, &now, >)) timersub(&when, &now, &wait_max); /* No negative. */
		}

		/*
		 *	Receive and process packets until there's nothing left incoming.
		 */
		if (dpc_recv_one_packet(&wait_max) < 1) break;
	}
}

/*
 *	Figure out how to enforce a rate limit. To do so we limit the number of new sessions allowed to be started.
 *	Returns: true if a limit has to be enforced at the moment, false otherwise.
 */
static bool dpc_rate_limit_calc(uint32_t *max_new_sessions)
{
	if (!rate_limit) return false;

	float elapsed, elapsed_T2, rtt_avg, rate_T2;
	dpc_transaction_stats_t *my_stats = &stat_ctx.tr_stats[DPC_TR_ALL];
	uint32_t num_packet_sent = stat_ctx.num_packet_sent[0];

	elapsed = dpc_job_elapsed_time_get();

	/*
	 *	Right at the beginning we do not have enough data to make accurate calculations.
	 *	So it will be either all or nothing (the latter if we're already beyond the limit).
	 */
	if (elapsed < 0.5) {
		/* If we are already beyond the limit, we're too fast. Hold back. */
		if (my_stats->num >= rate_limit) {
			*max_new_sessions = 0;
			return true;
		} else if (my_stats->num == 0) {
			/* If we don't have any reply, limit applies to packets sent. */
			if (num_packet_sent >= rate_limit) {
				*max_new_sessions = 0;
			} else {
				*max_new_sessions = (rate_limit - num_packet_sent);
			}
			return true;
		}

		/* No limit. */
		return false;
	}

	/* If we don't have any reply, limit applies to packets sent. */
	if (my_stats->num == 0) {
		if (num_packet_sent >= rate_limit * elapsed) {
			*max_new_sessions = 0;
		} else {
			*max_new_sessions = (rate_limit * elapsed) - num_packet_sent;
		}
		return true;
	}

	/*
	 *	Now = T1. We've received so far N1 replies (having a current rate/s = N1 / <elapsed time>).
	 *	Project ourselves in the future at T2 = T1 + <average rtt>.
	 *	At this point we expect to have received replies to all the ongoing requests (active sessions).
	 *	If the projected rate/s is higher than the rate limit, do not allow new sessions to be started.
	 *	Otherwise, compute what we would need to attain this rate limit.
	 */
	rtt_avg = dpc_timeval_to_float(&my_stats->rtt_cumul) / my_stats->num;
	/*
	 *	Note: we might lose a few milliseconds of precision with a float.
	 *	But we use that to compute an average, so it will be completely invisible.
	 */

	elapsed_T2 = elapsed + rtt_avg;
	rate_T2 = (my_stats->num + session_num_active) / elapsed_T2;

	/* We already expect to be beyond the limit at T2, so do not allow new sessions to be started for now. */
	if (rate_T2 >= rate_limit) {
		*max_new_sessions = 0;
		return true;
	}

	/*
	 *	Compute how many new sessions we would need to start now, assuming they are answered in <averate rtt>,
	 *	to reach the desired rate limit:
	 *	rate limit = ( N1 + <currently active sessions> + <new sessions to start> ) / ( <elapsed> + <rtt avg> )
	 */
	*max_new_sessions = (rate_limit * elapsed_T2) - (my_stats->num + session_num_active);
	return true;
}

/*
 *	Start new sessions, if possible.
 *	Returns: number of new sessions effectively started.
 */
static uint32_t dpc_loop_start_sessions(void)
{
	bool done = false;
	uint32_t num_started = 0; /* Number of sessions started in this iteration. */

 	/* If we've flagged that sessions should be be started anymore, return immediately. */
	if (!start_sessions_flag) return 0;

	uint32_t limit_new_sessions = 0;
	bool do_limit = dpc_rate_limit_calc(&limit_new_sessions);

	/* Set a max allowed loop time - don't loop forever in case of packets not expecting replies. */
	struct timeval tv_loop_max;
	gettimeofday(&tv_loop_max, NULL);
	timeradd(&tv_loop_max, &tv_loop_max_time, &tv_loop_max);

	/* Also limit time up to the next scheduled statistics event. */
	if (timerisset(&tv_progress_stat) && timercmp(&tv_loop_max, &tv_progress_stat, >)) {
		tv_loop_max = tv_progress_stat;
	}

	while (!done) {
		/* Max loop time limit reached. */
		struct timeval now;
		gettimeofday(&now, NULL);
		if (timercmp(&now, &tv_loop_max, >)) {
			DPC_DEBUG_TRACE("Loop time limit reached, started: %u", num_started);
			break;
		}

		/* Max session limit reached. */
		if (session_max_num && session_num >= session_max_num) {
			INFO("Max number of sessions (%u) reached: will not start any new session.", session_max_num);
			start_sessions_flag = false;
			break;
		}

		/* Time limit reached. */
		if (duration_max && dpc_job_elapsed_time_get() >= duration_max) {
			INFO("Max duration (%.3f s) reached: will not start any new session.", duration_max);
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

		/* Rate limit enforced and we've already started as many sessions as allowed for now. */
		if (do_limit && num_started >= limit_new_sessions) break;

		/*
		 *	Initialize a new session and send the packet.
		 */
		dpc_session_ctx_t *session = dpc_session_init(autofree);
		if (!session) continue;

		num_started ++;

		if (dpc_send_one_packet(session, &session->packet) < 0) {
			dpc_session_finish(session);
			continue;
		}

		if (session->reply_expected) {
			/*
			 *	Arm request timeout.
			 */
			dpc_event_add_request_timeout(session, NULL);
		} else {
			/* We've sent a packet to which no reply is expected. So this session ends right now. */
			dpc_session_finish(session);
		}
	}

	return num_started;
}

/*
 *	Handle timer events.
 */
static void dpc_loop_timer_events(void)
{
	int num_processed = 0; /* Number of timers events triggered. */
	struct timeval when;

	if (fr_event_list_num_timers(event_list) <= 0) return;

	gettimeofday(&when, NULL); /* Now. */
	while (fr_event_timer_run(event_list, &when)) {
		num_processed ++;
	}
}

/*
 *	Check if we're done with the main processing loop.
 */
static bool dpc_loop_check_done(void)
{
	/* There are still ongoing requests, to which we expect a reply or wait for a timeout. */
	//if (dpc_packet_list_num_elements(pl) > 0) return false; // checking active sessions is enough.

	/* There are still active sessions. */
	if (session_num_active > 0) return false;

	/* There are still events to process (ignoring the progress statistics event if it is armed). */
	if (fr_event_list_num_timers(event_list) - ((ev_progress_stats != NULL) ? 1 : 0) > 0) return false;

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
		/* Start new sessions. */
		dpc_loop_start_sessions();

		/* Receive and process reply packets. */
		dpc_loop_recv();

		/* Handle timer events. */
		dpc_loop_timer_events();

		/* Check if we're done. */
		dpc_loop_check_done();
	}
}

/*
 *	Pre-allocate a socket for an input item.
 */
static void dpc_input_socket_allocate(dpc_input_t *input)
{
	static bool warn_inaddr_any = true;

#ifdef HAVE_LIBPCAP
	if (iface && (fr_ipaddr_is_inaddr_any(&input->ext.src.ipaddr) == 1)
	    && (dpc_ipaddr_is_broadcast(&input->ext.dst.ipaddr) == 1)
	   ) {
		DPC_DEBUG_TRACE("Input (id: %u) involves broadcast using pcap raw socket", input->id);

		input->ext.with_pcap = true;
		return;
	}
#endif

	/*
	 *	Allocate the socket now. If we can't, stop.
	 */
	if (dpc_socket_provide(pl, &input->ext.src.ipaddr, input->ext.src.port) < 0) {
		char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
		ERROR("Failed to provide a suitable socket (input id: %u, requested socket src: %s:%u)", input->id,
		      fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &input->ext.src.ipaddr), input->ext.src.port);
		exit(EXIT_FAILURE);
	}

	/*
	 *	If we're using INADDR_ANY, make sure we know what we're doing.
	 */
	if (warn_inaddr_any && fr_ipaddr_is_inaddr_any(&input->ext.src.ipaddr)) {
		WARN("You didn't specify a source IP address."
		     " Consequently, a socket was allocated with INADDR_ANY (0.0.0.0)."
		     " Please make sure this is really what you intended.");
		warn_inaddr_any = false; /* Once is enough. */
	}
}

/*
 *	Parse an input item and prepare information necessary to build a packet.
 */
static bool dpc_parse_input(dpc_input_t *input)
{
	fr_cursor_t cursor;
	VALUE_PAIR *vp;
	VALUE_PAIR *vp_data = NULL, *vp_workflow_type = NULL;

	input->ext.code = FR_CODE_UNDEFINED;

	/*
	 *	Check if we are provided with pre-encoded DHCP data.
	 *	If so, extract (if there is one) the message type and the xid.
	 *	All other DHCP attributes provided through value pairs are ignored.
	 */
	if ((vp_data = ncc_pair_find_by_da(input->vps, attr_encoded_data))) {
		input->ext.code = dpc_message_type_extract(vp_data);
		input->ext.xid = dpc_xid_extract(vp_data);
	} else {
		/* Memorize attribute DHCP-Workflow-Type for later (DHCP-Message-Type takes precedence). */
		vp_workflow_type = ncc_pair_find_by_da(input->vps, attr_workflow_type);
	}

	/*
	 *	Loop over input value pairs. These take precedence over program arguments and options.
	 */
	for (vp = fr_cursor_init(&cursor, &input->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {

		if (fr_dict_vendor_num_by_da(vp->da) == DHCP_MAGIC_VENDOR) {

			if (!vp_data) { /* If we have pre-encoded DHCP data, all other DHCP attributes are ignored. */

				if (vp->da == attr_dhcp_message_type) {
					/* Packet type. */
					input->ext.code = vp->vp_uint32;

				} else if (vp->da == attr_dhcp_transaction_id) {
					/* Prefered xid. */
					input->ext.xid = vp->vp_uint32;
				}
			}

		} else if (vp->da == attr_packet_dst_port) {
			input->ext.dst.port = vp->vp_uint16;

		} else if (vp->da == attr_packet_dst_ip_address) {
			memcpy(&input->ext.dst.ipaddr, &vp->vp_ip, sizeof(input->ext.dst.ipaddr));

		} else if (vp->da == attr_packet_src_port) {
			input->ext.src.port = vp->vp_uint16;

		} else if (vp->da == attr_packet_src_ip_address) {
			memcpy(&input->ext.src.ipaddr, &vp->vp_ip, sizeof(input->ext.src.ipaddr));

		}

	} /* loop over the input vps */

	/*
	 *	If not specified in input vps, use default values.
	 */
	if (!vp_data) {
		if (input->ext.code == FR_CODE_UNDEFINED) {
			/*
			 *	Handling a workflow. All workflows start with a Discover.
			 */
			if (vp_workflow_type && vp_workflow_type->vp_uint8 && vp_workflow_type->vp_uint8 < DPC_WORKFLOW_MAX) {
				input->ext.workflow = vp_workflow_type->vp_uint8;
				input->ext.code = FR_DHCP_DISCOVER;

			} else if (workflow_code) {
				input->ext.workflow = workflow_code;
				input->ext.code = FR_DHCP_DISCOVER;
			}
		}

		/* Fall back to message type provided through command line (if there is one). */
		if (input->ext.code == FR_CODE_UNDEFINED) input->ext.code = packet_code;
	}

	/*
	 *	If source (addr / port) is not defined in input vps, use gateway if one is specified.
	 *	If nothing goes, fall back to default.
	 */
	if (   !ipaddr_defined(input->ext.src.ipaddr)
	    && (!with_template && gateway_list) /* If using a template, do not assign a gateway now. */
	) {
		input->ext.gateway = &gateway_list[gateway_next];
		gateway_next = (gateway_next + 1) % gateway_num;

		input->ext.src = *(input->ext.gateway);
	}

	if (!input->ext.src.port) input->ext.src.port = client_ep.port;
	if (   !ipaddr_defined(input->ext.src.ipaddr)
	    && !(with_template && gateway_list) /* If using a template with gateway, let this unspecified for now. */
	   ) {
		input->ext.src.ipaddr = client_ep.ipaddr;
	}

	if (!input->ext.dst.port) input->ext.dst.port = server_ep.port;
	if (!ipaddr_defined(input->ext.dst.ipaddr)) input->ext.dst.ipaddr = server_ep.ipaddr;

	if (!with_template && !vp_data && input->ext.code == FR_CODE_UNDEFINED) {
		/* Note: in template mode, we do not require a specified message type in the two input items. */
		WARN("No packet type specified in inputs vps or command line, discarding input (id: %u)", input->id);
		return false;
	}
	// TODO: allow to send without a type (BOOTP) ? for that we would need our own encoding function.

	/*
	 *	Pre-allocate the socket for this input item.
	 *	Unless: in template mode *and* with gateway(s) (in which case we already have the sockets allocated).
	 */
	if (!with_template || !gateway_list) {
		dpc_input_socket_allocate(input);
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

	/* Trace what we've read. */
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
static void dpc_input_load_from_fd(TALLOC_CTX *ctx, FILE *file_in, dpc_input_list_t *list, char const *filename)
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
		input->ext.xid = DPC_PACKET_ID_UNASSIGNED;

		if (fr_pair_list_afrom_file(input, &input->vps, file_in, &file_done) < 0) {
			PERROR("Failed to read input items from %s", filename);
			exit(EXIT_FAILURE); /* Be unforgiving. */
			break;
		}
		if (!input->vps) {
			/* Last line might be empty, in this case we will obtain a NULL vps pointer. Silently ignore this. */
			talloc_free(input);
			break;
		}
		fr_strerror(); /* Clear the error buffer */
		/*
		 *	After calling fr_pair_list_afrom_file we get weird things in FreeRADIUS error buffer, e.g.:
		 *	"Invalid character ':' in attribute name".
		 *	This happens apparently when handling an ethernet address (which is a value, not an attribute name).
		 *	Just ignore this.
		*/

		dpc_handle_input(input, list);

		/* Stop reading if we know we won't need it. */
		if (!with_template && session_max_num && list->size >= session_max_num) break;

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
		with_stdin_input = true;

		DEBUG("Reading input from stdin");
		dpc_input_load_from_fd(ctx, stdin, &vps_list_in, "stdin");
	} else {
		DPC_DEBUG_TRACE("Nothing to read on stdin");
	}

	/*
	 *	If an input file is provided, read it.
	 */
	if (file_vps_in && strcmp(file_vps_in, "-") != 0) {
		DEBUG("Reading input from file: %s", file_vps_in);

		file_in = fopen(file_vps_in, "r");
		if (!file_in) {
			ERROR("Error opening %s: %s", file_vps_in, strerror(errno));
			exit(EXIT_FAILURE);
		}

		dpc_input_load_from_fd(ctx, file_in, &vps_list_in, file_vps_in);

		fclose(file_in);
	}

	DEBUG("Done reading input, list size: %d", vps_list_in.size);

	/* Template: keep track of the two input items we'll need. */
	if (with_template) {
		template_invariant = vps_list_in.head;
		template_variable = vps_list_in.tail;

		/* Ensure a message type is provided. */
		if (template_invariant->ext.code == FR_CODE_UNDEFINED) {
			ERROR("No packet type specified in template input vps or command line");
			return -1;
		}

		/* If only one input item provided: this will be the variable list (no invariant). */
		if (vps_list_in.size < 2) template_invariant = NULL;
	}

	return 0;
}

/*
 *	Initialize the pcap raw socket.
 */
#ifdef HAVE_LIBPCAP
static void dpc_pcap_init(TALLOC_CTX *ctx)
{
	char pcap_filter[255];

	pcap = fr_pcap_init(ctx, iface, PCAP_INTERFACE_IN_OUT);
	if (!pcap) {
		PERROR("Failed to initialize pcap");
		exit(EXIT_FAILURE);
	}

	if (fr_pcap_open(pcap) < 0) {
		PERROR("Failed to open pcap interface");
		exit(EXIT_FAILURE);
	}

	sprintf(pcap_filter, "udp");
	/*
	 *	Note: destination of a reply to a broadcast request is not necessarily 255.255.255.255.
	 *	This is the case only if the Broadcast flag is set in the request. See section 4.1 of RFC 2131.
	 */

	if (fr_pcap_apply_filter(pcap, pcap_filter) < 0) {
		PERROR("Failed to apply pcap filter");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Add a raw socket to our list of managed sockets.
	 *	Note: even though we tag it with source port 68 (the DHCP port for clients), we can really
	 *	send using any source port with it (it's a raw socket) if we want to. The DHCP server probably
	 *	won't care, but will send the response using destination port 68.
	 */
	if (dpc_pcap_socket_add(pl, pcap, &client_ep.ipaddr, 68) < 0) {
		exit(EXIT_FAILURE);
	}
}
#endif

/*
 *	Get alternate (fallback) dictionaries directory, relative to the program location.
 *	As follows: <prog dir>/../share/freeradius
 *	<prog dir> is obtained through a "readlink" on /proc/<pid>/exe
 *	Note: this is *not* portable. It works on Linux, but not on all Unixes.
 */
static int dpc_get_alt_dir(void)
{
#ifndef __linux__ /* Don't even try if this is not Linux. */
	DEBUG("Not Linux: won't get program real location");
	return -1;
#else
	char buf[32] = "";
	char prog_path[PATH_MAX + 1] = "";
	char *prog_dir, *up_dir;

	sprintf(buf, "/proc/%d/exe", getpid());
	if (readlink(buf, prog_path, sizeof(prog_path) - 1) == -1) {
		ERROR("Cannot get program execution path from link '%s'", buf);
		return -1;
	}

	prog_dir = dirname(prog_path);
	up_dir = dirname(prog_dir);

	snprintf(alt_dict_dir, PATH_MAX, "%s/share/freeradius", up_dir);
	DEBUG("Using alternate dictionaries dir: %s", alt_dict_dir);
	return 0;
#endif
}

/*
 *	Initialize and load dictionaries.
 */
static void dpc_dict_init(TALLOC_CTX *ctx)
{
	/*
	 *	fr_dict_from_file cannot be called twice (or very bad things happen).
	 *	Probably need to free stuff for that.
	 *	To simplify, first check if the default directory exists before doing anything.
	 */
	char dict_path_freeradius[PATH_MAX + 1] = "";
	sprintf(dict_path_freeradius, "%s/%s", dict_dir, dict_fn_freeradius); // no "access_printf" or something!? damn.
	if (access(dict_path_freeradius, R_OK) < 0) {
		DEBUG("Cannot access dictionary file: %s", dict_path_freeradius);

		/* Get alternate directory (if possible). */
		if (dpc_get_alt_dir() != 0 || access(alt_dict_dir, R_OK) < 0) {
			PERROR("Failed to initialize dictionary: unable to locate dictionary files");
			exit(EXIT_FAILURE);
		}
		dict_dir = alt_dict_dir;
	}

	/*
	 *	Initialize dictionaries.
	 */
	if (fr_dict_global_init(ctx, dict_dir) < 0) {
		PERROR("Failed to initialize dictionary");
		exit(EXIT_FAILURE);
	}

#if 0
// this doesn't work anymore, because DHCP needs "Vendor-Specific" (why !?) which is defined in rfc2865...
// so for now we're using FreeRADIUS default "include all" dictionary. (cf. dhcpclient)
// TODO: fix this.

	/* Read FreeRADIUS internal dictionary first. */
	DEBUG("Including dictionary file: %s/%s", dict_dir, dict_fn_freeradius);
	if (fr_dict_from_file(&dict, dict_fn_freeradius) < 0) {
		PERROR("Failed to initialize dictionary: %s", dict_fn_freeradius);
		exit(EXIT_FAILURE);
	}

	/* Read the DHCP dictionary. */
	DEBUG("Including dictionary file: %s/%s", dict_dir, dict_fn_dhcp);
	if (fr_dict_read(dict, dict_dir, dict_fn_dhcp) != 0) {
		PERROR("Failed to read dictionary: %s", dict_fn_dhcp);
		exit(EXIT_FAILURE);
	}

	/* Read dhcperfcli internal dictionary. */
	DEBUG("Including dictionary file: %s/%s", dict_dir, dict_fn_dhcperfcli);
	if (fr_dict_read(dict, dict_dir, dict_fn_dhcperfcli) != 0) {
		PERROR("Failed to read dictionary: %s", dict_fn_dhcperfcli);
		exit(EXIT_FAILURE);
	}

	/* Preload dictionary attributes that we need. */
	if (fr_dict_attr_autoload(dpc_dict_attr_autoload) < 0) {
		PERROR("Failed to autoload dictionary attributes");
		exit(EXIT_FAILURE);
	}
#endif

	/* Preload dictionaries. */
	if (fr_dict_autoload(dpc_dict_autoload) < 0) {
		PERROR("Failed to autoload dictionaries");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Read dhcperfcli internal dictionary.
	 *	This must be done after fr_dict_autoload, but before fr_dict_attr_autoload.
	 */
	DEBUG("Including dictionary file: %s/%s", dict_dir, dict_fn_dhcperfcli);
	if (fr_dict_read(dict_dhcperfcli, dict_dir, dict_fn_dhcperfcli) != 0) {
		PERROR("Failed to read dictionary: %s", dict_fn_dhcperfcli);
		exit(EXIT_FAILURE);
	}

	/* Preload dictionary attributes that we need. */
	if (fr_dict_attr_autoload(dpc_dict_attr_autoload) < 0) {
		PERROR("Failed to autoload dictionary attributes");
		exit(EXIT_FAILURE);
	}

	/* Also need to load attributes required by DHCP library. */
	if (fr_dhcpv4_init() < 0) {
		PERROR("Failed to initialize DHCP library");
		exit(EXIT_FAILURE);
	}

	fr_strerror(); /* Clear the error buffer */
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
 *	See what kind of request we want to send, or workflow to handle.
 */
static int dpc_command_parse(char const *command)
{
	/* If an integer, assume this is the packet type (1 = discover, ...). */
	if (is_integer(command)) {
		int message = atoi(command);
		if (message > 255) return -1;
		packet_code = atoi(command);
		return 0;
	}

	/* Maybe it's a workflow. */
	workflow_code = fr_str2int(workflow_types, command, DPC_WORKFLOW_NONE);
	if (workflow_code != DPC_WORKFLOW_NONE) return 0;

	/* Or a packet type. */
	packet_code = fr_str2int(request_types, command, -1);
	if (packet_code != -1) return 0;

	/* Nothing goes. */
	return -1;
}

/*
 *	Add a gateway endpoint to the list.
 */
static void dpc_gateway_add(char *addr)
{
	ncc_endpoint_t this = { .port = DHCP_PORT_RELAY };

	if (ncc_host_addr_resolve(addr, &this) != 0) {
		PERROR("Failed to parse gateway address");
		exit(EXIT_FAILURE);
	}

	gateway_num ++;
	gateway_list = talloc_realloc(autofree, gateway_list, ncc_endpoint_t, gateway_num);
	memcpy(&gateway_list[gateway_num - 1], &this, sizeof(this));
}

/*
 *	Parse the gateway parameter.
 */
static void dpc_gateway_parse(char const *param)
{
	if (!param) return;

	char *param_dup = talloc_strdup(autofree, param);
	char *p = strsep(&param_dup, ",");
	while (p) {
		dpc_gateway_add(dpc_str_trim(p)); /* Trim spaces before trying to add this. */
		p = strsep(&param_dup, ",");
	}
}

/*
 *	Process command line options and arguments.
 */
static void dpc_options_parse(int argc, char **argv)
{
	int argval;
	bool debug_fr =  false;

#define ERROR_OPT_VALUE(_l) { \
		ERROR("Invalid value for option -%c (expected: %s)", argval, _l); \
		usage(1); \
	}

	while ((argval = getopt(argc, argv, "a:D:c:f:g:hI:L:N:p:P:r:Rs:t:TvxX"
#ifdef HAVE_LIBPCAP
	       "Ai:"
#endif
	      )) != EOF)
	{
		switch (argval) {
		case 'a':
			if (fr_inet_pton(&allowed_server, optarg, strlen(optarg), AF_INET, false, false) < 0)
				ERROR_OPT_VALUE("ip addr");
			break;

		case 'A':
			multi_offer = true;
			break;

		case 'c':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			input_num_use = atoi(optarg);
			if (input_num_use == 0) input_num_use = 1;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'f':
			file_vps_in = optarg;
			break;

		case 'g':
			dpc_gateway_parse(optarg);
			break;

		case 'h':
			usage(0);
			break;

#ifdef HAVE_LIBPCAP
		case 'i':
			iface = optarg;
			break;
#endif

		case 'I':
			if (!dpc_str_to_uint32(&base_xid, optarg)) ERROR_OPT_VALUE("integer or hex string");
			break;

		case 'L':
			if (!dpc_str_to_float(&duration_max, optarg)) ERROR_OPT_VALUE("floating point number");
			break;

		case 'N':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			session_max_num = atoi(optarg);
			break;

		case 'p':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			session_max_active = atoi(optarg);
			if (session_max_active == 0) session_max_active = 1;
			break;

		case 'P':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			packet_trace_lvl = atoi(optarg);
			break;

		case 'r':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			rate_limit = atoi(optarg);
			break;

		case 'R':
			templ_var = DPC_TEMPL_VAR_RANDOM;
			break;

		case 's':
			if (!dpc_str_to_float(&progress_interval, optarg)) ERROR_OPT_VALUE("floating point number");
			if (progress_interval < 0.1) progress_interval = 0.1; /* Don't allow absurdly low values. */
			else if (progress_interval > 864000) progress_interval = 0; /* Just don't. */
			break;

		case 't':
			if (!dpc_str_to_float(&timeout, optarg)) ERROR_OPT_VALUE("floating point number");
			if (timeout < 0.01) timeout = 0.01; /* Don't allow absurdly low values. */
			else if (timeout > 3600) timeout = 3600;
			break;

		case 'T':
			with_template = true;
			break;

		case 'v':
			version_print();
			exit(EXIT_SUCCESS);

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

	/*
	 *	Resolve server host address and port.
	 */
	if (argc - 1 >= 1 && strcmp(argv[1], "-") != 0) {
		ncc_host_addr_resolve(argv[1], &server_ep);
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (argc - 1 >= 2) {
		if (dpc_command_parse(argv[2]) != 0) {
			ERROR("Unrecognised command \"%s\"", argv[2]);
			usage(1);
		}
	}

	dpc_float_to_timeval(&tv_timeout, timeout);
	dpc_float_to_timeval(&tv_progress_interval, progress_interval);
}

/*
 *	Signal handler.
 */
static void dpc_signal(int sig)
{
	if (!signal_done) {
		/* Allow ongoing sessions to be finished gracefully. */
		INFO("Received signal [%d] (%s): will not start any new session.", sig, strsignal(sig));
		INFO("Send another signal if you wish to terminate immediately.");
		signal_done = true;
		start_sessions_flag = false;
	} else {
		/* ... unless someone's getting really impatient. */
		INFO("Received signal [%d] (%s): Aborting.", sig, strsignal(sig));
		dpc_end();
	}
}

/*
 *	The end.
 */
static void dpc_end(void)
{
	/* Job end timestamp. */
	gettimeofday(&tv_job_end, NULL);

	/* If we're producing progress statistics, do it one last time. */
	if (timerisset(&tv_progress_interval)) dpc_progress_stats_fprint(stdout);

	/* Statistics report. */
	dpc_stats_fprint(stdout);
	dpc_tr_stats_fprint(stdout);

	/* And we're done. */
	exit(EXIT_SUCCESS);
}


/*
 *	The main guy.
 */
int main(int argc, char **argv)
{
	char *p;
	unsigned int i;

	fr_debug_lvl = 0; /* FreeRADIUS libraries debug. */
	dpc_debug_lvl = 0; /* Our own debug. */
	fr_log_fp = stdout; /* Both will go there. */

	autofree = talloc_autofree_context();

	gettimeofday(&tv_start, NULL); /* Program start timestamp. */

	/* Get program name from argv. */
	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		progname = argv[0];
	} else {
		progname = p + 1;
	}

	dpc_options_parse(argc, argv);

	/*
	 *	Mismatch between the binary and the libraries it depends on.
	 */
	DEBUG2("FreeRADIUS magic number: %016lx", RADIUSD_MAGIC_NUMBER);
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		PERROR("Libraries check");
		exit(EXIT_FAILURE);
	}

	dpc_dict_init(autofree);

	dpc_event_list_init(autofree);
	dpc_packet_list_init(autofree);

	/*
	 *	Allocate sockets for gateways.
	 */
	for (i = 0; i < gateway_num; i++) {
		ncc_endpoint_t *this = &gateway_list[i];

		if (dpc_socket_provide(pl, &this->ipaddr, this->port) < 0) {
			char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
			ERROR("Failed to provide a suitable socket for gateway (requested socket src: %s:%u)",
					fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &this->ipaddr), this->port);
			exit(EXIT_FAILURE);
		}
	}

	/*
	 *	And a pcap raw socket (if we need one).
	 */
#ifdef HAVE_LIBPCAP
	if (iface) {
		dpc_pcap_init(autofree);
	}
#endif

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
	if (dpc_input_load(autofree) < 0) {
		exit(EXIT_FAILURE);
	}

	/*
	 *	Ensure we have something to work with.
	 */
	if (vps_list_in.size == 0) {
		if (!with_stdin_input && argc < 2) usage(0); /* If no input nor arguments, show usage. */

		WARN("No valid input loaded, nothing to do");
		exit(0);
	}

	/*
	 *	If packet trace level is unspecified, figure out something automatically.
	 */
	if (packet_trace_lvl == -1) {
		if (session_max_num == 1 || (!with_template && vps_list_in.size == 1 && input_num_use == 1)) {
			/* Only one request: full packet print. */
			packet_trace_lvl = 2;
		} else if (session_max_active == 1) {
			/*
			 *	Several requests, but no parallelism.
			 *	If the number of sessions and the max duration are reasonably small, print packets header.
			 *	Otherwise: no packet print.
			 */
			if (session_max_num > 50 || duration_max > 1.0) {
				packet_trace_lvl = 0;
			} else {
				packet_trace_lvl = 1;
			}
		} else {
			/* Several request in parallel: no packet print. */
			packet_trace_lvl = 0;
		}
		DPC_DEBUG_TRACE("Packet trace level set to: %d", packet_trace_lvl);
	}

#ifdef HAVE_LIBPCAP
	if (iface) {
		/*
		 *	Now that we've opened all the sockets we need, build the pcap filter.
		 */
		dpc_pcap_filter_build(pl, pcap);
	}
#endif

	gettimeofday(&tv_job_start, NULL); /* Job start timestamp. */

	/* Arm a timer to produce periodic statistics. */
	dpc_event_add_progress_stats();

	/* Execute the main processing loop. */
	dpc_main_loop();

	/* This is the end. */
	dpc_end();
}

/*
 *	Print program version.
 */
static void version_print(void)
{
	printf("%s: %s\n", progname, prog_version);
	printf("Built with libpcap: %s\n",
#ifdef HAVE_LIBPCAP
		"yes"
#else
		"no"
#endif
	);
}

/*
 *	Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *fd = status ? stderr : stdout;

	fprintf(fd, "Usage: %s [options] [<server>[:<port>] [<command>]]\n", progname);
	fprintf(fd, "  <server>:<port>  The DHCP server. If omitted, it must be specified in input items.\n");
	fprintf(fd, "  <command>        One of (message type): discover, request, decline, release, inform, lease_query.\n");
	fprintf(fd, "                   (or the message type numeric value: 1 = Discover, 2 = Request, ...).\n");
	fprintf(fd, "                   Or (workflow): dora, doradec (DORA / Decline), dorarel (DORA / Release).\n");
	fprintf(fd, "                   If omitted, message type must be specified in input items.\n");
	fprintf(fd, " Options:\n");
	fprintf(fd, "  -a <ipaddr>      Authorized server. Only allow replies from this server.\n");
#ifdef HAVE_LIBPCAP
	fprintf(fd, "  -A               Wait for multiple Offer replies to a broadcast Discover (requires option -i).\n");
#endif
	fprintf(fd, "  -c <num>         Use each input item <num> times (has no effect in template mode).\n");
	fprintf(fd, "  -D <dictdir>     Set dictionaries directory (defaults to " DICTDIR ").\n");
	fprintf(fd, "  -f <file>        Read input items from <file>, in addition to stdin.\n");
	fprintf(fd, "  -g <gw>[:port]   Handle sent packets as if relayed through giaddr <gw> (hops: 1, src: giaddr:port).\n");
	fprintf(fd, "                   A comma-separated list may be specified, in which case packets will be sent using all\n");
	fprintf(fd, "                   of those gateways in a round-robin fashion.\n");
	fprintf(fd, "  -h               Print this help message.\n");
#ifdef HAVE_LIBPCAP
	fprintf(fd, "  -i <interface>   Use this interface for unconfigured clients to broadcast through a raw socket.\n");
#endif
	fprintf(fd, "  -I <num>         Start generating xid values with <num>.\n");
	fprintf(fd, "  -L <seconds>     Limit duration (beyond which no new session will be started).\n");
	fprintf(fd, "  -N <num>         Start at most <num> sessions (in template mode: generate <num> sessions).\n");
	fprintf(fd, "  -p <num>         Send up to <num> session packets in parallel.\n");
	fprintf(fd, "  -P <num>         Packet trace level (0: none, 1: header, 2: and attributes, 3: and hex data).\n");
	fprintf(fd, "  -r <num>         Rate limit (transaction replies /s)\n");
	fprintf(fd, "  -R               Randomize template variable values (instead of increment).\n");
	fprintf(fd, "  -s <seconds>     Periodically report progress statistics information.\n");
	fprintf(fd, "  -t <timeout>     Wait at most <timeout> seconds for a reply (may be a floating point number).\n");
	fprintf(fd, "  -T               Template mode. Sessions input is generated from invariant and variable input items.\n");
	fprintf(fd, "  -v               Print version information.\n");
	fprintf(fd, "  -x               Turn on additional debugging. (-xx gives more debugging).\n");
	fprintf(fd, "  -X               Turn on FreeRADIUS libraries debugging (use this in conjunction with -x).\n");

	exit(status);
}
