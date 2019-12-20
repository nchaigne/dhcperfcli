/**
 * @file dpc_packet_list.c
 * @brief Functions to deal with outgoing lists / sets of DHCP packets.
 *
 * Similar to protocols/radius/list.c but adapted for handling DHCP.
 */

#include "dhcperfcli.h"
#include "dpc_packet_list.h"
#include "dpc_util.h"


/* We need as many sockets as source IP / port. In most cases, only one will be used. */
#define DPC_MAX_SOCKETS         32  // Is this enough ?
#define DPC_ID_ALLOC_MAX_TRIES  32


/*
 *	Keep track of the socket(s) (along with source and destination IP/port)
 *	associated to the packet list.
 *	(ref: structure fr_packet_socket_t from protocols/radius/list.c)
 *
 *	Note: we do not keep track of used ID's.
 */
typedef struct dpc_packet_socket {
	int sockfd;

	uint32_t num_outgoing;  //!< Number of packets to which a reply is expected on this socket.

	int src_any;
	fr_ipaddr_t src_ipaddr;
	uint16_t src_port;

#ifdef HAVE_LIBPCAP
	fr_pcap_t *pcap;
#endif

} dpc_packet_socket_t;

/*
 *	Note on sockets:
 *
 *	If we're using a socket bound to source 0.0.0.0 (INADDR_ANY) to send a packet, the system
 *	will pick an appropriate source IP address for our packet. We *cannot* know which it is.
 *
 *	If we bind a socket with source 0.0.0.0, we cannot use another socket with a source IP address
 *	(for the same source port).
 *
 *	Conversely, if we first bind a socket with a source IP address, we cannot later bind another
 *	socket with 0.0.0.0. It would fail with "Bind failed: EADDRINUSE: Address already in use".
 */


/*
 *	Structure defining a list of DHCP packets (incoming or outgoing)
 *	that should be managed.
 *	(ref: structure dpc_packet_list_t from protocols/radius/list.c)
 */
typedef struct dpc_packet_list {
	rbtree_t *tree;

	uint32_t num_outgoing;  //!< Number of packets to which a reply is currently expected.
	int last_recv;          //!< On which socket did we last receive a packet.
	int num_sockets;        //!< Number of managed sockets.

	dpc_packet_socket_t sockets[DPC_MAX_SOCKETS];

	uint32_t prev_id;       //!< Previously allocated xid. Allows to allocate xid's in a linear fashion.
} dpc_packet_list_t;


/*
 *	Check if two packets are identical from the packet list perspective.
 *	(ref: function fr_packet_cmp from protocols/radius/list.c)
 */
static int dpc_packet_cmp(DHCP_PACKET const *a, DHCP_PACKET const *b)
{
	int rcode = 0;

	DEBUG3("id: (%u <-> %u), sockfd: (%d <-> %d), src_port: (%d <-> %d), dst_port: (%d <-> %d)",
	       a->id, b->id, a->sockfd, b->sockfd, a->src_port, b->src_port, a->dst_port, b->dst_port);

	if (a->id < b->id) return -1;
	if (a->id > b->id) return +1;

	/*
	 *	Do *not* compare chaddr. They do not necessarily match.
	 *	E.g. a Lease-Query where the query type is not "by MAC address" (cf. RFC 4388 and 6148)
	 */
	//if (a->data && b->data && a->data_len >= 34 && b->data_len >= 34) {
	//	rcode = memcmp(a->data + 28, b->data + 28, 6);
	//	if (rcode != 0) return rcode;
	//}

	if (a->sockfd < b->sockfd) return -1;
	if (a->sockfd > b->sockfd) return +1;

	if (a->src_port && b->src_port) { /* Only compare source port if <> 0. */
		rcode = (int) a->src_port - (int) b->src_port;
		if (rcode != 0) return rcode;
	}

	rcode = fr_ipaddr_cmp(&a->src_ipaddr, &b->src_ipaddr);
	if (rcode != 0) return rcode;

	rcode = fr_ipaddr_cmp(&a->dst_ipaddr, &b->dst_ipaddr);
	if (rcode != 0) return rcode;

	rcode = (int) a->dst_port - (int) b->dst_port;
	return rcode;
}

/*
 *	From a given socket FD, retrieve the corresponding element of the socket array
 *	associated to the packet list.
 *	(ref: function fr_socket_find from protocols/radius/list.c)
 */
static dpc_packet_socket_t *dpc_socket_find(dpc_packet_list_t *pl, int sockfd)
{
	int i;
	for (i = 0; i < pl->num_sockets; i++) {
		if (pl->sockets[i].sockfd == sockfd) return &pl->sockets[i];
	}

	return NULL; /* Socket not found. */
}

/*
 *	Add a socket to our list of managed sockets.
 */
static dpc_packet_socket_t *dpc_socket_add(dpc_packet_list_t *pl, int sockfd, fr_ipaddr_t *src_ipaddr, uint16_t src_port)
{
	dpc_packet_socket_t *ps;

	if (pl->num_sockets >= DPC_MAX_SOCKETS) {
		fr_strerror_printf("Too many open sockets");
		return NULL;
	}

	ps = &pl->sockets[pl->num_sockets];
	if (ps->sockfd != -1) {
		fr_strerror_printf("Socket already allocated"); /* This should never happen. */
		return NULL;
	}

	/*
	 *	Fill in the packet list socket.
	 */
	memset(ps, 0, sizeof(*ps));

	ps->src_ipaddr = *src_ipaddr;
	ps->src_port = src_port;
	ps->sockfd = sockfd;

	pl->num_sockets ++;

	if (dpc_debug_lvl > 0) {
		char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
		DEBUG2("Adding new managed socket to packet list: fd: %d, src: %s:%i",
		       sockfd, fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), src_ipaddr), src_port);
	}

	DEBUG3("Now managing %d socket(s)", pl->num_sockets);

	return ps;
}

#ifdef HAVE_LIBPCAP
/*
 *	Build the pcap filter.
 *	Do not capture packets sent from or to an IP address to which we have an UDP socket bound.
 */
void dpc_pcap_filter_build(dpc_packet_list_t *pl, fr_pcap_t *pcap)
{
	int i;
	dpc_packet_socket_t *ps;
	char ipaddr_buf[FR_IPADDR_STRLEN] = "";
	char pcap_filter[4096] = ""; // TODO: size this dynamically
	size_t len = 0;
	char *p = &pcap_filter[0];

	len = sprintf(p, "udp");
	p += len;

	if (pl->num_sockets > 0) {
		for (i = 0; i<pl->num_sockets; i++) {
			ps = &pl->sockets[i];

			if (i == 0) {
				len = sprintf(p, " and host not (");
				p += len;
			} else {
				len = sprintf(p, " or ");
				p += len;
			}

			len = sprintf(p, "%s", fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf), &ps->src_ipaddr));
			p += len;
		}
		len = sprintf(p, ")");
		p += len;
	}
	DEBUG("Applying pcap filter: %s", pcap_filter);

	if (fr_pcap_apply_filter(pcap, pcap_filter) < 0) {
		PERROR("Failing to apply pcap filter");
		exit(EXIT_FAILURE);
	}
}

/*
 *	Add a pcap socket.
 */
int dpc_pcap_socket_add(dpc_packet_list_t *pl, fr_pcap_t *pcap, fr_ipaddr_t *src_ipaddr, uint16_t src_port)
{
	dpc_packet_socket_t *ps;

	ps = dpc_socket_add(pl, pcap->fd, src_ipaddr, src_port);
	if (!ps) return -1;

	ps->pcap = pcap; /* Remember this is a pcap socket. */
	return 0;
}
#endif

/*
 *	Provide a suitable socket from our list. If necesary, initialize a new one.
 */
int dpc_socket_provide(dpc_packet_list_t *pl, fr_ipaddr_t *src_ipaddr, uint16_t src_port)
{
	int i;
	dpc_packet_socket_t *ps;

	FN_ARG_CHECK(-1, pl);
	FN_ARG_CHECK(-1, src_ipaddr);
	FN_ARG_CHECK(-1, src_ipaddr->af != AF_UNSPEC);

	for (i = 0; i<pl->num_sockets; i++) {
		ps = &pl->sockets[i];

		if (ps->src_port == src_port && (fr_ipaddr_cmp(&ps->src_ipaddr, src_ipaddr) == 0)) {
			DEBUG3("Found suitable managed socket, fd: %d", ps->sockfd);
			return ps->sockfd;
		}
	}

	/* No socket found, we need a new one. */
	DEBUG3("No suitable managed socket found, need a new one...");

	/* Open a connectionless UDP socket for sending and receiving. */
	int sockfd = fr_socket_server_udp(src_ipaddr, &src_port, NULL, false);
	if (sockfd < 0) {
		fr_strerror_printf("Error opening socket: %s", fr_strerror());
		return -1;
	}

	if (fr_socket_bind(sockfd, src_ipaddr, &src_port, NULL) < 0) {
		fr_strerror_printf("Error binding socket: %s", fr_strerror());
		return -1;
	}

	/* Allow to use this socket to broadcast. */
	int on = 1;
	if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
		fr_strerror_printf("Can't set broadcast option: %s", fr_syserror(errno));
		return -1;
	}

	/* Add the socket to our list of managed sockets. */
	if (!dpc_socket_add(pl, sockfd, src_ipaddr, src_port)) {
		return -1;
	}
	return sockfd;
}

/*
 *	Find out if two packet entries are "identical", i.e. same
 *	packet id, socket, src port, src ip, dst ip, dst port.
 */
static int dpc_packet_entry_cmp(void const *one, void const *two)
{
	DHCP_PACKET const * const *a = one;
	DHCP_PACKET const * const *b = two;

	return dpc_packet_cmp(*a, *b);
}

/*
 *	Free the DHCP packet list.
 *	(ref: function fr_packet_list_free from protocols/radius/list.c)
 */
void dpc_packet_list_free(dpc_packet_list_t *pl)
{
	if (!pl) return;

	talloc_free(pl->tree);
	talloc_free(pl);
}

/*
 *	Create the DHCP packet list.
 *	Caller is responsible for managing the packet entries.
 *	(ref: function fr_packet_list_create from protocols/radius/list.c)
 */
dpc_packet_list_t *dpc_packet_list_create(TALLOC_CTX *ctx, uint32_t base_id)
{
	int i;
	dpc_packet_list_t *pl;

	pl = talloc_zero(ctx, dpc_packet_list_t);
	if (!pl) return NULL;

	pl->tree = rbtree_create(pl, dpc_packet_entry_cmp, NULL, 0);
	if (!pl->tree) {
		dpc_packet_list_free(pl);
		return NULL;
	}

	for (i = 0; i < DPC_MAX_SOCKETS; i++) {
		pl->sockets[i].sockfd = -1;
	}

	/* Initialize "previously allocated xid", which is used to allocate xid's in a linear fashion. */
	pl->prev_id = base_id - 1;

	return pl;
}

/*
 *	Insert an element in the packet list.
 *	Caller is responsible for allocating an ID before calling this.
 *	Or at least trying to: if the provided ID is already allocated, this will return false.
 *	(ref: function fr_packet_list_insert from protocols/radius/list.c)
 */
bool dpc_packet_list_insert(dpc_packet_list_t *pl, DHCP_PACKET **request_p)
{
	ncc_assert(pl != NULL);
	ncc_assert(request_p != NULL);
	ncc_assert(*request_p != NULL);

	bool r = rbtree_insert(pl->tree, request_p);
	if (r) {
		char from_to_buf[DPC_FROM_TO_STRLEN] = "";
		DEBUG3("Inserted packet: fd: %d, id: %u, %s", (*request_p)->sockfd, (*request_p)->id,
		       dpc_packet_from_to_sprint(from_to_buf, *request_p, true));
	}

	return r;
}

/*
 *	For the reply packet we've received, look for the corresponding DHCP request
 *	from the packet list.
 *	(ref: function fr_packet_list_find_byreply from protocols/radius/list.c)
 */
DHCP_PACKET **dpc_packet_list_find_byreply(dpc_packet_list_t *pl, DHCP_PACKET *reply)
{
	DHCP_PACKET my_request = { 0 }, *request = NULL;
	dpc_packet_socket_t *ps;

	ncc_assert(pl != NULL);
	ncc_assert(reply != NULL);

	ps = dpc_socket_find(pl, reply->sockfd);
	if (!ps) {
		ERROR("Failed to find socket in packet list, fd: %d", reply->sockfd);
		return NULL;
	}

	/*
	 *	Initialize request from reply, AND from the source IP & port of this socket.
	 *	The client may have bound the socket to 0, in which case it's some random port,
	 *	that is NOT in the original request->src_port.
	 */
	my_request.sockfd = reply->sockfd;
	my_request.id = reply->id;

	if (ps->src_any) {
		my_request.src_ipaddr = ps->src_ipaddr;
	} else {
		my_request.src_ipaddr = reply->dst_ipaddr;
	}
	my_request.src_port = ps->src_port;

	my_request.dst_ipaddr = reply->src_ipaddr;
	my_request.dst_port = reply->src_port;

	/* Allow chaddr to be accessible. */
	my_request.data = reply->data;
	my_request.data_len = reply->data_len;

	/*
	 *	If we've received this on the raw socket, this has to be handled specifically, e.g.:
	 *	The packet we've sent : src = 0.0.0.0:68 -> dst = 255.255.255.255:67
	 *	The reply we get : src = <DHCP server>:67 -> dst = 255.255.255.255:68
	 */
#ifdef HAVE_LIBPCAP
	if (ps->pcap) {
		DEBUG3("Reply received through raw socket: looking for broadcast packet.");
		my_request.src_ipaddr.addr.v4.s_addr = htonl(INADDR_ANY);
		my_request.dst_ipaddr.addr.v4.s_addr = htonl(INADDR_BROADCAST);
		my_request.src_port = 0; /* Match all. This allows to handle multiple source ports with a single pcap socket. */
	}
#endif

	request = &my_request;

	char from_to_buf[DPC_FROM_TO_STRLEN] = "";
	DEBUG3("Searching for packet: fd: %d, id: %u, %s", request->sockfd, request->id,
	       dpc_packet_from_to_sprint(from_to_buf, request, true));

	return rbtree_finddata(pl->tree, &request);
}

/*
 *	Remove an element from the packet list.
 *	Note: contrary to RADIUS we don't keep track of allocated ID's per socket.
 *	Caller is responsible to ensure he won't use again the ID previously allocated.
 *	(ref: function fr_packet_list_yank from protocols/radius/list.c)
 */
bool dpc_packet_list_yank(dpc_packet_list_t *pl, DHCP_PACKET *request)
{
	rbnode_t *node;

	ncc_assert(pl != NULL);
	ncc_assert(request != NULL);

	node = rbtree_find(pl->tree, &request);
	if (!node) return false;

	rbtree_delete(pl->tree, node);
	return true;
}

/*
 *	Get the number of elements in the packet list.
 *	(ref: function fr_packet_list_num_elements from protocols/radius/list.c)
 */
uint32_t dpc_packet_list_num_elements(dpc_packet_list_t *pl)
{
	if (!pl) return 0;

	return rbtree_num_elements(pl->tree);
}

/*
 *	Given an initialized DHCP packet, find a suitable UDP socket, and allocate an ID
 *	not yet used for that socket in the packet list.
 *	(ref: function fr_packet_list_id_alloc from protocols/radius/list.c)
 *
 *	Note: the allocation mechanism for DHCP is different from that of RADIUS. We don't keep
 *	track of used ID stored in the socket structure (that would be impossible since we have
 *	2^32-1 possible ID's for DHCP), instead we allocate xid's in a linear fashion (unless told
 *	otherwise) so we're almost certain to get an ID easily.
 *	If caller wants a specific ID, we try to comply, and if it's not available we fall back to
 *	the linear allocation mechanism.
 */
bool dpc_packet_list_id_alloc(dpc_packet_list_t *pl, int sockfd, DHCP_PACKET **request_p)
{
	int id;
	dpc_packet_socket_t *ps;
	DHCP_PACKET *request;
	int tries = 0;

	ncc_assert(pl != NULL);
	ncc_assert(request_p != NULL);
	ncc_assert(*request_p != NULL);

	request = *request_p;

	/*
	 *	Find the socket.
	 */
	ps = dpc_socket_find(pl, sockfd);
	if (ps == NULL) {
		fr_strerror_printf("Failed to find socket allocated with fd: %d", sockfd);
		return false;
	}
	DEBUG3("Socket retrieved (fd: %d), now trying to get an id", sockfd);

	/*
	 *	Set the ID, source IP, and source port.
	 */
	request->sockfd = ps->sockfd;
	request->src_ipaddr = ps->src_ipaddr;
	//request->src_port = ps->src_port; /* Keep source port set by requestor. */

	if (request->id == DPC_PACKET_ID_UNASSIGNED) {
		id = ++ pl->prev_id;
		request->id = id;
	} else {
		 /* First try with the id they want. */
		id = request->id;
	}

	/*
	 *	Loop trying to allocate an unused ID into the packet list, but not forever.
	 *	We arbitrary limit the iteration count.
	 */
	while (tries < DPC_ID_ALLOC_MAX_TRIES) {

		/*
		 *	Make sure we never allocate the reserved ID which means "unassigned".
		 */
		if (id != DPC_PACKET_ID_UNASSIGNED) {
			/*
			 *	Try to insert into the packet list. If successful, it means the ID was available.
			*/
			if (dpc_packet_list_insert(pl, request_p)) {
				DEBUG3("Successful insert into packet list (allocated xid: %d)", request->id);
				ps->num_outgoing ++;
				pl->num_outgoing ++;
				return true;
			}
		}

		/* Otherwise, try another ID. */
		tries ++;
		id = ++ pl->prev_id;
		request->id = id;
	}

	DEBUG3("Giving up after %d tries, last xid tried: %d", tries, pl->prev_id);

	/*
	 *	We failed to allocate an ID. Reset information in the packet before returning.
	 */
	request->id = DPC_PACKET_ID_UNASSIGNED;
	request->sockfd = -1;
	request->src_ipaddr.af = AF_UNSPEC;
	request->src_port = 0;

	return false;
}

/*
 *	Free the ID previously allocated to a given packet, and remove the packet from
 *	the packet list.
 *	(ref: function fr_packet_list_id_free from protocols/radius/list.c)
 */
bool dpc_packet_list_id_free(dpc_packet_list_t *pl, DHCP_PACKET *request)
{
	dpc_packet_socket_t *ps;

	ncc_assert(pl != NULL);
	ncc_assert(request != NULL);

	if (!dpc_packet_list_yank(pl, request)) return false;

	ps = dpc_socket_find(pl, request->sockfd);
	if (!ps) return false;

	ps->num_outgoing --;
	pl->num_outgoing --;

	request->id = DPC_PACKET_ID_UNASSIGNED;
	request->sockfd = -1;
	request->src_ipaddr.af = AF_UNSPEC;
	request->src_port = 0;

	return true;
}

/*
 *	Loop over the list of sockets tied to the packet list. Prepare each socket
 *	for reception, calling FD_SET to update a fd_set structure.
 *	Return the highest-numbered fd of these sockets + 1.
 *	(ref: function fr_packet_list_fd_set from protocols/radius/list.c)
 */
int dpc_packet_list_fd_set(dpc_packet_list_t *pl, fd_set *set)
{
	int i, maxfd;

	ncc_assert(pl != NULL);
	ncc_assert(set != NULL);

	maxfd = -1;

	FD_ZERO(set); /* Clear the FD set. */

	for (i = 0; i < DPC_MAX_SOCKETS; i++) {
		if (pl->sockets[i].sockfd == -1) continue;
		FD_SET(pl->sockets[i].sockfd, set); /* Add the socket fd to the set. */
		if (pl->sockets[i].sockfd > maxfd) {
			maxfd = pl->sockets[i].sockfd;
		}
	}

	if (maxfd < 0) return -1;

	return maxfd + 1;
}

/*
 *	The FD set is ready for reading.
 *	Loop over the list of sockets tied to the packet list.
 *	Receive the first incoming packet found.
 *	(ref: function fr_packet_list_recv from protocols/radius/list.c)
 */
DHCP_PACKET *dpc_packet_list_recv(dpc_packet_list_t *pl, fd_set *set)
{
	int start;
	DHCP_PACKET *packet;
	dpc_packet_socket_t *ps;

	ncc_assert(pl != NULL);
	ncc_assert(set != NULL);

	start = pl->last_recv;
	do {
		start = (start + 1) % DPC_MAX_SOCKETS;
		ps = &pl->sockets[start];

		if (ps->sockfd == -1) continue;

		if (!FD_ISSET(ps->sockfd, set)) continue;

		/* Using either udp or pcap socket for reception. */
#ifdef HAVE_LIBPCAP
		if (ps->pcap) {
			packet = fr_dhcpv4_pcap_recv(ps->pcap);
			if (packet) packet->sockfd = ps->pcap->fd; /* fr_dhcpv4_pcap_recv does not fill this. Why!? */
		} else
#endif
		{
			packet = fr_dhcpv4_udp_packet_recv(ps->sockfd);
		}
		if (!packet) continue;

		/*
		 *	We've received a packet, but are not guaranteed this was an expected reply.
		 *	Call fr_packet_list_find_byreply(). If it doesn't find anything, discard the reply.
		 */
		DEBUG3("Received packet on socket fd: %d (index in array: %d)", ps->sockfd, start);

		pl->last_recv = start;
		return packet;

	} while (start != pl->last_recv);

	return NULL;
}
