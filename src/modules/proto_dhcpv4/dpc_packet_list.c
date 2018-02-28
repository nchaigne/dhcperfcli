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
#define DPC_ID_ALLOC_MAX_TRIES  100

/*
 *	TODO: once this works, implement something better.
 */


/*
 *	Keep track of the socket(s) (along with source and destination IP/port)
 *	associated to the packet list.
 *	(ref: structure fr_packet_socket_t from protocols/radius/list.c)
 *
 *	Note: we do not keep track of used ID's.
 */
typedef struct dpc_packet_socket {
// TODO: clean this up. We don't need destination, maybe not ctx...
	int sockfd;
	void *ctx;

	uint32_t num_outgoing;

	int src_any;
	fr_ipaddr_t src_ipaddr;
	uint16_t src_port;

	int dst_any;
	fr_ipaddr_t dst_ipaddr;
	uint16_t dst_port;

	bool dont_use; // TODO: remove. We probably don't need this.

} dpc_packet_socket_t;

/*
 *	Structure defining a list of DHCP packets (incoming or outgoing)
 *	that should be managed.
 *	(ref: structure dpc_packet_list_t from protocols/radius/list.c)
 *
 *	Notes:
 *	- although we only need one socket here, we manage an array as is done for RADIUS.
 *	- alloc_id is not used by FreeRADIUS.
 *	- prev_id is a new field added to keep track of xid's allocated in a linear fashion.
 */
typedef struct dpc_packet_list {
	rbtree_t *tree;

	//int alloc_id;
	uint32_t num_outgoing;
	int last_recv;
	int num_sockets;

	dpc_packet_socket_t sockets[DPC_MAX_SOCKETS];

	uint32_t prev_id; // useful for DHCP, to allocate xid's in a linear fashion.
} dpc_packet_list_t;


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
 *	Provide a suitable socket from our list. If necesary, initialize a new one.
 */
int dpc_socket_provide(dpc_packet_list_t *pl, fr_ipaddr_t *src_ipaddr, uint16_t src_port)
{
	int i;
	dpc_packet_socket_t *ps;

	if (!pl || !src_ipaddr || (src_ipaddr->af == AF_UNSPEC)) {
		fr_strerror_printf("Invalid argument");
		return -1;
	}

	for (i = 0; i<pl->num_sockets; i++) {
		ps = &pl->sockets[i];

		if (ps->src_port == src_port && (fr_ipaddr_cmp(&ps->src_ipaddr, src_ipaddr) == 0)) {
			DPC_DEBUG_TRACE("Found suitable managed socket, fd: %d", ps->sockfd);
			return ps->sockfd;
		}
	}
	DPC_DEBUG_TRACE("No suitable managed socket found, need a new one...");

	/* No socket found, we need a new one. */
	if (pl->num_sockets >= DPC_MAX_SOCKETS) {
		fr_strerror_printf("Too many open sockets");
		return -1;
	}

	ps = &pl->sockets[pl->num_sockets];
	if (ps->sockfd != -1) {
		fr_strerror_printf("Socket already allocated"); /* This should never happen. */
		return -1;
	}

	/* Open a connectionless UDP socket for sending and receiving. */
	int my_sockfd = fr_socket_server_udp(src_ipaddr, &src_port, NULL, false);
	if (my_sockfd < 0) {
		ERROR("Error opening socket: %s", fr_strerror());
		return -1;
	}

	if (fr_socket_bind(my_sockfd, src_ipaddr, &src_port, NULL) < 0) {
		ERROR("Error binding socket: %s", fr_strerror());
		return -1;
	}

	memset(ps, 0, sizeof(*ps));

	ps->src_ipaddr = *src_ipaddr;
	ps->src_port = src_port;

	/*
	 *	As the last step before returning.
	 */
	ps->sockfd = my_sockfd;
	pl->num_sockets ++;

	if (dpc_debug_lvl > 0) {
		dpc_socket_inspect(fr_log_fp, "Adding new managed socket to packet list:", my_sockfd, NULL, NULL, NULL, NULL);
	}

	DPC_DEBUG_TRACE("Now managing %d socket(s)", pl->num_sockets);

	return my_sockfd;
}

/*
 *	TODO: this is ugly...
 *	(ref: function fr_packet_list_socket_add from protocols/radius/list.c)
 */
bool dpc_packet_list_socket_add(dpc_packet_list_t *pl, int sockfd,
                                fr_ipaddr_t *dst_ipaddr, uint16_t dst_port, void *ctx)
{
	struct sockaddr_storage src;
	socklen_t sizeof_src;
	dpc_packet_socket_t *ps;

	if (!pl || !dst_ipaddr || (dst_ipaddr->af == AF_UNSPEC)) {
		fr_strerror_printf("Invalid argument");
		return false;
	}

	if (pl->num_sockets >= DPC_MAX_SOCKETS) {
		fr_strerror_printf("Too many open sockets");
		return false;
	}

	/*
	 *	Just add it at the end. We don't need to ever remove sockets.
	 */
	ps = &pl->sockets[pl->num_sockets];
	if (ps->sockfd != -1) {
		fr_strerror_printf("Socket already allocated"); /* This should never happen. */
		return false;
	}

	memset(ps, 0, sizeof(*ps));
	ps->ctx = ctx;

	/*
	 *	Get address family, etc. first, so we know if we need to do udpfromto.
	 *
	 *	FIXME: udpfromto also does this, but it's not a critical problem.
	 */
	sizeof_src = sizeof(src);
	memset(&src, 0, sizeof_src);
	if (getsockname(sockfd, (struct sockaddr *) &src, &sizeof_src) < 0) {
		fr_strerror_printf("%s", fr_syserror(errno));
		return false;
	}

	if (fr_ipaddr_from_sockaddr(&src, sizeof_src, &ps->src_ipaddr, &ps->src_port) < 0) {
		fr_strerror_printf("Failed to get IP");
		return false;
	}

	ps->dst_ipaddr = *dst_ipaddr;
	ps->dst_port = dst_port;

	ps->src_any = fr_ipaddr_is_inaddr_any(&ps->src_ipaddr);
	if (ps->src_any < 0) return false;

	ps->dst_any = fr_ipaddr_is_inaddr_any(&ps->dst_ipaddr);
	if (ps->dst_any < 0) return false;

	/*
	 *	As the last step before returning.
	 */
	ps->sockfd = sockfd;
	pl->num_sockets ++;

	return true;
}

/*
 *	Find out if two packet entries are "identical" as compared by fr_packet_cmp:
 *	packet id, socket, src port, src ip, dst ip, dst port.
 */
static int dpc_packet_entry_cmp(void const *one, void const *two)
{
	RADIUS_PACKET const * const *a = one;
	RADIUS_PACKET const * const *b = two;

	return fr_packet_cmp(*a, *b); // use comparison function from list.c, this is good enough.
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
dpc_packet_list_t *dpc_packet_list_create(uint32_t base_id)
{
	int i;
	dpc_packet_list_t *pl;

	pl = malloc(sizeof(*pl)); // TODO: talloc this.
	if (!pl) return NULL;
	memset(pl, 0, sizeof(*pl));

	pl->tree = rbtree_create(NULL, dpc_packet_entry_cmp, NULL, 0);
	if (!pl->tree) {
		dpc_packet_list_free(pl);
		return NULL;
	}

	for (i = 0; i < DPC_MAX_SOCKETS; i++) {
		pl->sockets[i].sockfd = -1;
	}

	/* Initialize "previously allocated xid", which is used to allocate xid's in a linear fashion. */
	pl->prev_id = base_id;

	return pl;
}

/*
 *	Insert an element in the packet list.
 *	Caller is responsible for allocating an ID before calling this.
 *	Or at least trying to: if the provided ID is already allocated, this will return false.
 *	(ref: function fr_packet_list_insert from protocols/radius/list.c)
 */
bool dpc_packet_list_insert(dpc_packet_list_t *pl, RADIUS_PACKET **request_p)
{
	if (!pl || !request_p || !*request_p) return false;

	return rbtree_insert(pl->tree, request_p);
}

/*
 *	For the reply packet we've received, look for the corresponding DHCP request
 *	from the packet list.
 *	(ref: function fr_packet_list_find_byreply from protocols/radius/list.c)
 */
RADIUS_PACKET **dpc_packet_list_find_byreply(dpc_packet_list_t *pl, RADIUS_PACKET *reply)
{
	RADIUS_PACKET my_request, *request;
	dpc_packet_socket_t *ps;

	if (!pl || !reply) return NULL;

	ps = dpc_socket_find(pl, reply->sockfd);
	if (!ps) return NULL;

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

	request = &my_request;

	return rbtree_finddata(pl->tree, &request);
}

/*
 *	Remove an element from the packet list.
 *	Note: contrary to RADIUS we don't keep track of allocated ID's per socket.
 *	Caller is responsible to ensure he won't use again the ID previously allocated.
 *	(ref: function fr_packet_list_yank from protocols/radius/list.c)
 */
bool dpc_packet_list_yank(dpc_packet_list_t *pl, RADIUS_PACKET *request)
{
	rbnode_t *node;

	if (!pl || !request) return false;

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
bool dpc_packet_list_id_alloc(dpc_packet_list_t *pl, RADIUS_PACKET **request_p, void **pctx)
{
	if (!pl || !request_p) return false;

	int i, fd, id;
	int src_any = 0;
	dpc_packet_socket_t *ps = NULL;
	RADIUS_PACKET *request = *request_p;
	int tries = 0;

	if ((request->dst_ipaddr.af == AF_UNSPEC) ||
	    (request->dst_port == 0)) {
		fr_strerror_printf("No destination address/port specified");
		return false;
	}

	/*
	 *	Special case: unspec == "don't care"
	 */
	if (request->src_ipaddr.af == AF_UNSPEC) {
		memset(&request->src_ipaddr, 0, sizeof(request->src_ipaddr));
		request->src_ipaddr.af = request->dst_ipaddr.af;
	}

	src_any = fr_ipaddr_is_inaddr_any(&request->src_ipaddr);
	if (src_any < 0) {
		fr_strerror_printf("Can't check src_ipaddr");
		return false;
	}

	/*
	 *	MUST specify a destination address.
	 */
	if (fr_ipaddr_is_inaddr_any(&request->dst_ipaddr) != 0) {
		fr_strerror_printf("Must specify a dst_ipaddr");
		return false;
	}

	/*
	 *	Warning: id in RADIUS_PACKET is of type "int".
	 *	For DHCP the xid is a number ranging from 0 to 2^32-1.
	 *	But we need a way to keep track of packets initialized but with no assigned id yet.
	 *	So We will consider the "id" as if unsigned, and special value -1 will mean "unassigned"
	 *	(Even though 0xffffffff is normally a valid xid value for DHCP. We can live with this.)
	 */
	fd = -1;

	/*
	 *	Note: the search randomization mechanism from fr_packet_list_id_alloc is not useful here
	 *	for DHCP, so we'll just get rid of it.
	 */
	for (i = 0; i < DPC_MAX_SOCKETS; i++) {
		if (pl->sockets[i].sockfd == -1) continue; /* paranoia */

		ps = &(pl->sockets[i]);

		/*
		 *	This socket is marked as "don't use for new packets". But we can still receive packets
		 *	that are outstanding.
		 */
		if (ps->dont_use) continue;

		/*
		 *	Address families don't match, skip it.
		 */
		if (ps->src_ipaddr.af != request->dst_ipaddr.af) continue;

		/*
		 *	MUST match dst port, if we have one.
		 */
		if ((ps->dst_port != 0) &&
		    (ps->dst_port != request->dst_port)) continue;

		/*
		 *	MUST match requested src port, if one has been given.
		 */
		if ((request->src_port != 0) &&
		    (ps->src_port != request->src_port)) continue;

		/*
		 *	We're sourcing from *, and they asked for a specific source address: ignore it.
		 */
		if (ps->src_any && !src_any) continue;

		/*
		 *	We're sourcing from a specific IP, and they asked for a source IP that isn't us: ignore it.
		 */
		if (!ps->src_any && !src_any &&
		    (fr_ipaddr_cmp(&request->src_ipaddr,
				   &ps->src_ipaddr) != 0)) continue;

		/*
		 *	UDP sockets are allowed to match destination IPs exactly, OR a socket with destination * is allowed
		 *	to match any requested destination.
		 */
		if (!ps->dst_any &&
		    (fr_ipaddr_cmp(&request->dst_ipaddr,
				   &ps->dst_ipaddr) != 0)) continue;

		/*
		 *	Otherwise, this socket is OK to use.
		 */

		/* The DHCP way: use this fd, then try and allocate an unused ID. */
		fd = i;
		break;
	}

	/*
	 *	Ask the caller to allocate a new socket.
	 */
	if (fd < 0) {
		fr_strerror_printf("Failed finding socket, caller must allocate a new one");
		return false;
	}

	/*
	 *	Set the ID, source IP, and source port.
	 */
	request->sockfd = ps->sockfd;
	request->src_ipaddr = ps->src_ipaddr;
	request->src_port = ps->src_port;

	id = DPC_PACKET_ID_UNASSIGNED;
	if (request->id == DPC_PACKET_ID_UNASSIGNED) { /* If not, first try with the id they want. */
		id = ++ pl->prev_id;
		request->id = id;
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
				if (pctx) *pctx = ps->ctx;
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
bool dpc_packet_list_id_free(dpc_packet_list_t *pl, RADIUS_PACKET *request, bool yank)
// TODO: do we need "yank" ie are there cases where we could not want to ?
{
	dpc_packet_socket_t *ps;

	if (!pl || !request) return false;

	if (yank && !dpc_packet_list_yank(pl, request)) return false;

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

	if (!pl || !set) return 0;

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
RADIUS_PACKET *dpc_packet_list_recv(dpc_packet_list_t *pl, fd_set *set)
{
	int start;
	RADIUS_PACKET *packet;

	if (!pl || !set) return NULL;

	start = pl->last_recv;
	do {
		start = (start + 1) % DPC_MAX_SOCKETS;

		if (pl->sockets[start].sockfd == -1) continue;

		if (!FD_ISSET(pl->sockets[start].sockfd, set)) continue;

		packet = fr_dhcpv4_udp_packet_recv(pl->sockets[start].sockfd);
		if (!packet) continue;

		/*
		 *	We've received a packet, but are not guaranteed this was an expected reply.
		 *	Call fr_packet_list_find_byreply(). If it doesn't find anything, discard the reply.
		 */

		pl->last_recv = start;
		return packet;

	} while (start != pl->last_recv);

	return NULL;
}
