/**
 * @file dpc_packet_list.c
 * @brief Functions to deal with outgoing lists / sets of DHCP packets.
 *
 * Similar to protocols/radius/list.c but adapted for handling DHCP.
 */

#include "dpc_packet_list.h"


/* We only need one socket for DHCP, so we limit the array size to one. */
#define DPC_MAX_SOCKETS (1)



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
} dhb_packet_list_t;



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

	rbtree_free(pl->tree);
	free(pl);
}

/*
 *	Create the DHCP packet list.
 *	Caller is responsible for managing the packet entries.
 *  (ref: function fr_packet_list_create from protocols/radius/list.c)
 */
dpc_packet_list_t *dpc_packet_list_create(uint32_t base_id)
{
	int i;
	dhb_packet_list_t *pl;

	pl = malloc(sizeof(*pl));
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
 *	For the reply packet we've received, look for the corresponding DHCP request
 *	from the packet list.
 *  (ref: function fr_packet_list_find_byreply from protocols/radius/list.c)
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
