#ifndef _DPC_PACKET_LIST_H
#define _DPC_PACKET_LIST_H

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/conf.h>
#include <freeradius-devel/packet.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>


#define DPC_PACKET_ID_UNASSIGNED (-1)


typedef struct dpc_packet_list dpc_packet_list_t;


void dpc_packet_list_free(dpc_packet_list_t *pl);
dpc_packet_list_t *dpc_packet_list_create(uint32_t base_id);

int dpc_socket_provide(dpc_packet_list_t *pl, fr_ipaddr_t *src_ipaddr, uint16_t src_port);

bool dpc_packet_list_socket_add(dpc_packet_list_t *pl, int sockfd,
                                fr_ipaddr_t *dst_ipaddr, uint16_t dst_port, void *ctx);

bool dpc_packet_list_insert(dpc_packet_list_t *pl, RADIUS_PACKET **request_p);
RADIUS_PACKET **dpc_packet_list_find_byreply(dpc_packet_list_t *pl, RADIUS_PACKET *reply);
bool dpc_packet_list_yank(dpc_packet_list_t *pl, RADIUS_PACKET *request);
uint32_t dpc_packet_list_num_elements(dpc_packet_list_t *pl);

bool dpc_packet_list_id_alloc(dpc_packet_list_t *pl, RADIUS_PACKET **request_p, void **pctx);
bool dpc_packet_list_id_free(dpc_packet_list_t *pl, RADIUS_PACKET *request, bool yank);

int dpc_packet_list_fd_set(dpc_packet_list_t *pl, fd_set *set);
RADIUS_PACKET *dpc_packet_list_recv(dpc_packet_list_t *pl, fd_set *set);

#endif
