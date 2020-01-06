#pragma once
/*
 * dpc_packet_list.h
 */

typedef struct dpc_packet_list dpc_packet_list_t;


void dpc_packet_list_free(dpc_packet_list_t *pl);
dpc_packet_list_t *dpc_packet_list_create(TALLOC_CTX *ctx, uint32_t base_id);
void dpc_packet_list_set_base_id(dpc_packet_list_t *pl, uint32_t base_id);

#ifdef HAVE_LIBPCAP
void dpc_pcap_filter_build(dpc_packet_list_t *pl, fr_pcap_t *pcap);
int dpc_pcap_socket_add(dpc_packet_list_t *pl, fr_pcap_t *pcap, fr_ipaddr_t *src_ipaddr, uint16_t src_port);
#endif
int dpc_socket_provide(dpc_packet_list_t *pl, fr_ipaddr_t *src_ipaddr, uint16_t src_port);

bool dpc_packet_list_insert(dpc_packet_list_t *pl, DHCP_PACKET **request_p);
DHCP_PACKET **dpc_packet_list_find_byreply(dpc_packet_list_t *pl, DHCP_PACKET *reply);
bool dpc_packet_list_yank(dpc_packet_list_t *pl, DHCP_PACKET *request);
uint32_t dpc_packet_list_num_elements(dpc_packet_list_t *pl);

bool dpc_packet_list_id_alloc(dpc_packet_list_t *pl, int sockfd, DHCP_PACKET **request_p);
bool dpc_packet_list_id_free(dpc_packet_list_t *pl, DHCP_PACKET *request);

int dpc_packet_list_fd_set(dpc_packet_list_t *pl, fd_set *set);
DHCP_PACKET *dpc_packet_list_recv(dpc_packet_list_t *pl, fd_set *set);
