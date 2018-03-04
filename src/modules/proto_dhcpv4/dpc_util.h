#ifndef _DPC_UTIL_H
#define _DPC_UTIL_H

#include <freeradius-devel/libradius.h>

#define DPC_FROM_TO_STRLEN (21 + (FR_IPADDR_STRLEN*2))

void dpc_printf_log(char const *fmt, ...);
void dpc_dev_print(char const *file, int line, char const *fmt, ...);

static void dpc_packet_header_print(FILE *fp, RADIUS_PACKET *packet, bool received);
void dpc_packet_fields_print(FILE *fp, VALUE_PAIR *vp);
int dpc_packet_options_print(FILE *fp, VALUE_PAIR *vp);
void dpc_packet_print(FILE *fp, RADIUS_PACKET *packet, bool received);

char *dpc_ether_addr_print(const uint8_t *addr, char *buf);
char *dpc_print_packet_from_to(char *buf, RADIUS_PACKET *packet, bool extra);

int dpc_socket_inspect(FILE *fp, const char *log_pre, int sockfd,
                       fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port);

VALUE_PAIR *dpc_pair_find_dhcp(VALUE_PAIR *head, unsigned int attr, int8_t tag);
VALUE_PAIR *dpc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from);

void dpc_float_to_timeval(struct timeval *tv, float f_val);

void dpc_input_item_add(dpc_input_list_t *list, dpc_input_t *entry);
dpc_input_t *dpc_input_item_draw(dpc_input_t *entry);
dpc_input_t *dpc_get_input_list_head(dpc_input_list_t *list);

#endif
