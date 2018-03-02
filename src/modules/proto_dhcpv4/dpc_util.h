#ifndef _DPC_UTIL_H
#define _DPC_UTIL_H

#include <freeradius-devel/libradius.h>

#define DPC_FROM_TO_STRLEN (21 + (FR_IPADDR_STRLEN*2))

void dpc_printf_log(char const *fmt, ...);
void dpc_dev_print(char const *file, int line, char const *fmt, ...);
char *dpc_print_packet_from_to(char *buf, RADIUS_PACKET *packet, bool extra);
int dpc_socket_inspect(FILE *fp, const char *log_pre, int sockfd,
                       fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port);

#endif
