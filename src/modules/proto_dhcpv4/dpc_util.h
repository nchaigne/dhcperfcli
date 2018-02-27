#ifndef _DPC_UTIL_H
#define _DPC_UTIL_H

#include <freeradius-devel/libradius.h>

int dpc_socket_inspect(FILE *fp, int sockfd,
                       fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port);

#endif
