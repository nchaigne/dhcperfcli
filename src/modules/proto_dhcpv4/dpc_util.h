#ifndef _DPC_UTIL_H
#define _DPC_UTIL_H

#include "dhcperfcli.h"
#include <freeradius-devel/libradius.h>


#define DPC_FROM_TO_STRLEN    (21 + (FR_IPADDR_STRLEN * 2) + 5 + IFNAMSIZ + 1)
#define DPC_TIME_STRLEN       (15 + 1)
#define DPC_MSG_NUM_STRLEN    ((16 + 2) * (DHCP_MAX_MESSAGE_TYPE - 2) + 1)

#define DPC_DELTA_TIME_DECIMALS  3


/* Get visibility on fr_event_timer_t opaque struct (fr_event_timer is defined in lib/util/event.c) */
typedef struct dpc_fr_event_timer {
	struct timeval		when;			//!< When this timer should fire.
	/* We don't need anything beyond that. */
} dpc_fr_event_timer_t;

/* Get visibility on fr_event_list_t opaque struct (fr_event_list is defined in lib/util/event.c) */
typedef struct dpc_fr_event_list {
	fr_heap_t		*times;			//!< of timer events to be executed.
	/* We don't need anything beyond that. */
} dpc_fr_event_list_t;

int fr_event_timer_peek(fr_event_list_t *fr_el, struct timeval *when);

void dpc_printf_log(char const *fmt, ...);
void dpc_dev_print(char const *file, int line, char const *fmt, ...);
char *dpc_print_delta_time(char *out, struct timeval *from, struct timeval *when, uint8_t decimals);

char *dpc_num_message_type_print(char *out, uint32_t num_packet[]);

void dpc_packet_header_print(FILE *fp, dpc_session_ctx_t *session, RADIUS_PACKET *packet, dpc_packet_event_t pevent);
void dpc_packet_fields_print(FILE *fp, VALUE_PAIR *vp);
int dpc_packet_options_print(FILE *fp, VALUE_PAIR *vp);
void dpc_packet_print(FILE *fp, dpc_session_ctx_t *session, RADIUS_PACKET *packet,
                      dpc_packet_event_t pevent, int trace_lvl);
void dpc_packet_data_print(FILE *fp, RADIUS_PACKET *packet);

char *dpc_print_hex_data(char *out, const uint8_t *in, int in_len, char const *sep,
                         char const *prefix, int line_max_len);
char *dpc_ether_addr_print(const uint8_t *addr, char *buf);
char *dpc_print_packet_from_to(char *buf, RADIUS_PACKET *packet, bool extra);

int dpc_socket_inspect(FILE *fp, char const *log_pre, int sockfd,
                       fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port);

VALUE_PAIR *dpc_pair_find_dhcp(VALUE_PAIR *head, unsigned int attr, int8_t tag);
VALUE_PAIR *dpc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from);
VALUE_PAIR *dpc_pair_value_increment(VALUE_PAIR *vp);
VALUE_PAIR *dpc_pair_value_randomize(VALUE_PAIR *vp);
void dpc_octet_array_increment(uint8_t *array, int size, uint8_t low, uint8_t high);
bool dpc_octet_increment(uint8_t *value, uint8_t low, uint8_t high);

void dpc_float_to_timeval(struct timeval *tv, float f_val);
float dpc_timeval_to_float(struct timeval *tv);
bool dpc_str_to_float(float *out, char const *value);
char *dpc_str_trim(char *str);

void dpc_input_item_add(dpc_input_list_t *list, dpc_input_t *entry);
dpc_input_t *dpc_input_item_draw(dpc_input_t *entry);
dpc_input_t *dpc_get_input_list_head(dpc_input_list_t *list);

bool dpc_stdin_peek(void);
int dpc_ipaddr_is_broadcast(fr_ipaddr_t const *ipaddr);

#endif
