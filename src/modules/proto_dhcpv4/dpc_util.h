#pragma once
/*
 * dpc_util.h
 */

#include "dhcperfcli.h"


#define DPC_FROM_TO_STRLEN    (21 + (FR_IPADDR_STRLEN * 2) + 5 + IFNAMSIZ + 1)
#define DPC_TIME_STRLEN       (15 + 1)
#define DPC_MSG_NUM_STRLEN    ((16 + 2) * (DHCP_MAX_MESSAGE_TYPE - 2) + 1)

#define DPC_DELTA_TIME_DECIMALS  3


void dpc_printf_log(char const *fmt, ...);
void dpc_dev_print(char const *file, int line, char const *fmt, ...);
char *dpc_delta_time_sprint(char *out, struct timeval *from, struct timeval *when, uint8_t decimals);

char *dpc_num_message_type_sprint(char *out, uint32_t num_packet[]);

char *dpc_message_type_sprint(char *out, int code);
void dpc_packet_header_fprint(FILE *fp, dpc_session_ctx_t *session, RADIUS_PACKET *packet, dpc_packet_event_t pevent);
void dpc_packet_fields_fprint(FILE *fp, VALUE_PAIR *vp);
int dpc_packet_options_fprint(FILE *fp, VALUE_PAIR *vp);
void dpc_packet_fprint(FILE *fp, dpc_session_ctx_t *session, RADIUS_PACKET *packet,
                       dpc_packet_event_t pevent, int trace_lvl);
void dpc_packet_data_fprint(FILE *fp, RADIUS_PACKET *packet);
void dpc_packet_data_options_fprint(FILE *fp, unsigned int cur_pos, uint8_t const *p, uint8_t const *data_end,
                                    bool print_end_pad, uint8_t *overload);

char *dpc_hex_data_sprint(char *out, const uint8_t *in, int in_len, char const *sep,
                          char const *prefix, int line_max_len);
char *dpc_ether_addr_sprint(char *out, const uint8_t *addr);
char *dpc_packet_from_to_sprint(char *out, RADIUS_PACKET *packet, bool extra);

VALUE_PAIR *dpc_pair_find_dhcp(VALUE_PAIR *head, unsigned int attr, int8_t tag);
VALUE_PAIR *dpc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from);
VALUE_PAIR *dpc_pair_value_increment(VALUE_PAIR *vp);
VALUE_PAIR *dpc_pair_value_randomize(VALUE_PAIR *vp);
void dpc_octet_array_increment(uint8_t *array, int size, uint8_t low, uint8_t high);
bool dpc_octet_increment(uint8_t *value, uint8_t low, uint8_t high);
unsigned int dpc_message_type_extract(VALUE_PAIR *vp);
uint32_t dpc_xid_extract(VALUE_PAIR *vp);

int dpc_float_to_timeval(struct timeval *out, float in);
bool dpc_str_to_float(float *out, char const *in);
bool dpc_str_to_uint32(uint32_t *out, char const *in);
char *dpc_str_trim(char *str);

void dpc_input_item_add(dpc_input_list_t *list, dpc_input_t *entry);
dpc_input_t *dpc_input_item_copy(TALLOC_CTX *ctx, dpc_input_t const *in);
dpc_input_t *dpc_input_item_draw(dpc_input_t *entry);
dpc_input_t *dpc_get_input_list_head(dpc_input_list_t *list);

bool dpc_stdin_peek(void);
int dpc_ipaddr_is_broadcast(fr_ipaddr_t const *ipaddr);
