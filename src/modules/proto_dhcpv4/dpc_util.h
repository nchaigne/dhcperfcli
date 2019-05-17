#pragma once
/*
 * dpc_util.h
 */

#include "dhcperfcli.h"


#define DPC_FROM_TO_STRLEN    (21 + (FR_IPADDR_STRLEN * 2) + 5 + IFNAMSIZ + 1)
#define DPC_MSG_NUM_STRLEN    ((16 + 2) * (DHCP_MAX_MESSAGE_TYPE - 2) + 1)

#define DPC_DELTA_TIME_DECIMALS  3


char *dpc_message_type_sprint(char *out, int code);
void dpc_packet_header_fprint(FILE *fp, dpc_session_ctx_t *session, DHCP_PACKET *packet, dpc_packet_event_t pevent);
void dpc_packet_fields_fprint(FILE *fp, VALUE_PAIR *vp);
int dpc_packet_options_fprint(FILE *fp, VALUE_PAIR *vp);
void dpc_packet_fprint(FILE *fp, dpc_session_ctx_t *session, DHCP_PACKET *packet,
                       dpc_packet_event_t pevent, int trace_lvl);
void dpc_packet_data_fprint(FILE *fp, DHCP_PACKET *packet);
void dpc_packet_data_options_fprint(FILE *fp, unsigned int cur_pos, uint8_t const *p, uint8_t const *data_end,
                                    bool print_end_pad, uint8_t *overload);

char *dpc_hex_data_sprint(char *out, size_t outlen, const uint8_t *in, int in_len, char const *sep,
                          char const *prefix, int line_max_len);
char *dpc_packet_from_to_sprint(char *out, DHCP_PACKET *packet, bool extra);

VALUE_PAIR *dpc_pair_value_increment(VALUE_PAIR *vp);
VALUE_PAIR *dpc_pair_value_randomize(VALUE_PAIR *vp);
void dpc_octet_array_increment(uint8_t *array, int size, uint8_t low, uint8_t high);
bool dpc_octet_increment(uint8_t *value, uint8_t low, uint8_t high);
unsigned int dpc_message_type_extract(VALUE_PAIR *vp);
uint32_t dpc_xid_extract(VALUE_PAIR *vp);

dpc_input_t *dpc_input_item_copy(TALLOC_CTX *ctx, dpc_input_t const *in);
void dpc_input_list_fprint(FILE *fp, ncc_list_t *list);

int dpc_ipaddr_is_broadcast(fr_ipaddr_t const *ipaddr);
