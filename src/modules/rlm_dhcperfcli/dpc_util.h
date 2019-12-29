#pragma once
/*
 * dpc_util.h
 */

#include "dhcperfcli.h"


#define DPC_FROM_TO_STRLEN       (21 + (FR_IPADDR_STRLEN * 2) + 5 + IFNAMSIZ + 1)

#define DPC_MSG_NUM_STRLEN       ((16 + 2) * (DHCP_MAX_MESSAGE_TYPE - 2) + 1)

#define DPC_DELTA_TIME_DECIMALS  3

#define DPC_XLAT_MAX_LEN 4096


void dpc_tr_stats_update_values(dpc_transaction_stats_t *my_stats, fr_time_delta_t rtt);
void dpc_dyn_tr_stats_update(TALLOC_CTX *ctx, dpc_dyn_tr_stats_t *dyn_tr_stats, char const *name, fr_time_delta_t rtt);

char *dpc_session_transaction_snprint(char *out, size_t outlen, dpc_session_ctx_t *session);
char *dpc_message_type_sprint(char *out, int code);
char *dpc_retransmit_snprint(char *out, size_t outlen, uint32_t num_sent, uint32_t *breakdown, uint32_t retransmit_max);

void dpc_packet_digest_fprint(FILE *fp, dpc_session_ctx_t *session, DHCP_PACKET *packet, dpc_packet_event_t pevent);
void dpc_packet_fields_fprint(FILE *fp, VALUE_PAIR *vp);
int dpc_packet_options_fprint(FILE *fp, VALUE_PAIR *vp);
void dpc_packet_fprint(FILE *fp, dpc_session_ctx_t *session, DHCP_PACKET *packet, dpc_packet_event_t pevent);
void dpc_packet_data_fprint(FILE *fp, DHCP_PACKET *packet);
void dpc_packet_data_options_fprint(FILE *fp, unsigned int cur_pos, uint8_t const *p, uint8_t const *data_end,
                                    bool print_end_pad, uint8_t *overload);

char *dpc_packet_from_to_sprint(char *out, DHCP_PACKET *packet, bool extra);

VALUE_PAIR *dpc_pair_value_increment(VALUE_PAIR *vp);
VALUE_PAIR *dpc_pair_value_randomize(VALUE_PAIR *vp);
void dpc_octet_array_increment(uint8_t *array, int size, uint8_t low, uint8_t high);
bool dpc_octet_increment(uint8_t *value, uint8_t low, uint8_t high);
unsigned int dpc_message_type_extract(VALUE_PAIR *vp);
uint32_t dpc_xid_extract(VALUE_PAIR *vp);

dpc_input_t *dpc_input_item_copy(TALLOC_CTX *ctx, dpc_input_t const *in);
void dpc_input_debug(dpc_input_t *input);
void dpc_input_list_debug(ncc_dlist_t *dlist);
void dpc_segment_list_debug(ncc_dlist_t *list);

int dpc_ipaddr_is_broadcast(fr_ipaddr_t const *ipaddr);

ssize_t dpc_xlat_eval(char *out, size_t outlen, char const *fmt, DHCP_PACKET *packet);
ssize_t dpc_xlat_eval_compiled(char *out, size_t outlen, xlat_exp_t const *xlat, DHCP_PACKET *packet);
