/**
 * @file dpc_util.c
 * @brief Utility functions
 */

#include "dhcperfcli.h"
#include "ncc_util.h"
#include "ncc_xlat.h"
#include "dpc_packet_list.h"
#include "dpc_util.h"
#include "dpc_config.h"


typedef struct {
	uint8_t size;
	char const *name;
} dpc_dhcp_header_t;

dpc_dhcp_header_t dpc_dhcp_headers[] = {
	{  1, "op" }, {  1, "htype" }, {  1, "hlen" }, {  1, "hops" },
	{  4, "xid" },
	{  2, "secs" }, {  2, "flags" },
	{  4, "ciaddr" },
	{  4, "yiaddr" },
	{  4, "siaddr" },
	{  4, "giaddr" },
	{  DHCP_CHADDR_LEN, "chaddr" },
	{  DHCP_SNAME_LEN,  "sname" },
	{  DHCP_FILE_LEN,   "file" },
	{  4, "options" },
	{ -1, NULL}
};


/*
 *	Update a type of transaction statistics, with one newly completed transaction:
 *	number of such transactions, cumulated rtt, min/max rtt.
 */
void dpc_tr_stats_update_values(dpc_transaction_stats_t *stats, fr_time_delta_t rtt)
{
	if (!rtt) return;

	/* Update 'rtt_min'. */
	if (stats->num == 0 || rtt < stats->rtt_min) {
		stats->rtt_min = rtt;
	}

	/* Update 'rtt_max'. */
	if (stats->num == 0 || rtt > stats->rtt_max) {
		stats->rtt_max = rtt;
	}

	/* Update 'rtt_cumul' and 'num'. */
	stats->rtt_cumul += rtt;
	stats->num ++;
}

/*
 *	Update statistics for a dynamically named transaction type.
 */
void dpc_dyn_tr_stats_update(TALLOC_CTX *ctx, dpc_dyn_tr_stats_t *dyn_tr_stats, char const *name, fr_time_delta_t rtt)
{
	/* Get the transaction name index. */
	int i = ncc_str_array_index(ctx, &dyn_tr_stats->names, name);

	/* Reallocate if necessary */
	size_t num_transaction_type = talloc_array_length(dyn_tr_stats->stats);
	if (i >= num_transaction_type) {
		TALLOC_REALLOC_ZERO(ctx, dyn_tr_stats->stats,
		                    dpc_transaction_stats_t, num_transaction_type, i + 1);
	}

	dpc_transaction_stats_t *my_stats = &(dyn_tr_stats->stats[i]);
	dpc_tr_stats_update_values(my_stats, rtt);
}

/**
 * Print the transaction name (request sent, reply received) associated to a session.
 * Built as follows: [<input name>.]<request>:<reply>
 */
char *dpc_session_transaction_snprint(char *out, size_t outlen, dpc_session_ctx_t *session)
{
	char *p = out;
	char const *p_name_request;
	char const *p_name_reply;

	*p = '\0';

	if (!session || !session->request || !session->reply
	    || !is_dhcp_message(session->request->code) || !is_dhcp_message(session->reply->code)) {
		return NULL;
	}

	p_name_request = dpc_message_types[session->request->code];
	p_name_reply = dpc_message_types[session->reply->code];

	if (session->input->name) {
		snprintf(p, outlen, "%s.%s:%s", session->input->name, p_name_request, p_name_reply);
	} else {
		snprintf(p, outlen, "%s:%s", p_name_request, p_name_reply);
	}
	return out;
}

/*
 *	Print the message type from packet code.
 */
char *dpc_message_type_sprint(char *out, int message)
{
	char *p = out;
	size_t len;

	if (is_dhcp_message(message)) {
		sprintf(p, "%s", dpc_message_types[message]);
	} else {
		len = sprintf(out, "DHCP packet");
		p += len;
		if (message <= 0) sprintf(p, " (BOOTP)"); /* No DHCP Message Type: maybe BOOTP (or malformed DHCP packet). */
		else sprintf(p, " (unknown type: %u)", message);
	}
	return out;
}

/*
 *	Print retransmissions breakdown by number of retransmissions per request sent.
 */
char *dpc_retransmit_snprint(char *out, size_t outlen, uint32_t num_sent, uint32_t *breakdown, uint32_t retransmit_max)
// TODO: use outlen
{
	int i;
	char *p = out;
	size_t len = 0;

	*p = '\0';
	if (num_sent == 0 || !breakdown) return out;

#define RETR_PRINT(_num, _ind) \
{ \
	if (_num > 0) { \
		if (p != out) { \
			len = sprintf(p, ", "); \
			p += len; \
		} \
		len = sprintf(p, "#%u: %u (%.1f%%)", _ind, _num, 100 * (float)_num / num_sent); \
		p += len; \
	} \
}

	for (i = 0; i < retransmit_max; i++) {
		if (i >= 10) break; /* Limit what we print. */
		RETR_PRINT(breakdown[i], i + 1);
	}
	return out;
}

/*
 *	Print the packet summary.
 */
void dpc_packet_digest_fprint(FILE *fp, dpc_session_ctx_t *session, DHCP_PACKET *packet, dpc_packet_event_t pevent)
{
	char from_to_buf[DPC_FROM_TO_STRLEN] = "";

	uint32_t yiaddr;
	char lease_ipaddr[128] = "";
	uint8_t hwaddr[6] = "";
	char buf_hwaddr[NCC_ETHADDR_STRLEN] = "";

	if (!fp) return;
	if (!packet) return;

	if (session) fprintf(fp, "(%u) ", session->id);

	/* Elapsed time. */
	if (CONF.packet_trace_elapsed) {
		char time_buf[NCC_TIME_STRLEN];
		fprintf(fp, "t(%s) ", ncc_fr_delta_time_snprint(time_buf, sizeof(time_buf), &fte_start, NULL, DPC_DELTA_TIME_DECIMALS));
	}

	/* Absolute date/time. */
	if (CONF.packet_trace_timestamp) {
		char datetime_buf[NCC_DATETIME_STRLEN];
		fprintf(fp, "%s ", ncc_absolute_time_snprint(datetime_buf, sizeof(datetime_buf), NCC_TIME_FMT));
	}

	switch (pevent) {
		case DPC_PACKET_SENT:
			fprintf(fp, "Sent");
			if (session->retransmit > 0) {
				fprintf(fp, " (retr: %u)", session->retransmit);
			}
			break;
		case DPC_PACKET_RECEIVED:
			fprintf(fp, "Received");
			break;
		case DPC_PACKET_RECEIVED_DISCARD:
			fprintf(fp, "Discarded received");
			break;
		case DPC_PACKET_TIMEOUT:
			fprintf(fp, "Timed out");
			break;
	}

	/*
	 *	Considerations on packet length:
	 *	- BOOTP packet length is fixed (300 octets).
	 *	- DHCP packet length is *at least* 243 octets:
	 *	  236 (fields) + 4 (magic cookie) + 3 (just enough room for option Message Type - which is required).
	 *
	 *	Note: some archaic DHCP relays or servers won't even accept a DHCP packet smaller than 300 octets...
	 */

	if (packet->data && packet->data_len < 243) { /* Obviously malformed. */
		fprintf(fp, " malformed packet");
	} else {
		char buf[50];
		fprintf(fp, " %s", dpc_message_type_sprint(buf, packet->code));
	}

	/* DHCP specific information. */
	if (packet->data && packet->data_len >= 34) { /* Only print this if there is enough data. */
		memcpy(hwaddr, packet->data + 28, sizeof(hwaddr));
		fprintf(fp, " (hwaddr: %s", ncc_ether_addr_snprint(buf_hwaddr, sizeof(buf_hwaddr), hwaddr));

		if (packet->code == FR_DHCP_ACK || packet->code == FR_DHCP_OFFER) {
			memcpy(&yiaddr, packet->data + 16, 4);
			fprintf(fp, ", yiaddr: %s", inet_ntop(AF_INET, &yiaddr, lease_ipaddr, sizeof(lease_ipaddr)));
		}

		/* If we sent a Request and got a NAK, print the Requested IP address that the server didn't like.
		 */
		if (packet->code == FR_DHCP_NAK && session->request->code == FR_DHCP_REQUEST) {
			VALUE_PAIR *vp = fr_pair_find_by_da(session->request->vps, attr_dhcp_requested_ip_address, TAG_ANY);
			if (vp) {
				fprintf(fp, ", req addr: %s", inet_ntop(AF_INET, &vp->vp_ipv4addr, lease_ipaddr, sizeof(lease_ipaddr)));
			}
		}

		fprintf(fp, ")");
	}

	fprintf(fp, " Id %u (0x%08x) %s length %zu", packet->id, packet->id,
	        dpc_packet_from_to_sprint(from_to_buf, packet, false), packet->data_len);

	/* Also print rtt for replies. */
	if (pevent == DPC_PACKET_RECEIVED && session->ftd_rtt) {
		fprintf(fp, ", rtt: %.3f ms", 1000 * ncc_fr_time_to_float(session->ftd_rtt));
	}
	fprintf(fp, "\n");
}

/*
 *	Print the "fields" (options excluded) of a DHCP packet (from the VPs list).
 */
void dpc_packet_fields_fprint(FILE *fp, VALUE_PAIR *vp)
{
	fr_cursor_t cursor;

	for (vp = fr_cursor_init(&cursor, &vp); vp; vp = fr_cursor_next(&cursor)) {
		if (vp_is_dhcp_field(vp)) {
			fr_pair_fprint(fp, vp);
		}
	}
}

/*
 *	Print the "options" of a DHCP packet (from the VPs list).
 */
int dpc_packet_options_fprint(FILE *fp, VALUE_PAIR *vp)
{
	char buf[1024];
	char *p = buf;
	int num = 0; /* Keep track of how many options we have. */

	fr_cursor_t cursor;
	for (vp = fr_cursor_init(&cursor, &vp); vp; vp = fr_cursor_next(&cursor)) {
		if (vp_is_dhcp_option(vp)) {
			num ++;

			p = buf;
			*p++ = '\t';

			if (vp_is_dhcp_sub_option(vp)) {
				/* This is a sub-option.
				 * Print <option.sub-attr> (eg. "82.1").
				 */
				p += sprintf(p, "(%d.%d) ", vp->da->parent->attr, vp->da->attr);
			} else {
				/* This is a simple option. */
				p += sprintf(p, "(%d) ", vp->da->attr);
			}

			p += fr_pair_snprint(p, sizeof(buf) - 1, vp);
			*p++ = '\n';
			*p = '\0';

			fputs(buf, fp);
		}
	}
	return num;
}

/*
 * Print a DHCP packet.
 */
void dpc_packet_fprint(FILE *fp, dpc_session_ctx_t *session, DHCP_PACKET *packet, dpc_packet_event_t pevent)
{
	VALUE_PAIR *vp_encoded_data = NULL;

	if (!fp || !packet) return;

	if (CONF.packet_trace_lvl >= 1) {
		dpc_packet_digest_fprint(fp, session, packet, pevent);
	}

	if (CONF.packet_trace_lvl >= 2) {
		if ((vp_encoded_data = ncc_pair_find_by_da(packet->vps, attr_encoded_data)) != NULL) {
			fprintf(fp, "DHCP data:\n");
			fr_pair_fprint(fp, vp_encoded_data);
		} else {
			fprintf(fp, "DHCP vps fields:\n");
			dpc_packet_fields_fprint(fp, packet->vps);

			fprintf(fp, "DHCP vps options:\n");
			if (dpc_packet_options_fprint(fp, packet->vps) == 0) {
				fprintf(fp, "\t(empty list)\n");
			}
		}
	}

	if (CONF.packet_trace_lvl >= 3) {
		fprintf(fp, "DHCP hex data:\n");
		dpc_packet_data_fprint(fp, packet);

		/*
		 *	If this is a packet we're sending, which was not built using pre-encoded data,
		 *	build and print the equivalent DHCP-Encoded-Data so we can reuse it effortlessly.
		 */
		if (pevent == DPC_PACKET_SENT && !vp_encoded_data) {
			VALUE_PAIR *vp = ncc_pair_create_by_da(packet, NULL, attr_encoded_data);
			fr_pair_value_memcpy(vp, packet->data, packet->data_len, true);
			fprintf(fp, "DHCP data:\n");
			fr_pair_fprint(fp, vp);
		}
	}
}

/*
 *	Print the data of a DHCP packet.
 *	Fields and options are printed in hex, along with their position in the packet.
 *	This allows to see what is exactly in a packet and where.
 */
void dpc_packet_data_fprint(FILE *fp, DHCP_PACKET *packet)
{
	char header[64];
	char buf[2048];
	uint8_t const *p, *data_end;
	unsigned int cur_pos = 0;
	uint8_t overload = 0;
	int i;

	if (!packet->data) return;

	p = packet->data;
	data_end = packet->data + packet->data_len - 1;

	/*
	 *	Print fields.
	 */
	for (i = 0; dpc_dhcp_headers[i].name; i++) {
		if (cur_pos + dpc_dhcp_headers[i].size > packet->data_len) {
			/*
			 *	This is malformed. Still print something useful.
			 */
			fprintf(fp, "  incomplete/malformed DHCP data (len: %zu)\n", packet->data_len);
			int remain = packet->data_len - cur_pos;
			if (remain > 0) {
				sprintf(header, "  %04x  %10s: ", cur_pos, "remainder");
				ncc_hex_data_snprint(buf, sizeof(buf), p, remain, " ", header, 16);
				fprintf(fp, "%s\n", buf);
			}
			return;
		}

		/* One valid field to print. */
		sprintf(header, "  %04x  %10s: ", cur_pos, dpc_dhcp_headers[i].name);
		ncc_hex_data_snprint(buf, sizeof(buf), p, dpc_dhcp_headers[i].size, " ", header, 16);
		fprintf(fp, "%s\n", buf);

		p += dpc_dhcp_headers[i].size;
		cur_pos += dpc_dhcp_headers[i].size;
	}

	/*
	 *	Print options.
	 */
	dpc_packet_data_options_fprint(fp, cur_pos, p, data_end, true, &overload);
	if (overload) {
		if ((overload & 1) == 1) {
			/* The 'file' field is used to hold options. It must be interpreted before 'sname'. */
			fprintf(fp, "  -- options overload: file --\n");
			cur_pos = offsetof(dhcp_packet_t, file);
			p = packet->data + cur_pos;
			data_end = p + DHCP_FILE_LEN - 1;
			dpc_packet_data_options_fprint(fp, cur_pos, p, data_end, false, NULL);
		}
		if ((overload & 2) == 2) {
			/* The 'sname' field is used to hold options. */
			fprintf(fp, "  -- options overload: sname --\n");
			cur_pos = offsetof(dhcp_packet_t, sname);
			p = packet->data + cur_pos;
			data_end = p + DHCP_SNAME_LEN - 1;
			dpc_packet_data_options_fprint(fp, cur_pos, p, data_end, false, NULL);
		}
	}
}

/*
 *	Print DHCP packet options in hex, along with their position in the packet.
 */
void dpc_packet_data_options_fprint(FILE *fp, unsigned int cur_pos, uint8_t const *p, uint8_t const *data_end,
                                    bool print_end_pad, uint8_t *overload)
{
	char buf[2048];
	char header[64];
	int pad_size = 0;
	uint8_t const *pad_p = NULL;
	size_t options_len = data_end - p + 1;

	/*
	 *	Print options.
	 */
	while (p <= data_end) {

		if (*p == 0) { /* Pad Option. Group consecutive padding in a single string. */
			if (!pad_p) pad_p = p;
			pad_size ++;
			p ++;
			continue;
		} else if (pad_p) { /* We're done with padding octets: print them. */
			sprintf(header, "  %04x  %10s: ", cur_pos, "pad");
			ncc_hex_data_snprint(buf, sizeof(buf), pad_p, pad_size, " ", header, 16);
			fprintf(fp, "%s\n", buf);

			cur_pos += pad_size;
			pad_p = NULL;
			pad_size = 0;
		}

		if (*p == 255) { /* End Option. */
			sprintf(header, "  %04x  %10s: ", cur_pos, "end");
			ncc_hex_data_snprint(buf, sizeof(buf), p, 1, " ", header, 16);
			fprintf(fp, "%s\n", buf);

			p ++;
			cur_pos ++;
			continue;
		}

		/*
		 *	Option format: <code> <len> <option data>
		 *	So an option is coded on "1 + 1 + value of <len>" octets.
		 */
		if (  ((p + 1) > data_end) /* No room for <len> */
		   || ((p + 1 + p[1] ) > data_end) /* No room for <option data> */
		   ) {
			fprintf(fp, "  incomplete/malformed DHCP options (len: %zu)\n", options_len);
			int remain = data_end - p + 1;
			if (remain > 0) {
				sprintf(header, "  %04x  %10s: ", cur_pos, "remainder");
				ncc_hex_data_snprint(buf, sizeof(buf), p, remain, " ", header, 16);
				fprintf(fp, "%s\n", buf);
			}
			return;
		}

		/* One valid option to print. */
		int opt_size = p[1] + 2;
		if (overload && p[0] == FR_DHCP_OVERLOAD) *overload = p[2];
		sprintf(header, "  %04x  %10d: ", cur_pos, p[0]);
		ncc_hex_data_snprint(buf, sizeof(buf), p, opt_size, " ", header, 16);
		fprintf(fp, "%s\n", buf);
		p += opt_size;
		cur_pos += opt_size;
	}

	if (print_end_pad && pad_p) { /* There may be more padding after End Option. */
		sprintf(header, "  %04x  %10s: ", cur_pos, "pad");
		ncc_hex_data_snprint(buf, sizeof(buf), pad_p, pad_size, " ", header, 16);
		fprintf(fp, "%s\n", buf);
	}
}

/*
 *	Print packet source and destination IP/port.
 *	Caller is responsible for passing an output buffer (buf) with sufficient space (DPC_FROM_TO_STRLEN).
 */
char *dpc_packet_from_to_sprint(char *out, DHCP_PACKET *packet, bool extra)
{
	char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
	char dst_ipaddr_buf[FR_IPADDR_STRLEN] = "";
	char via[5 + IFNAMSIZ] = "";

	fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &packet->src_ipaddr);
	fr_inet_ntop(dst_ipaddr_buf, sizeof(dst_ipaddr_buf), &packet->dst_ipaddr);

	if (!extra) {
		sprintf(out, "from %s:%u to %s:%u",
		        src_ipaddr_buf, packet->src_port, dst_ipaddr_buf, packet->dst_port
		);
	} else {
		sprintf(out, "from %s:%u (prefix: %d) to %s:%u (prefix: %d)",
		        src_ipaddr_buf, packet->src_port, packet->src_ipaddr.prefix,
		        dst_ipaddr_buf, packet->dst_port, packet->dst_ipaddr.prefix
		);
	}

#if defined(WITH_IFINDEX_NAME_RESOLUTION)
	if (packet->if_index) {
		char if_name[IFNAMSIZ];
		sprintf(via, " via %s", fr_ifname_from_ifindex(if_name, packet->if_index));
		strcat(out, via);
	}
#endif

	return out;
}

/*
 *	Increment the value of a value pair.
 */
VALUE_PAIR *dpc_pair_value_increment(VALUE_PAIR *vp)
{
	if (!vp || !vp->da) return NULL;

	switch (vp->da->type) {
	case FR_TYPE_UINT8:
		vp->vp_uint8 ++;
		break;

	case FR_TYPE_UINT16:
		vp->vp_uint16 ++;
		break;

	case FR_TYPE_UINT32:
		vp->vp_uint32 ++;
		break;

	case FR_TYPE_UINT64:
		vp->vp_uint64 ++;
		break;

	case FR_TYPE_STRING:
	{
		/* Technically type string can hold any octet value, but we'll restrict to printable ASCII-7 characters. */
		char *buff = talloc_zero_array(vp, char, vp->vp_length + 1);
		memcpy(buff, vp->vp_strvalue, vp->vp_length);
		dpc_octet_array_increment((uint8_t *)buff, vp->vp_length, 33, 126); /* Also avoid space (32). */
		fr_pair_value_strsteal(vp, buff);
		break;
	}

	case FR_TYPE_OCTETS:
	{
		uint8_t *buff = talloc_zero_array(vp, uint8_t, vp->vp_length);
		memcpy(buff, vp->vp_octets, vp->vp_length);
		dpc_octet_array_increment(buff, vp->vp_length, 0, 255);
		fr_pair_value_memsteal(vp, buff, true);
		break;
	}

	case FR_TYPE_IPV4_ADDR:
		vp->vp_ipv4addr = htonl(ntohl(vp->vp_ipv4addr) + 1);

		/* Don't use broadcast IP address. */
		if (dpc_ipaddr_is_broadcast(&vp->vp_ip)) vp->vp_ipv4addr = htonl(1);
		break;

	case FR_TYPE_ETHERNET:
	{
		/* Hackish way to increment the 6 octets of hwaddr. */
		uint64_t hwaddr = 0;
		memcpy(&hwaddr, vp->vp_ether, 6);
		hwaddr = ntohll(hwaddr) + (1 << 16);
		hwaddr = htonll(hwaddr);
		memcpy(vp->vp_ether, &hwaddr, 6);

		/* Don't use broadcast ethernet address. */
		if (memcmp(&eth_bcast, vp->vp_ether, 6) == 0) {
			memset(vp->vp_ether, '\0', 6);
			vp->vp_ether[5] ++;
		}
		break;
	}

	default: /* Type not handled. */
		break;
	}

	return vp;
}

/*
 *	Randomize the value of a value pair.
 */
VALUE_PAIR *dpc_pair_value_randomize(VALUE_PAIR *vp)
{
	if (!vp || !vp->da) return NULL;

	switch (vp->da->type) {
	case FR_TYPE_UINT8:
		vp->vp_uint8 = fr_rand() & 0xff;
		break;

	case FR_TYPE_UINT16:
		vp->vp_uint16 = fr_rand() & 0xffff;
		break;

	case FR_TYPE_UINT32:
		vp->vp_uint32 = fr_rand();
		break;

	case FR_TYPE_UINT64:
		vp->vp_uint64 = ((uint64_t)fr_rand() << 32) | fr_rand();
		break;

	case FR_TYPE_STRING:
	{
		unsigned int i;
		char *buff = talloc_zero_array(vp, char, vp->vp_length + 1);
		memcpy(buff, vp->vp_strvalue, vp->vp_length);
		for (i = 0; i < vp->vp_length; i ++) {
			/* Restrict to printable ASCII-7 characters. */
			buff[i] = (fr_rand() % (126 - 32 + 1)) + 32;
		}
		fr_pair_value_strsteal(vp, buff);
		break;
	}

	case FR_TYPE_OCTETS:
	{
		uint8_t *buff = talloc_zero_array(vp, uint8_t, vp->vp_length);
		memcpy(buff, vp->vp_octets, vp->vp_length);
		fr_rand_buffer(buff, vp->vp_length);
		fr_pair_value_memsteal(vp, buff, true);
		break;
	}

	case FR_TYPE_IPV4_ADDR:
		vp->vp_ipv4addr = fr_rand();
		break;

	case FR_TYPE_ETHERNET:
		fr_rand_buffer(vp->vp_ether, 6);
		break;

	default: /* Type not handled. */
		break;
	}

	return vp;
}

/*
 *	Increment an octet array (starting at the last octet), restricting value of each octet to a bounded interval.
 */
void dpc_octet_array_increment(uint8_t *array, int size, uint8_t low, uint8_t high)
{
	int i;
	for (i = size; i > 0 ; i--) {
		if (!dpc_octet_increment(&array[i-1], low, high)) break;
	}
}

/*
 *	Increment an octet, restricting its value to a bounded interval.
 *	Returns true if value fell back to the lower bound.
 */
bool dpc_octet_increment(uint8_t *value, uint8_t low, uint8_t high)
{
	uint8_t in = *value;
	if (*value == high) *value = low;
	else (*value) ++;

	return (*value < in);
}

/*
 *	Try and extract the message type from the DHCP pre-encoded data provided.
 */
unsigned int dpc_message_type_extract(VALUE_PAIR *vp)
{
	unsigned int code = FR_CODE_UNDEFINED;
	uint8_t const *message_type;

	if (vp->vp_length <= 240) goto end; /* No options. */

	message_type = fr_dhcpv4_packet_get_option((dhcp_packet_t const *) vp->vp_octets, vp->vp_length,
	                                           attr_dhcp_message_type);
	if (message_type) {
		code = message_type[2];
	}

end:
	DEBUG_TRACE("Extracted message code: %u", code);
	return code;
}

/*
 *	Extract the xid from the DHCP pre-encoded data provided.
 */
uint32_t dpc_xid_extract(VALUE_PAIR *vp)
{
	uint32_t value;

	if (vp->vp_length < 8) return DPC_PACKET_ID_UNASSIGNED;

	memcpy(&value, vp->vp_octets + 4, 4);
	return ntohl(value);
}

/*
 *	Duplicate an input item (copy initially does not belong to any list).
 */
dpc_input_t *dpc_input_item_copy(TALLOC_CTX *ctx, dpc_input_t const *in)
{
	dpc_input_t *out; // the duplicated input

	MEM(out = talloc_zero(ctx, dpc_input_t));

	/*
	 *	First copy everything, then reset what needs to be.
	 */
	memcpy(out, in, sizeof(*out));

	out->vps = NULL;
	out->dlist = (fr_dlist_t){};

	/* Copy the list of vps (preserving pre-compiled xlat) */
	MEM(ncc_pair_list_copy(out, &out->vps, in->vps) >= 0);

	return out;
}

/*
 *	Print the contents of a list of dpc_input_t items.
 */
void dpc_input_list_fprint(FILE *fp, ncc_dlist_t *list)
{
	fprintf(fp, "List contains %u element(s)\n", NCC_DLIST_SIZE(list));

	dpc_input_t *item = NCC_DLIST_HEAD(list);
	int i = 0;
	while (item) {
		fprintf(fp, " - Element #%u:\n", i);
		fprintf(fp, "   - id: %u\n", item->id);
		fprintf(fp, "   - vps: %s\n", item->vps ? "" : "NULL");

		fr_cursor_t cursor;
		VALUE_PAIR *vp;
		for (vp = fr_cursor_init(&cursor, &item->vps); vp; vp = fr_cursor_next(&cursor)) {
			fr_pair_fprint(fp, vp);
		}

		item = NCC_DLIST_NEXT(&input_list, item);
		i++;
	}
}

/*
 *	Determine if an IP address is the broadcast address.
 *	Returns: 0 if it is not, 1 if it is, -1 on error.
 */
int dpc_ipaddr_is_broadcast(fr_ipaddr_t const *ipaddr)
{
	if (ipaddr->af == AF_INET) {
		if (ipaddr->addr.v4.s_addr == htonl(INADDR_BROADCAST)) {
			return 1;
		}
	} else {
		fr_strerror_printf("Unsupported address family");
		return -1;
	}

	return 0;
}


/*
 *	Wrapper to FreeRADIUS xlat_eval with a fake REQUEST provided,
 *	which allows access to "control" and "packet" lists of value pairs
 */
ssize_t dpc_xlat_eval(char *out, size_t outlen, char const *fmt, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;

	return ncc_xlat_eval(out, outlen, fmt, vps);
}

/*
 *	Wrapper to FreeRADIUS xlat_eval_compiled with a fake REQUEST provided,
 *	which allows access to "control" and "packet" lists of value pairs
 */
ssize_t dpc_xlat_eval_compiled(char *out, size_t outlen, xlat_exp_t const *xlat, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;

	return ncc_xlat_eval_compiled(out, outlen, xlat, vps);
}
