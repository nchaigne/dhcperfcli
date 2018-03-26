/**
 * @file dpc_util.c
 * @brief Utility functions
 */

#include "dhcperfcli.h"
#include "dpc_util.h"

extern struct timeval tv_start;


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
 *	Peek into an event list to retrieve the timestamp of next event.
 *
 *	Note: structures fr_event_list_t and fr_event_timer_t are opaque, so we have to partially redefine them
 *	so we can access what we need.
 *	(I know, this is dangerous. We'll be fine as long as they do not change.)
 *	Ideally, this should be provided by FreeRADIUS lib. TODO: ask them ?
 */
int fr_event_timer_peek(fr_event_list_t *fr_el, struct timeval *when)
{
	dpc_fr_event_list_t *el = (dpc_fr_event_list_t *)fr_el;
	dpc_fr_event_timer_t *ev;

	if (unlikely(!el)) return 0;

	if (fr_heap_num_elements(el->times) == 0) {
		when->tv_sec = 0;
		when->tv_usec = 0;
		return 0;
	}

	ev = fr_heap_peek(el->times);
	if (!ev) {
		when->tv_sec = 0;
		when->tv_usec = 0;
		return 0;
	}

	*when = ev->when;
	return 1;
}

/*
 *	Print a log message.
 *	Substitute for fr_printf_log so we can use our own debug level.
 */
void dpc_printf_log(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!fr_log_fp) {
		va_end(ap);
		return;
	}

	vfprintf(fr_log_fp, fmt, ap);
	va_end(ap);

	return;
}

/*
 *	"Developer" debug print.
 *	(ref: function fr_proto_print from lib/util/proto.c)
 */
#define DEV_PRINT_BASENAME 1
static unsigned int dev_log_indent = 30;
static char spaces[] = "                                                 ";
void dpc_dev_print(char const *file, int line, char const *fmt, ...)
{
	va_list ap;
	size_t len;
	char prefix[256];
	char const *filename = file;

#ifdef DEV_PRINT_BASENAME
	/* 	file is __FILE__ which is set at build time by gcc.
	 *	e.g. src/modules/proto_dhcpv4/dhcperfcli.c
	 *	Extract the file base name to have leaner traces.
	*/
	char *p = strrchr(file, FR_DIR_SEP);
	if (p) filename = p + 1;
#endif

	len = snprintf(prefix, sizeof(prefix), " )%s:%i", filename, line);
	if (len > dev_log_indent) dev_log_indent = len;

	fprintf(fr_log_fp, "%s%.*s: ", prefix, (int)(dev_log_indent - len), spaces);

	/* Print elapsed time. */
	char time_buf[DPC_TIME_STRLEN];
	fprintf(fr_log_fp, "t(%s) ", dpc_print_delta_time(time_buf, &tv_start, NULL, DPC_DELTA_TIME_DECIMALS));

	va_start(ap, fmt);
	vfprintf(fr_log_fp, fmt, ap);
	va_end(ap);

	fprintf(fr_log_fp, "\n");
	fflush(fr_log_fp);
}

/*
 *	Print a time difference, in format: [[<HH>:]<MI>:]<SS>[.<d{1,6}>]
 *	Hour and minute printed only if relevant, decimals optional.
 *	If when is NULL, now is used instead.
 */
char *dpc_print_delta_time(char *out, struct timeval *from, struct timeval *when, uint8_t decimals)
{
	struct timeval delta, to;
	uint32_t sec, min, hour;

	if (!when) {
		gettimeofday(&to, NULL);
		when = &to;
	}

	timersub(when, from, &delta); /* delta = when - from */

	hour = (uint32_t)(delta.tv_sec / 3600);
	min = (uint32_t)(delta.tv_sec % 3600) / 60;
	sec = (uint32_t)(delta.tv_sec % 3600) % 60;

	if (hour > 0) {
		sprintf(out, "%d:%.02d:%.02d", hour, min, sec);
	} else if (min > 0) {
		sprintf(out, "%d:%.02d", min, sec);
	} else {
		sprintf(out, "%d", sec);
	}

	if (decimals) {
		char buffer[32] = "";
		sprintf(buffer, ".%06ld", delta.tv_usec);
		strncat(out, buffer, decimals + 1); /* (always terminated with '\0'). */
	}

	return out;
}

/*
 *	Print number of each type of message (sent or received).
 */
char *dpc_num_message_type_print(char *out, uint32_t num_packet[])
{
	int i;
	char *p = out;
	size_t len = 0;

	*p = '\0';
	for (i = 1; i < DHCP_MAX_MESSAGE_TYPE; i ++) {
		if (num_packet[i] > 0) {
			if (p != out) {
				len = sprintf(p, ", ");
				p += len;
			}
			len = sprintf(p, "%s: %u", dpc_message_types[i], num_packet[i]);
			p += len;
		}
	}
	return out;
}

/*
 *	Print the packet header.
 */
void dpc_packet_header_print(FILE *fp, dpc_session_ctx_t *session, RADIUS_PACKET *packet, dpc_packet_event_t pevent)
{
	char from_to_buf[DPC_FROM_TO_STRLEN] = "";

	uint32_t yiaddr;
	char lease_ipaddr[128] = "";
	uint8_t hwaddr[6] = "";
	char buf_hwaddr[128] = "";

	if (!fp) return;
	if (!packet) return;

	/* Internally, DHCP packet code starts with an offset of 1024 (hack), so... */
	int code = packet->code - FR_DHCPV4_OFFSET;

	if (session) fprintf(fp, "(%u) ", session->id);

	switch (pevent) {
		case DPC_PACKET_SENT:
			fprintf(fp, "Sent");
			break;
		case DPC_PACKET_RECEIVED:
			fprintf(fp, "Received");
			break;
		case DPC_PACKET_TIMEOUT:
			fprintf(fp, "Timed out");
			break;
	}

	if (is_dhcp_code(code)) {
		fprintf(fp, " %s", dpc_message_types[code]);
	} else {
		fprintf(fp, " DHCP packet");
		if (code <= 0) fprintf(fp, " (BOOTP)"); /* No DHCP Message Type: BOOTP (or malformed DHCP packet). */
		else fprintf(fp, " (code %u)", code);
	}

	/* DHCP specific information. */
	if (packet->data) { // don't crash if called before packet is encoded.
		memcpy(hwaddr, packet->data + 28, sizeof(hwaddr));
		fprintf(fp, " (hwaddr: %s", dpc_ether_addr_print(hwaddr, buf_hwaddr) );

		if (packet->code == FR_DHCPV4_ACK || packet->code == FR_DHCPV4_OFFER) {
			memcpy(&yiaddr, packet->data + 16, 4);
			fprintf(fp, ", yiaddr: %s", inet_ntop(AF_INET, &yiaddr, lease_ipaddr, sizeof(lease_ipaddr)) );
		}
		fprintf(fp, ")");
	}

	fprintf(fp, " Id %u (0x%08x) %s length %zu\n", packet->id, packet->id,
	        dpc_print_packet_from_to(from_to_buf, packet, false), packet->data_len);
}

/*
 *	Print the "fields" (options excluded) of a DHCP packet (from the VPs list).
 */
void dpc_packet_fields_print(FILE *fp, VALUE_PAIR *vp)
{
	fr_cursor_t cursor;

	for (vp = fr_cursor_init(&cursor, &vp); vp; vp = fr_cursor_next(&cursor)) {
		if ((fr_dict_vendor_num_by_da(vp->da) == DHCP_MAGIC_VENDOR) && (vp->da->attr >= 256 && vp->da->attr <= 269)) {
			fr_pair_fprint(fp, vp);
		}
	}
}

/*
 *	Print the "options" of a DHCP packet (from the VPs list).
 */
int dpc_packet_options_print(FILE *fp, VALUE_PAIR *vp)
{
	char buf[1024];
	char *p = buf;
	int num = 0; /* Keep track of how many options we have. */

	fr_cursor_t cursor;
	for (vp = fr_cursor_init(&cursor, &vp); vp; vp = fr_cursor_next(&cursor)) {
		if ((fr_dict_vendor_num_by_da(vp->da) == DHCP_MAGIC_VENDOR) && !(vp->da->attr >= 256 && vp->da->attr <= 269)) {

			num ++;

			p = buf;
			*p++ = '\t';

			if (vp->da->parent && vp->da->parent->type == FR_TYPE_TLV) {
				/* If attribute has a parent which is of type "tlv", print <option.sub-attr> (eg. "82.1"). */
				p += sprintf(p, "(%d.%d) ", vp->da->parent->attr, vp->da->attr);
			} else {
				/* Otherwise this is a simple option. */
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
void dpc_packet_print(FILE *fp, dpc_session_ctx_t *session, RADIUS_PACKET *packet,
                      dpc_packet_event_t pevent, int trace_lvl)
{
	if (!fp || !packet) return;

	if (trace_lvl >= 1) {
		dpc_packet_header_print(fp, session, packet, pevent);
	}

	if (trace_lvl >= 2) {
		fprintf(fp, "DHCP vps fields:\n");
		dpc_packet_fields_print(fp, packet->vps);

		fprintf(fp, "DHCP vps options:\n");
		if (dpc_packet_options_print(fp, packet->vps) == 0) {
			fprintf(fp, "\t(empty list)\n");
		}
	}

	if (trace_lvl >= 3) {
		fprintf(fp, "DHCP hex data:\n");
		dpc_packet_data_print(fp, packet);
	}
}

/*
 *	Print the data of a DHCP packet.
 *	Fields and options are printed in hex, along with their position in the packet.
 *	This allows to see what is exactly in a packet and where.
 */
void dpc_packet_data_print(FILE *fp, RADIUS_PACKET *packet)
{
	uint8_t const *p, *data_end;
	char header[64];
	char buf[1024];
	int i;
	unsigned int cur_pos = 0;
	int pad_size = 0;
	uint8_t const *pad_p = NULL;

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
				dpc_print_hex_data(buf, p, remain, " ", header, 16);
				fprintf(fp, "%s\n", buf);
			}
			return;
		}

		/* One valid field to print. */
		sprintf(header, "  %04x  %10s: ", cur_pos, dpc_dhcp_headers[i].name);
		dpc_print_hex_data(buf, p, dpc_dhcp_headers[i].size, " ", header, 16);
		fprintf(fp, "%s\n", buf);

		p += dpc_dhcp_headers[i].size;
		cur_pos += dpc_dhcp_headers[i].size;
	}

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
			dpc_print_hex_data(buf, pad_p, pad_size, " ", header, 16);
			fprintf(fp, "%s\n", buf);

			cur_pos += pad_size;
			pad_p = NULL;
			pad_size = 0;
		}

		if (*p == 255) { /* End Option. */
			sprintf(header, "  %04x  %10s: ", cur_pos, "end");
			dpc_print_hex_data(buf, p, 1, " ", header, 16);
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
			fprintf(fp, "  incomplete/malformed DHCP data (len: %zu)\n", packet->data_len);
			int remain = packet->data_len - cur_pos;
			if (remain > 0) {
				sprintf(header, "  %04x  %10s: ", cur_pos, "remainder");
				dpc_print_hex_data(buf, p, remain, " ", header, 16);
				fprintf(fp, "%s\n", buf);
			}
			return;
		}

		/* One valid option to print. */
		int opt_size = p[1] + 2;
		sprintf(header, "  %04x  %10d: ", cur_pos, p[0]);
		dpc_print_hex_data(buf, p, opt_size, " ", header, 16);
		fprintf(fp, "%s\n", buf);
		p += opt_size;
		cur_pos += opt_size;
	}

	if (pad_p) { /* There may be more padding after End Option. */
		sprintf(header, "  %04x  %10s: ", cur_pos, "pad");
		dpc_print_hex_data(buf, pad_p, pad_size, " ", header, 16);
		fprintf(fp, "%s\n", buf);
	}
}

/*
 *	Print a data buffer in hexadecimal representation.
 */
char *dpc_print_hex_data(char *out, const uint8_t *in, int in_len, char const *sep,
                         char const *prefix, int line_max_len)
{
	int i;
	int k = 0; /* Position in the current line. */

	int prefix_len = 0;
	if (prefix) {
		prefix_len = strlen(prefix);
		out += sprintf(out, "%s", prefix);
	}

	for (i = 0; i < in_len; i++) {
		if (line_max_len && (k == line_max_len)) { /* Start a new line. */
			out += sprintf(out, "\n%*s", prefix_len, "");
			k = 0;
		}
		if (k && sep) {
			out += sprintf(out, "%s", sep);
		}
		out += sprintf(out, "%02x", in[i]);
		k ++;
	}
	*out = '\0';
	return out;
}

/*
 *	Print an ethernet address in a buffer.
 */
char *dpc_ether_addr_print(const uint8_t *addr, char *buf)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
	        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return buf;
}

/*
 *	Print packet source and destination IP/port.
 *	Caller is responsible for passing an output buffer (buf) with sufficient space (DPC_FROM_TO_STRLEN).
 */
char *dpc_print_packet_from_to(char *buf, RADIUS_PACKET *packet, bool extra)
{
	char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
	char dst_ipaddr_buf[FR_IPADDR_STRLEN] = "";
	char via[5 + IFNAMSIZ] = "";

	fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &packet->src_ipaddr);
	fr_inet_ntop(dst_ipaddr_buf, sizeof(dst_ipaddr_buf), &packet->dst_ipaddr);

	if (!extra) {
		sprintf(buf, "from %s:%u to %s:%u",
		        src_ipaddr_buf, packet->src_port, dst_ipaddr_buf, packet->dst_port
		);
	} else {
		sprintf(buf, "from %s:%u (prefix: %d) to %s:%u (prefix: %d)",
		        src_ipaddr_buf, packet->src_port, packet->src_ipaddr.prefix,
		        dst_ipaddr_buf, packet->dst_port, packet->dst_ipaddr.prefix
		);
	}

#if defined(WITH_IFINDEX_NAME_RESOLUTION)
	if (packet->if_index) {
		char if_name[IFNAMSIZ];
		sprintf(via, " via %s", fr_ifname_from_ifindex(if_name, packet->if_index));
		strcat(buf, via);
	}
#endif

	return buf;
}

/*
 *	Print information on a socket from its file descriptor.
 */
int dpc_socket_inspect(FILE *fp, char const *log_pre, int sockfd,
                       fr_ipaddr_t *src_ipaddr, uint16_t *src_port, fr_ipaddr_t *dst_ipaddr, uint16_t *dst_port)
{
	struct sockaddr_storage salocal;
	socklen_t salen;

	fr_ipaddr_t my_src_ipaddr;
	uint16_t my_src_port;
	fr_ipaddr_t my_dst_ipaddr;
	uint16_t my_dst_port;

	bool dst_notconn = false; /* If the socket is not connected to a peer. */

	char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
	char dst_ipaddr_buf[FR_IPADDR_STRLEN] = "";

	/*
	 *	Return these if the caller cared.
	*/
	if (!src_ipaddr) src_ipaddr = &my_src_ipaddr;
	if (!src_port) src_port = &my_src_port;
	if (!dst_ipaddr) dst_ipaddr = &my_dst_ipaddr;
	if (!dst_port) dst_port = &my_dst_port;

	/*
	 *	Get source information.
	 */
	salen = sizeof(salocal);
	memset(&salocal, 0, salen);
	if (getsockname(sockfd, (struct sockaddr *) &salocal, &salen) < 0) {
		fr_strerror_printf("Failed getting socket name: %s", fr_syserror(errno));
		return -1;
	}

	if (fr_ipaddr_from_sockaddr(&salocal, salen, src_ipaddr, src_port) < 0) {
		ERROR("Failed getting src ipaddr (fr_ipaddr_from_sockaddr)");
		return -1;
	}

	/*
	 *	Get destination information.
	 */
	salen = sizeof(salocal);
	memset(&salocal, 0, salen);
	if (getpeername(sockfd, (struct sockaddr *) &salocal, &salen) < 0) {
		if (errno == ENOTCONN) {
			dst_notconn = true;
		} else {
			ERROR("Failed getting peer name: %s", fr_syserror(errno));
			return -1;
		}
	}

	if (!dst_notconn) {
		if (fr_ipaddr_from_sockaddr(&salocal, salen, dst_ipaddr, dst_port) < 0) {
			ERROR("Failed getting dst ipaddr (fr_ipaddr_from_sockaddr)");
			return -1;
		}
	}

	if (log_pre) fprintf(fp, "%s ", log_pre);
	fprintf(fp, "fd: %d", sockfd);
	fprintf(fp, ", src: %s:%i", fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), src_ipaddr), *src_port);
	if (!dst_notconn) {
		fprintf(fp, ", dst: %s:%i", fr_inet_ntop(dst_ipaddr_buf, sizeof(dst_ipaddr_buf), dst_ipaddr), *dst_port);
	} else {
		fprintf(fp, ", dst: not connected");
	}
	fprintf(fp, "\n");

	return 0;
}

/*
 *	Find the matching DHCP attribute.
 */
VALUE_PAIR *dpc_pair_find_dhcp(VALUE_PAIR *head, unsigned int attr, int8_t tag)
{
	return fr_pair_find_by_num(head, DHCP_MAGIC_VENDOR, attr, tag);
}

/*
 *	Append a list of VP. (inspired from FreeRADIUS's fr_pair_list_copy.)
 */
VALUE_PAIR *dpc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from)
{
	vp_cursor_t src, dst;

	if (NULL == *to) { // fall back to fr_pair_list_copy for a new list.
		*to = fr_pair_list_copy(ctx, from);
		return (*to);
	}

	VALUE_PAIR *out = *to, *vp;

	fr_pair_cursor_init(&dst, &out);
	for (vp = fr_pair_cursor_init(&src, &from);
	     vp;
	     vp = fr_pair_cursor_next(&src)) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&out);
			return NULL;
		}
		fr_pair_cursor_append(&dst, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	return *to;
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
		fr_pair_value_memsteal(vp, buff);
		break;
	}

	case FR_TYPE_IPV4_ADDR:
		vp->vp_ipv4addr = htonl(ntohl(vp->vp_ipv4addr) + 1);
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
		fr_pair_value_memsteal(vp, buff);
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
 *	Convert a float to struct timeval.
 */
void dpc_float_to_timeval(struct timeval *tv, float in)
{
	tv->tv_sec = (time_t)in;
	tv->tv_usec = (uint64_t)(in * USEC) - (tv->tv_sec * USEC);
}

/*
 *	Convert a struct timeval to float.
 */
float dpc_timeval_to_float(struct timeval *in)
{
	float value = (in->tv_sec + (float)in->tv_usec / USEC);
	return value;
}

/*
 *	Check that a string represents a valid positive floating point number (e.g. 3, 2.5, .542).
 *	If so convert it to float.
 *	Note: not using strtof because we want to be more restrictive.
 */
bool dpc_str_to_float(float *out, char const *in)
{
	if (!in || strlen(in) == 0) return false;

	char const *p = in;
	while (*p != '\0') {
		if (isdigit(*p)) {
			p ++;
			continue;
		}
		if (*p == '.') {
			p ++;
			if (*p == '\0') return false; /* Do not allow a dot without any following digit. */
			break;
		}
		return false; /* Not a digit or dot. */
	}

	while (*p != '\0') { /* Everything after the dot must be a digit. */
		if (!isdigit(*p)) return false;
		p ++;
	}

	/* Format is correct. */
	if (out) {
		*out = atof(in);
	}
	return true;
}

/*
 *	Check that a string represents either an integer or a valid hex string.
 *	If so convert it to uint32.
 */
bool dpc_str_to_uint32(uint32_t *out, char const *in)
{
	uint64_t uinteger = 0;
	char *p = NULL;

	if (!in || in[0] == '\0') return false;

	uinteger = fr_strtoull(in, &p); /* Allows integer or hex string. */
	if (*p != '\0' || uinteger > UINT32_MAX) return false;

	*out = (uint32_t) uinteger;
	return true;
}

/*
 *	Trim a string from spaces (left and right).
 *	(Note: this alters the original string in case of right triming.)
 */
char *dpc_str_trim(char *str)
{
	char *p = str;
	char *end = str + strlen(p) - 1;
	while (isspace(*p)) p ++;
	while (end > p && isspace(*end)) *end-- = '\0';
	return p;
}

/*
 *	Add an allocated input entry to the tail of the list.
 */
void dpc_input_item_add(dpc_input_list_t *list, dpc_input_t *entry)
{
	if (!list || !entry) return;

	if (!list->head) {
		assert(list->tail == NULL);
		list->head = entry;
		entry->prev = NULL;
	} else {
		assert(list->tail != NULL);
		assert(list->tail->next == NULL);
		list->tail->next = entry;
		entry->prev = list->tail;
	}
	list->tail = entry;
	entry->next = NULL;
	entry->list = list;
	list->size ++;
}

/*
 *	Remove an input entry from its list.
 */
dpc_input_t *dpc_input_item_draw(dpc_input_t *entry)
{
	if (!entry) return NULL; // should not happen.
	if (!entry->list) return entry; // not in a list: just return the entry.

	dpc_input_t *prev, *next;

	prev = entry->prev;
	next = entry->next;

	dpc_input_list_t *list = entry->list;

	assert(list->head != NULL); // entry belongs to a list, so the list can't be empty.
	assert(list->tail != NULL); // same.

	if (prev) {
		assert(list->head != entry); // if entry has a prev, then entry can't be head.
		prev->next = next;
	}
	else {
		assert(list->head == entry); // if entry has no prev, then entry must be head.
		list->head = next;
	}

	if (next) {
		assert(list->tail != entry); // if entry has a next, then entry can't be tail.
		next->prev = prev;
	}
	else {
		assert(list->tail == entry); // if entry has no next, then entry must be tail.
		list->tail = prev;
	}

	entry->list = NULL;
	entry->prev = NULL;
	entry->next = NULL;
	list->size --;
	return entry;
}

/*
 *	Get the head input entry from a list.
 */
dpc_input_t *dpc_get_input_list_head(dpc_input_list_t *list)
{
	if (!list) return NULL;
	if (!list->head || list->size == 0) { // list is empty.
		return NULL;
	}
	// list is valid and has at least one element.
	return dpc_input_item_draw(list->head);
}

/*
 *	Peek at stdin (fd 0) to see if it has input.
 */
bool dpc_stdin_peek()
{
	fd_set set;
	int max_fd = 1;
	struct timeval tv;

	FD_ZERO(&set);
	FD_SET(0, &set);
	timerclear(&tv);

	if (select(max_fd, &set, NULL, NULL, &tv) <= 0) {
		return false;
	}

	return true;
}

/*
 *	Determine if an IP address is the broadcast address.
 *	Returns: 0 if it is not, 1 if it is, 0 on error.
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
