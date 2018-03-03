/**
 * @file dpc_util.c
 * @brief Utility functions
 */

#include "dhcperfcli.h"
#include "dpc_util.h"


/*
 *	Print a log message.
 *	Substitute for fr_printf_log so we can use our own debug level.
 */
void dpc_printf_log(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if ((dpc_debug_lvl == 0) || !fr_log_fp) {
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

	va_start(ap, fmt);
	vfprintf(fr_log_fp, fmt, ap);
	va_end(ap);

	fprintf(fr_log_fp, "\n");
	fflush(fr_log_fp);
}

/*
 *	Print the packet header.
 */
void dpc_packet_header_print(FILE *fp, RADIUS_PACKET *packet, bool received)
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

	fprintf(fp, "%s", received ? "Received" : "Sent");

	if (is_dhcp_code(code)) {
		fprintf(fp, " %s", dhcp_message_types[code]);
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

	fprintf(fp, " Id %u (0x%08x) %s length %zu\n",
	        packet->id, packet->id,
	        dpc_print_packet_from_to(from_to_buf, packet, false),
	        packet->data_len);
}

/*
 *	Print the "fields" (options excluded) of a DHCP packet (from the VPs list).
 */
void dpc_packet_fields_print(FILE *fp, VALUE_PAIR *vp)
{
	fr_cursor_t cursor;

	for (vp = fr_cursor_init(&cursor, &vp); vp; vp = fr_cursor_next(&cursor)) {
		if ((vp->da->vendor == DHCP_MAGIC_VENDOR) && (vp->da->attr >= 256 && vp->da->attr <= 269)) {
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
		if ((vp->da->vendor == DHCP_MAGIC_VENDOR) && !(vp->da->attr >= 256 && vp->da->attr <= 269)) {
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
void dpc_packet_print(FILE *fp, RADIUS_PACKET *packet, bool received)
{
	if (!fp || !packet) return;

	dpc_packet_header_print(fp, packet, received);

	fprintf(fp, "DHCP vps fields:\n");
	dpc_packet_fields_print(fp, packet->vps);

	fprintf(fp, "DHCP vps options:\n");
	if (dpc_packet_options_print(fp, packet->vps) == 0) {
		fprintf(fp, "\t(empty list)\n");
	}
}

/*
 *	Print an ethernet address in a buffer.
 */
char *dpc_ether_addr_print(const uint8_t *addr, char *buf)
{
	sprintf (buf, "%02x:%02x:%02x:%02x:%02x:%02x",
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
	return buf;
}

/*
 *	Print information on a socket from its file descriptor.
 */
int dpc_socket_inspect(FILE *fp, const char *log_pre, int sockfd,
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
 * Convert a float to struct timeval.
 */
void dpc_float_to_timeval(struct timeval *tv, float f_val)
{
	tv->tv_sec = (time_t)f_val;
	tv->tv_usec = (uint64_t)(f_val * USEC) - (tv->tv_sec * USEC);
}
