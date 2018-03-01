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
