/*
 * dhcperfcli.h
 */

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/io/time.h>

#include <assert.h>


/*
 *	Trace / logging.
 */
extern int dpc_debug_lvl;

#undef DEBUG
#define DEBUG(fmt, ...)		if (fr_log_fp && (dpc_debug_lvl > 0)) dpc_printf_log(fmt "\n", ## __VA_ARGS__)

#undef DEBUG2
#define DEBUG2(fmt, ...)	if (fr_log_fp && (dpc_debug_lvl > 1)) dpc_printf_log(fmt "\n", ## __VA_ARGS__)

#undef WARN
#define WARN(fmt, ...)		fr_perror("Warning: " fmt, ## __VA_ARGS__)

#undef ERROR
#define ERROR(fmt, ...)		fr_perror("ERROR: " fmt, ## __VA_ARGS__)

/* Reuse of nifty FreeRADIUS functions in util/proto.c */
#ifndef NDEBUG
#  define DPC_DEBUG_TRACE(_x, ...)	if (fr_log_fp && (dpc_debug_lvl > 3)) dpc_dev_print(__FILE__, __LINE__, _x, ## __VA_ARGS__)
#  define DPC_DEBUG_HEX_DUMP(_x, _y, _z)	if (fr_log_fp && (dpc_debug_lvl > 3)) fr_proto_print_hex_data(__FILE__, __LINE__, _x, _y, _z)
#else
#  define DPC_DEBUG_TRACE(_x, ...)
#  define DPC_DEBUG_HEX_DUMP(_x, _y, _z)
#endif


#define DHCP_PORT_SERVER	67
#define DHCP_MAX_MESSAGE_TYPE (16)
// DHCP_MAX_MESSAGE_TYPE is defined in src/protocols/dhcpv4/base.c, we need our own.

#define is_dhcp_code(_x) ((_x > 0) && (_x < DHCP_MAX_MESSAGE_TYPE))


typedef struct dpc_input dpc_input_t;
typedef struct dpc_input_list dpc_input_list_t;

/*
 *	Holds input data (vps read from file or stdin).
 */
struct dpc_input {
	VALUE_PAIR *vps;

	dpc_input_list_t *list; // the list to which this entry belongs (NULL for an unchained entry).

	dpc_input_t *prev;
	dpc_input_t *next;
};

/*
 *	Chained list of input data elements.
 */
struct dpc_input_list {
	dpc_input_t *head;
	dpc_input_t *tail;
	uint32_t size;
};
