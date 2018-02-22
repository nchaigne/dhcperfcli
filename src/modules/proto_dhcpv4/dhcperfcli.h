/*
 * dhcperfcli.h
 */

#include <freeradius-devel/libradius.h>
#include <freeradius-devel/event.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>
#include <freeradius-devel/io/time.h>

#include <assert.h>



#undef DEBUG
#define DEBUG(fmt, ...)		if (fr_debug_lvl > 0) fr_printf_log(fmt "\n", ## __VA_ARGS__)

#undef DEBUG2
#define DEBUG2(fmt, ...)	if (fr_debug_lvl > 1) fr_printf_log(fmt "\n", ## __VA_ARGS__)

#undef ERROR
#define ERROR(fmt, ...)		fr_perror("ERROR: " fmt, ## __VA_ARGS__)


#define DHCP_PORT_SERVER	67


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
