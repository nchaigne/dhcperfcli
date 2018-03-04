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


#define DHCP_PORT_SERVER  67
#define DHCP_PORT_CLIENT  68
#define DHCP_PORT_RELAY   67

#define DHCP_MAX_MESSAGE_TYPE  (16)
// DHCP_MAX_MESSAGE_TYPE is defined in protocols/dhcpv4/base.c, we need our own.

/* DHCP options/fields (which are not defined in protocols/dhcpv4/dhcpv4.h) */
#define FR_DHCP_DHCP_SERVER_IDENTIFIER  54
#define FR_DHCPV4_TRANSACTION_ID        260


#define is_dhcp_code(_x) ((_x > 0) && (_x < DHCP_MAX_MESSAGE_TYPE))


/* Specific states of a session. */
typedef enum {
	DPC_STATE_UNDEFINED = 0,

	DPC_STATE_EXPECT_REPLY,       //!< Expecting reply to a request.
	DPC_STATE_DORA_EXPECT_OFFER,  //!< DORA workflow expecting an Offer reply to the Discover request.
	DPC_STATE_MAX
} dpc_state_t;


typedef struct dpc_input dpc_input_t;
typedef struct dpc_input_list dpc_input_list_t;
typedef struct dpc_session_ctx dpc_session_ctx_t;

/*
 *	Holds input data (vps read from file or stdin).
 */
struct dpc_input {
	uint32_t id;            //!< Id of input (0 for the first one).

	VALUE_PAIR *vps;        //!< List of input value pairs read.

	unsigned int code;      //!< Packet code (type).
	fr_ipaddr_t src_ipaddr; //!< Src IP address of packet.
	fr_ipaddr_t dst_ipaddr; //!< Dst IP address of packet.
	uint16_t src_port;      //!< Src port of packet.
	uint16_t dst_port;      //!< Dst port of packet.

	dpc_input_list_t *list; //!< The list to which this entry belongs (NULL for an unchained entry).

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

/*
 *	Session context.
 */
struct dpc_session_ctx {
	uint32_t id;            //!< Id of session (0 for the first one).

	RADIUS_PACKET *packet;
	RADIUS_PACKET *reply;

	dpc_state_t state;
	bool reply_expected;    //!< Whether a reply is expected or not.
};
