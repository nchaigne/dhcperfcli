/*
 * dhcperfcli.h
 */

#ifndef _DHCPERFCLI_H
#define _DHCPERFCLI_H

#include <freeradius-devel/radiusd.h>
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

// INFO, WARN, ERROR and PERROR defined in log.h should be sufficient (for now at least)
/*
#undef WARN
#define WARN(fmt, ...)		fr_perror("Warning: " fmt, ## __VA_ARGS__)

#undef ERROR
#define ERROR(fmt, ...)		fr_perror("ERROR: " fmt, ## __VA_ARGS__)
*/

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
#define FR_DHCPV4_REQUESTED_IP_ADDRESS    50
#define FR_DHCPV4_DHCP_SERVER_IDENTIFIER  54
#define FR_DHCPV4_HOP_COUNT               259
#define FR_DHCPV4_TRANSACTION_ID          260
#define FR_DHCPV4_GATEWAY_IP_ADDRESS      266


#define is_dhcp_code(_x) ((_x > 0) && (_x < DHCP_MAX_MESSAGE_TYPE))


/*
 *	Statistics update.
 */
#define STAT_INCR_PACKET_SENT(packet_code) \
{ \
	int code = packet_code - FR_DHCPV4_OFFSET; \
	if (is_dhcp_code(code)) { \
		stat_ctx.num_packet_sent[code] ++; \
		stat_ctx.num_packet_sent[0] ++; \
	} \
}
#define STAT_INCR_PACKET_RECV(packet_code) \
{ \
	int code = packet_code - FR_DHCPV4_OFFSET; \
	if (is_dhcp_code(code)) { \
		stat_ctx.num_packet_recv[code] ++; \
		stat_ctx.num_packet_recv[0] ++; \
	} \
}


/* Specific states of a session. */
typedef enum {
	DPC_STATE_UNDEFINED = 0,
	DPC_STATE_NO_REPLY,           //!< No reply is expected to the request.
	DPC_STATE_EXPECT_REPLY,       //!< Expecting any reply to a request.
	DPC_STATE_DORA_EXPECT_OFFER,  //!< DORA workflow expecting an Offer reply to the Discover.
	DPC_STATE_DORA_EXPECT_ACK,    //!< DORA workflow expecting an Ack reply to the Request.
	DPC_STATE_MAX
} dpc_state_t;

/* DHCP workflows. */
typedef enum {
	DPC_WORKFLOW_NONE = 0,  //<! Any packet - reply (unless none expected).
	DPC_WORKFLOW_DORA,      //<! Discover - Offer, Request - Ack.
	DPC_WORKFLOW_MAX
} dpc_workflow_type_t;

/* Transactions (request / reply, or workflow). */
typedef enum {
	DPC_TR_ALL = 0,         //<! All unitary packet - reply transactions (DORA not included)
	DPC_TR_DISCOVER_OFFER,  //<! Discover - Offer
	DPC_TR_REQUEST_ACK,     //<! Request - Ack
	DPC_TR_REQUEST_NAK,     //<! Request - Nak
	DPC_TR_DORA,            //<! Discover - Offer, Request - Ack (a.k.a "DORA")
	DPC_TR_MAX
} dpc_transaction_type_t;

/* Packet events. */
typedef enum {
	DPC_PACKET_SENT = 1,
	DPC_PACKET_RECEIVED,
	DPC_PACKET_TIMEOUT
} dpc_packet_event_t;


/*
 *	Holds statistics for a given transaction type.
 */
typedef struct dpc_transaction_stats {
	uint32_t       num;       //!< Number of completed transactions
	struct timeval rtt_cumul; //!< Cumulated rtt (request to reply time)
	struct timeval rtt_min;   //!< Lowest rtt
	struct timeval rtt_max;   //!< Highest rtt (timeout are not included)
} dpc_transaction_stats_t;

/*
 *	All statistics.
 */
typedef struct dpc_statistics {
	/*
	 *	Statistics per transaction or workflow type.
	 *	Note: entry "All" aggregates all unitary transactions (i.e. DORA workflow not included).
	 */
	dpc_transaction_stats_t tr_stats[DPC_TR_MAX];

	uint32_t num_packet_sent[DHCP_MAX_MESSAGE_TYPE];
	uint32_t num_packet_lost[DHCP_MAX_MESSAGE_TYPE];
	uint32_t num_packet_recv[DHCP_MAX_MESSAGE_TYPE];

} dpc_statistics_t;


/* Endpoint: IP address and port. */
typedef struct dpc_endpoint {
	fr_ipaddr_t ipaddr;
	uint16_t port;
} dpc_endpoint_t;

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
	unsigned int workflow;  //!< Workflow (if handling one).
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
	uint32_t id;             //!< Id of session (0 for the first one).

	dpc_input_t *input;      //!< Input data.
	struct timeval tv_start; //<! Session start timestamp.

	RADIUS_PACKET *packet;
	RADIUS_PACKET *reply;

	dpc_state_t state;
	bool reply_expected;     //!< Whether a reply is expected or not.

	fr_event_timer_t const *event; //<! armed timer event (if any).
};

#endif
