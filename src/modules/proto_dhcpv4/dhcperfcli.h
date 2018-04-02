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
 *	Assuming an upper rate of 20 000 packets sent per second, constant over a period of time.
 *	With a uint32_t we can store up to (2^32-1) / 20 000 = ~ 60H of traffic.
 *	We might want to move to uint64_t for counting packets. TODO.
 */


extern int dpc_debug_lvl;
extern fr_dict_attr_t const *da_encoded_data;

/*
 *	Trace / logging.
 */
#define DPC_DEBUG_ENABLED(_p) (fr_log_fp && dpc_debug_lvl >= _p)
#define DPC_DEBUG(_p, _f, ...) if (DPC_DEBUG_ENABLED(_p)) dpc_printf_log(_f "\n", ## __VA_ARGS__)

#undef DEBUG
#define DEBUG(fmt, ...)  DPC_DEBUG(1, fmt, ## __VA_ARGS__)

#undef DEBUG2
#define DEBUG2(fmt, ...) DPC_DEBUG(2, fmt, ## __VA_ARGS__)

// INFO, WARN, ERROR and PERROR defined in log.h should be sufficient (for now at least)
/*
#undef WARN
#define WARN(fmt, ...)		fr_perror("Warning: " fmt, ## __VA_ARGS__)

#undef ERROR
#define ERROR(fmt, ...)		fr_perror("ERROR: " fmt, ## __VA_ARGS__)
*/

/* Trace macros with prefixed session id. */
#define DPC_SDEBUG(_p, _f, ...) if (DPC_DEBUG_ENABLED(_p)) dpc_printf_log("(%u) " _f "\n", session->id, ## __VA_ARGS__)

#define SDEBUG(fmt, ...)  DPC_SDEBUG(1, fmt, ## __VA_ARGS__)
#define SDEBUG2(fmt, ...) DPC_SDEBUG(2, fmt, ## __VA_ARGS__)
#define SERROR(fmt, ...)  if (fr_log_fp) dpc_printf_log("(%u) Error : " fmt "\n", session->id, ## __VA_ARGS__)
#define SPERROR(fmt, ...) if (fr_log_fp) fr_perror("(%u) Error : " fmt, session->id, ## __VA_ARGS__)

/* Reuse of nifty FreeRADIUS functions in util/proto.c */
#define DPC_DEBUG_TRACE(_x, ...)       if (DPC_DEBUG_ENABLED(4)) dpc_dev_print(__FILE__, __LINE__, _x, ## __VA_ARGS__)
#define DPC_DEBUG_HEX_DUMP(_x, _y, _z) if (DPC_DEBUG_ENABLED(4)) fr_proto_print_hex_data(__FILE__, __LINE__, _x, _y, _z)
/*
 *	Note: we want these even if not built with --enable-developer. This option has a daunting performance cost.
 *	With it we can do only about ~5k req/s (Discover - Offer). In non developer mode we can go up to ~10k req/s.
 *	Moreover, at this rate the limiting factor is the DHCP server: we're only using about 35% of our own CPU
 *	(on my test system), so we could potentially go much higher.
 */


#define DHCP_PORT_SERVER  67
#define DHCP_PORT_CLIENT  68
#define DHCP_PORT_RELAY   67

#define DHCP_MAX_MESSAGE_TYPE  (16)
// DHCP_MAX_MESSAGE_TYPE is defined in protocols/dhcpv4/base.c, we need our own.
extern char const *dpc_message_types[DHCP_MAX_MESSAGE_TYPE];
#define is_dhcp_code(_x) ((_x > 0) && (_x < DHCP_MAX_MESSAGE_TYPE))

#define is_dhcp_reply_expected(_x) (_x == FR_DHCP_DISCOVER || _x == FR_DHCP_REQUEST || _x == FR_DHCP_INFORM \
	|| _x == FR_DHCP_LEASE_QUERY)
/*
 *	Decline, Release: these messages do not get a reply.
 *	Inform: "The servers SHOULD unicast the DHCPACK reply to the address given in the 'ciaddr' field of the DHCPINFORM
 *	message." (RFC 2131). This means we'll only get the reply if setting ciaddr to address we've used as source.
*/


#define ipaddr_defined(_x) (_x.af != AF_UNSPEC)


/*
 *	Statistics update.
 */
#define STAT_INCR_PACKET_SENT(packet_code) \
{ \
	int code = packet_code - FR_DHCP_OFFSET; \
	stat_ctx.num_packet_sent[0] ++; \
	if (is_dhcp_code(code)) stat_ctx.num_packet_sent[code] ++; \
}
#define STAT_INCR_PACKET_RECV(packet_code) \
{ \
	int code = packet_code - FR_DHCP_OFFSET; \
	stat_ctx.num_packet_recv[0] ++; \
	if (is_dhcp_code(code)) stat_ctx.num_packet_recv[code] ++; \
}
#define STAT_INCR_PACKET_LOST(packet_code) \
{ \
	int code = packet_code - FR_DHCP_OFFSET; \
	stat_ctx.num_packet_lost[0] ++; \
	if (is_dhcp_code(code)) stat_ctx.num_packet_lost[code] ++; \
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
	DPC_TR_ALL = 0,                //<! All unitary packet - reply transactions (DORA not included)
	DPC_TR_DISCOVER_OFFER,         //<! Discover - Offer
	DPC_TR_DISCOVER_ACK,           //<! Discover - Ack (Rapid Commit - cf. RFC 4039)
	DPC_TR_REQUEST_ACK,            //<! Request - Ack
	DPC_TR_REQUEST_NAK,            //<! Request - Nak
	DPC_TR_LEASE_QUERY_UNASSIGNED, //<! Lease-Query - Lease-Query-Unassigned
	DPC_TR_LEASE_QUERY_UNKNOWN,    //<! Lease-Query - Lease-Query-Unknown
	DPC_TR_LEASE_QUERY_ACTIVE,     //<! Lease-Query - Lease-Query-Active
	DPC_TR_DORA,                   //<! Discover - Offer, Request - Ack (a.k.a "DORA")
	DPC_TR_MAX
} dpc_transaction_type_t;

/* Packet events. */
typedef enum {
	DPC_PACKET_SENT = 1,
	DPC_PACKET_RECEIVED,
	DPC_PACKET_TIMEOUT
} dpc_packet_event_t;

/* Template variable update mode. */
typedef enum {
	DPC_TEMPL_VAR_NONE = 0,
	DPC_TEMPL_VAR_INCREMENT,
	DPC_TEMPL_VAR_RANDOM
} dpc_templ_var_t;


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

	uint32_t num_packet_recv_unexpected;

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
	uint32_t id;             //!< Id of input (0 for the first one).

	VALUE_PAIR *vps;         //!< List of input value pairs read.

	unsigned int code;       //!< Packet code (type).
	unsigned int workflow;   //!< Workflow (if handling one).
	uint32_t xid;            //!< Prefered value for xid.

	dpc_endpoint_t src;      //!< Src IP address and port.
	dpc_endpoint_t dst;      //!< Dst IP address and port.
	dpc_endpoint_t *gateway; //!< If using a gateway as source endpoint.
	bool with_pcap;          //!< If using a pcap socket (no src IP, dst = broadcast, and pcap is available).

	dpc_input_list_t *list;  //!< The list to which this entry belongs (NULL for an unchained entry).

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

	fr_event_timer_t const *event; //<! Armed timer event (if any).
};

#endif
