#pragma once
/*
 * dhcperfcli.h
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

#include <assert.h>
#include <libgen.h>

#include "ncc_util.h"


typedef struct dpc_context dpc_context_t;

extern dpc_context_t exe_ctx;
#define ECTX exe_ctx

/*
 *	Execution context.
 *	Holds global parameters set at initialization stage.
 */
struct dpc_context {
	int debug_lvl;

	int talloc_memory_report;        //!< On exit, print a memory report on what's left unfreed.

	float request_timeout;           //<! Max time waiting for a reply to a request we've sent.
	struct timeval tvi_request_timeout;

	float progress_interval;         //<! Time interval between periodic progress statistics.
	struct timeval tvi_progress_interval;

	uint32_t base_xid;               //<! Base value for xid generated in DHCP packets.

	float duration_start_max;        //<! Limit duration for starting new input sessions.
	struct timeval tve_start_max;    //<! Time after which no input session is allowed to be started.

	uint32_t session_max_num;        //<! Limit number of sessions initialized from input items.
	uint32_t session_max_active;     //<! Max number of session packets sent concurrently (default: 1).

	float rate_limit;                //<! Limit rate/s of sessions initialized from input (all transactions combined).

	uint32_t min_session_for_rps;    //<! Min number of sessions started from input to compute a session rate per second.
	float min_session_time_for_rps;  //<! Min elapsed time to compute a session rate per second.
	float min_ref_time_rate_limit;   //<! Min reference time considered for rate limit.
	float rate_limit_time_lookahead; //<! Time lookahead for rate limit enforcement, to factor in processing time.
};


/*	We don't do RADIUS, but reuse the same structure for DHCP.
 *	(cf. lib/util/packet.h)
 */
#define DHCP_PACKET RADIUS_PACKET


/*
 *	Assuming an upper rate of 20 000 packets sent per second, constant over a period of time.
 *	With a uint32_t we can store up to (2^32-1) / 20 000 = ~ 60H of traffic.
 *	We might want to move to uint64_t for counting packets. TODO.
 */


extern int dpc_debug_lvl;
extern fr_dict_attr_t const *attr_encoded_data;
extern fr_dict_attr_t const *attr_dhcp_message_type;

extern fr_dict_t *dict_dhcpv4; /* Defined in src/protocols/dhcpv4/base.c */


#define dpc_assert rad_assert
/*
 *	Using rad_assert defined in include/rad_assert.h
 *
 *	assert output:
 *	dhcperfcli: src/modules/proto_dhcpv4/dpc_packet_list.c:601: dpc_packet_list_recv: Assertion `pl != ((void *)0)' failed.
 *
 *	rad_assert output:
 *	ASSERT FAILED src/modules/proto_dhcpv4/dpc_packet_list.c[601]: pl != NULL
 */


/*
 *	Trace / logging.
 */

/*
	Note: FreeRADIUS logs macros are defined in src/lib/server/log.h

	Sample output:

	Fri Apr  5 10:00:44 2019 : Debug : DEBUG test
	Fri Apr  5 10:00:44 2019 : Info  : INFO test
	Fri Apr  5 10:00:44 2019 : Warn  : WARN test
	Fri Apr  5 10:00:44 2019 : Error : ERROR test
	Fri Apr  5 10:01:59 2019 : Warn  : PWARN test: fr_strerror_printf
	Fri Apr  5 10:01:59 2019 : Error : PERROR test: fr_strerror_printf

	We'll redefine our own, so we get exactly what we want.

	We don't support the push/pop mechanism of FreeRADIUS which allows to have multiple error messages
	logged in a single call of PERROR (cf. fr_strerror_printf_push / fr_log_perror).
*/
#undef DEBUG
#define DEBUG(_f, ...)  NCC_DEBUG(1, _f, ## __VA_ARGS__)

#undef DEBUG2
#define DEBUG2(_f, ...)  NCC_DEBUG(2, _f, ## __VA_ARGS__)

#undef DEBUG3
#define DEBUG3(_f, ...) NCC_DEBUG(3, _f, ## __VA_ARGS__)

#undef DEBUG4
#define DEBUG4(_f, ...) NCC_DEBUG(4, _f, ## __VA_ARGS__)

#undef INFO
#define INFO(_f, ...) NCC_LOG("Info : " _f, ## __VA_ARGS__)

#undef WARN
#define WARN(_f, ...) NCC_LOG("Warn : " _f, ## __VA_ARGS__)

#undef ERROR
#define ERROR(_f, ...) NCC_LOG("Error : " _f, ## __VA_ARGS__)

#undef PWARN
#define PWARN(_f, ...) NCC_LOG("Warn : " _f ": %s", ## __VA_ARGS__, fr_strerror())

#undef PERROR
#define PERROR(_f, ...) NCC_LOG("Error : " _f ": %s", ## __VA_ARGS__, fr_strerror())

/* Trace macros with prefixed session id. */
#define DPC_SDEBUG(_p, _f, ...) if (NCC_DEBUG_ENABLED(_p)) NCC_LOG("(%u) " _f, session->id, ## __VA_ARGS__)

#define SDEBUG(_f, ...)  DPC_SDEBUG(1, _f, ## __VA_ARGS__)
#define SDEBUG2(_f, ...) DPC_SDEBUG(2, _f, ## __VA_ARGS__)
#define SERROR(_f, ...)  if (NCC_LOG_ENABLED) NCC_LOG("(%u) Error : " _f, session->id, ## __VA_ARGS__)
#define SPERROR(_f, ...) if (NCC_LOG_ENABLED) NCC_LOG("(%u) Error : " _f ": %s", session->id, ## __VA_ARGS__, fr_strerror())

#define SWARN(_f, ...)  if (NCC_LOG_ENABLED) NCC_LOG("(%u) Warn : " _f, session->id, ## __VA_ARGS__)
#define SPWARN(_f, ...) if (NCC_LOG_ENABLED) NCC_LOG("(%u) Warn : " _f ": %s", session->id, ## __VA_ARGS__, fr_strerror())

/* Reuse of nifty FreeRADIUS functions in util/proto.c */
#define DPC_DEBUG_TRACE(_f, ...)         NCC_DEBUG(3, _f, ## __VA_ARGS__)

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
#define is_dhcp_message(_x) ((_x > 0) && (_x < DHCP_MAX_MESSAGE_TYPE))

#define is_dhcp_reply_expected(_x) (_x == FR_DHCP_DISCOVER || _x == FR_DHCP_REQUEST || _x == FR_DHCP_INFORM \
	|| _x == FR_DHCP_LEASE_QUERY)
/*
 *	Decline, Release: these messages do not get a reply.
 *	Inform: "The servers SHOULD unicast the DHCPACK reply to the address given in the 'ciaddr' field of the DHCPINFORM
 *	message." (RFC 2131). This means we'll only get the reply if setting ciaddr to address we've used as source.
*/


#define vp_is_dhcp_attr(_vp) (_vp && (fr_dict_by_da(_vp->da) == dict_dhcpv4))

#define vp_is_dhcp_field(_vp) vp_is_dhcp_attr(_vp) && (_vp->da->attr >= 256 && _vp->da->attr <= 269)

#define vp_is_dhcp_option(_vp) vp_is_dhcp_attr(_vp) && (_vp->da->attr <= 255)

#define vp_is_dhcp_sub_option(_vp) vp_is_dhcp_attr(_vp) && (_vp->da->parent && _vp->da->parent->type == FR_TYPE_TLV && _vp->da->parent->parent)
// attribute is a DHCP sub-option if it has a parent of type "tlv", which has also a parent (the protocol itself).


/*
 *	Statistics update.
 */
#define STAT_INCR_PACKET_SENT(_packet_code) \
{ \
	stat_ctx.num_packet_sent[0] ++; \
	if (is_dhcp_message(_packet_code)) stat_ctx.num_packet_sent[_packet_code] ++; \
}
#define STAT_INCR_PACKET_RECV(_packet_code) \
{ \
	stat_ctx.num_packet_recv[0] ++; \
	if (is_dhcp_message(_packet_code)) stat_ctx.num_packet_recv[_packet_code] ++; \
}
#define STAT_INCR_PACKET_LOST(_packet_code) \
{ \
	stat_ctx.num_packet_lost[0] ++; \
	if (is_dhcp_message(_packet_code)) stat_ctx.num_packet_lost[_packet_code] ++; \
}

#define STAT_ALL_LOST (stat_ctx.num_packet_lost[0])


/* Specific states of a session. */
typedef enum {
	DPC_STATE_UNDEFINED = 0,
	DPC_STATE_NO_REPLY,             //!< No reply is expected to the request.
	DPC_STATE_EXPECT_REPLY,         //!< Expecting any reply to a request.
	DPC_STATE_WAIT_OTHER_REPLIES,   //!< Waiting for possible other replies to a broadcast Discover.
	DPC_STATE_DORA_EXPECT_OFFER,    //!< DORA workflow expecting an Offer reply to the Discover.
	DPC_STATE_DORA_EXPECT_ACK,      //!< DORA workflow expecting an Ack reply to the Request.
	DPC_STATE_MAX
} dpc_state_t;

/* DHCP workflows. */
typedef enum {
	DPC_WORKFLOW_NONE = 0,     //<! Any packet - reply (unless none expected).
	DPC_WORKFLOW_DORA,         //<! Discover - Offer, Request - Ack.
	DPC_WORKFLOW_DORA_DECLINE, //<! DORA followed by Decline.
	DPC_WORKFLOW_DORA_RELEASE, //<! DORA followed by an immediate Release.
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
	DPC_PACKET_RECEIVED_DISCARD,
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


typedef struct dpc_input dpc_input_t;
typedef struct dpc_session_ctx dpc_session_ctx_t;

/*
 *	Pre-parsed input information.
 */
typedef struct dpc_input_ext {
	unsigned int code;       //!< Packet code (type).
	unsigned int workflow;   //!< Workflow (if handling one).
	uint32_t xid;            //!< Prefered value for xid.

	ncc_endpoint_t src;      //!< Src IP address and port.
	ncc_endpoint_t dst;      //!< Dst IP address and port.
	bool with_pcap;          //!< If using a pcap socket (no src IP, dst = broadcast, and pcap is available).
} dpc_input_ext_t;

/*
 *	Holds input data (vps read from file or stdin).
 */
struct dpc_input {
	/* Generic chaining */
	ncc_list_t *list;        //!< The list to which this entry belongs (NULL for an unchained entry).
	ncc_list_item_t *prev;
	ncc_list_item_t *next;

	/* Specific item data */
	uint32_t id;              //!< Id of input (0 for the first one).
	uint32_t num_use;         //!< How many times has this input been used.

	VALUE_PAIR *vps;          //!< List of input value pairs read.

	bool do_xlat;             //<! If the input contain vp's of type VT_XLAT and we handle xlat expansion.

	struct timeval tve_start; //!< Timestamp of first use.
	struct timeval tve_end;   //!< Timestamp of last use once input is done.

	uint32_t max_use;         //<! Maximum number of times this input can be used.
	float max_duration;       //!< Maximum duration of starting sessions with this input (relative to input start use).
	struct timeval tve_max_start; //!< tve_start + max_duration

	bool done;                //!< Is this input done ? (i.e. no session can be started from it)

	dpc_input_ext_t ext;      //!< Input pre-parsed information.
};

/*
 *	Session context.
 */
struct dpc_session_ctx {
	uint32_t id;              //!< Id of session (0 for the first one).

	dpc_input_t *input;       //!< Input data.
	struct timeval tve_start; //<! Session start timestamp.

	ncc_endpoint_t *gateway;  //!< If using a gateway as source endpoint.
	ncc_endpoint_t src;       //!< Src IP address and port.
	ncc_endpoint_t dst;       //!< Dst IP address and port.

	DHCP_PACKET *request;
	DHCP_PACKET *reply;

	uint32_t num_send;        //<! Number of requests sent (not including retransmissions).

	dpc_state_t state;
	bool reply_expected;      //!< Whether a reply is expected or not.

	fr_event_timer_t const *event; //<! Armed timer event (if any).
};
