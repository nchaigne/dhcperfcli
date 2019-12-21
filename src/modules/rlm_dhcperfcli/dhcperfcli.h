#pragma once
/*
 * dhcperfcli.h
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/dhcpv4/dhcpv4.h>

#include <assert.h>
#include <libgen.h>

#include "ncc_util.h"
#include "ncc_segment.h"


typedef struct dpc_context dpc_context_t;

extern dpc_context_t exe_ctx;
#define ECTX exe_ctx

/*
 *	Execution context.
 *	Holds global parameters set at initialization stage.
 */
struct dpc_context {
	uint32_t min_session_for_rps;     //<! Min number of sessions started from input to compute a session rate per second.
	double min_session_time_for_rps;  //<! Min elapsed time to compute a session rate per second.
	double min_ref_time_rate_limit;   //<! Min reference time considered for rate limit.
	double rate_limit_time_lookahead; //<! Time lookahead for rate limit enforcement, to factor in processing time.
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
extern fr_time_t fte_start;
extern ncc_dlist_t input_list;
extern fr_dict_attr_t const *attr_encoded_data;
extern fr_dict_attr_t const *attr_dhcp_message_type;
extern fr_dict_attr_t const *attr_dhcp_requested_ip_address;

extern fr_dict_t *dict_dhcpv4; /* Defined in src/protocols/dhcpv4/base.c */


/*
 *	Trace / logging.
 */

/* Trace macros with prefixed session id. */
#define DPC_SDEBUG(_p, _f, ...) if (NCC_DEBUG_ENABLED(_p)) NCC_LOG(0, "(%u) " _f, session->id, ## __VA_ARGS__)

#define SDEBUG(_f, ...)  DPC_SDEBUG(1, _f, ## __VA_ARGS__)
#define SDEBUG2(_f, ...) DPC_SDEBUG(2, _f, ## __VA_ARGS__)
#define SERROR(_f, ...)  if (NCC_LOG_ENABLED) NCC_LOG(0, "(%u) Error : " _f, session->id, ## __VA_ARGS__)
#define SPERROR(_f, ...) if (NCC_LOG_ENABLED) NCC_LOG(0, "(%u) Error : " _f ": %s", session->id, ## __VA_ARGS__, fr_strerror())

#define SWARN(_f, ...)  if (NCC_LOG_ENABLED) NCC_LOG(0, "(%u) Warn : " _f, session->id, ## __VA_ARGS__)
#define SPWARN(_f, ...) if (NCC_LOG_ENABLED) NCC_LOG(0, "(%u) Warn : " _f ": %s", session->id, ## __VA_ARGS__, fr_strerror())


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

#define DPC_PACKET_ID_UNASSIGNED (-1)



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

/* Packet statistics. */
typedef enum {
	DPC_STAT_PACKET_SENT = 0,  //<! Packets sent (not including retransmissions)
	DPC_STAT_PACKET_RETR = 1,  //<! Packets retransmitted
	DPC_STAT_PACKET_LOST = 2,  //<! Packets lost (no reply received before timeout + all retransmissions)
	DPC_STAT_PACKET_RECV = 3,  //<! Packets (replies) received

	DPC_STAT_MAX_TYPE = DPC_STAT_PACKET_RECV
} dpc_packet_stat_field_t;

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
	uint32_t num;              //!< Number of completed transactions
	fr_time_delta_t rtt_cumul; //!< Cumulated rtt (request to reply time)
	fr_time_delta_t rtt_min;   //!< Lowest rtt
	fr_time_delta_t rtt_max;   //!< Highest rtt (timeout are not included)
} dpc_transaction_stats_t;

/*
 *	All statistics.
 */
typedef struct {
	uint32_t sent;  //<! Packets sent (not including retransmissions)
	uint32_t retr;  //<! Packets retransmitted
	uint32_t lost;  //<! Packets lost (no reply received before timeout + all retransmissions)
	uint32_t recv;  //<! Packets (replies) received
} dpc_packet_stat_t;

/*
 *	Statistics for dynamically named transactions.
 */
typedef struct {
	char **names;                   //<! Array storing transaction names.
	dpc_transaction_stats_t *stats; //<! Statistics data.
} dpc_dyn_tr_stats_t;

typedef struct dpc_statistics {
	/*
	 *	Statistics per transaction or workflow type.
	 *	Note: entry "All" aggregates all unitary transactions (i.e. DORA workflow not included).
	 */
	dpc_transaction_stats_t tr_stats[DPC_TR_MAX];

	/* Statistics per dynamically named transaction type. */
	dpc_dyn_tr_stats_t dyn_tr_stats;

	dpc_packet_stat_t dpc_stat[DHCP_MAX_MESSAGE_TYPE + 1];

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
	fr_dlist_t dlist;          //!< Our entry into the linked list.

	/* Specific item data */
	char const *name;         //!< Name of input (optional).
	uint32_t id;              //!< Id of input (0 for the first one).
	bool done;                //!< Is this input done ? (i.e. no session can be started from it).
	uint32_t num_use;         //!< How many times has this input been used to start sessions.

	VALUE_PAIR *vps;          //!< List of input value pairs read.

	ncc_dlist_t *segments;       //<! List of input scoped segments.
	ncc_segment_t *segment_cur;  //<! Currently used segment.
	ncc_segment_t *segment_dflt; //<! Default segment for this input.

	bool do_xlat;             //<! If the input contain vp's of type VT_XLAT and we handle xlat expansion.

	fr_time_delta_t ftd_start_delay; //!< Delay after which this input can be used to start sessions.
	fr_time_t fte_start;      //!< Timestamp of first use.
	fr_time_t fte_end;        //!< Timestamp of last use once input is done.

	double rate_limit;        //<! Limit rate/s of sessions initialized from this input.

	uint32_t max_use;         //<! Maximum number of times this input can be used.
	double max_duration;      //!< Maximum duration of starting sessions with this input (relative to input start use).
	fr_time_t fte_max_start;  // fte_start + max_duration

	fr_ipaddr_t *authorized_servers; //<! Only allow replies from explicitly authorized servers.

	dpc_input_ext_t ext;      //!< Input pre-parsed information.
};

/*
 *	Session context.
 */
struct dpc_session_ctx {
	uint32_t id;              //!< Id of session (0 for the first one).

	dpc_input_t *input;       //!< Input data.
	fr_time_t fte_start;      //<! Session start timestamp.

	ncc_endpoint_t *gateway;  //!< If using a gateway as source endpoint.
	ncc_endpoint_t src;       //!< Src IP address and port.
	ncc_endpoint_t dst;       //!< Dst IP address and port.

	DHCP_PACKET *request;
	DHCP_PACKET *reply;

	uint32_t retransmit;      //!< Number of times we've retransmitted this request.
	fr_time_t fte_init;       //!< When the packet was (first) initialized. Not altered when retransmitting.
	fr_time_delta_t ftd_rtt;  //!< Request to reply rtt (round trip time).

	uint32_t num_send;        //<! Number of requests sent (not including retransmissions).

	dpc_state_t state;
	bool reply_expected;      //!< Whether a reply is expected or not.

	fr_event_timer_t const *event; //<! Armed timer event (if any).
};



/*
 *	Statistics macros.
 */
#define PACKET_STAT_INCR(_data, _type, _packet_code) \
{ \
	dpc_packet_stat_t *_dpc_stat = (dpc_packet_stat_t *)_data; \
	(_dpc_stat)[0]._type ++; \
	if (is_dhcp_message(_packet_code)) (_dpc_stat)[_packet_code]._type ++; \
}

#define PACKET_STAT_GET(_dpc_stat, _type, _packet_code) ((dpc_packet_stat_t *)_dpc_stat)[_packet_code]._type

#define PACKET_STAT_NUM_INCR(_dpc_stat, _type_num, _code) \
{ \
	switch (_type_num) { \
	case DPC_STAT_PACKET_SENT: PACKET_STAT_INCR(_dpc_stat, sent, _code); break; \
	case DPC_STAT_PACKET_RETR: PACKET_STAT_INCR(_dpc_stat, retr, _code); break; \
	case DPC_STAT_PACKET_LOST: PACKET_STAT_INCR(_dpc_stat, lost, _code); break; \
	case DPC_STAT_PACKET_RECV: PACKET_STAT_INCR(_dpc_stat, recv, _code); break; \
	} \
}

static inline uint32_t PACKET_STAT_NUM_GET(dpc_packet_stat_t *dpc_stat, dpc_packet_stat_field_t type_num, uint32_t code)
{
	uint32_t value = 0;

	switch (type_num) {
	case DPC_STAT_PACKET_SENT: value = PACKET_STAT_GET(dpc_stat, sent, code); break;
	case DPC_STAT_PACKET_RETR: value = PACKET_STAT_GET(dpc_stat, retr, code); break;
	case DPC_STAT_PACKET_LOST: value = PACKET_STAT_GET(dpc_stat, lost, code); break;
	case DPC_STAT_PACKET_RECV: value = PACKET_STAT_GET(dpc_stat, recv, code); break;
	default:
		break;
	}
	return value;
}

#define __STAT_INCR(_type, _packet) { \
	PACKET_STAT_INCR(stat_ctx.dpc_stat, _type, _packet->code); \
}
// don't use this, it cannot handle functions calls (needed for time-data).

/* Update packet statistics.
 * If time-data is enabled, also store in time-data context.
 */
#define STAT_NUM_INCR(_type_num, _packet) { \
	PACKET_STAT_NUM_INCR(stat_ctx.dpc_stat, _type_num, _packet->code); \
	if (CONF.with_timedata) dpc_timedata_store_packet_stat(_type_num, _packet->code); \
}

//#define STAT_INCR_PACKET_SENT(_packet) STAT_INCR(sent, _packet)
//#define STAT_INCR_PACKET_RETR(_packet) STAT_INCR(retr, _packet)
//#define STAT_INCR_PACKET_LOST(_packet) STAT_INCR(lost, _packet)
//#define STAT_INCR_PACKET_RECV(_packet) STAT_INCR(recv, _packet)

#define STAT_INCR_PACKET_SENT(_packet) STAT_NUM_INCR(DPC_STAT_PACKET_SENT, _packet)
#define STAT_INCR_PACKET_RETR(_packet) STAT_NUM_INCR(DPC_STAT_PACKET_RETR, _packet)
#define STAT_INCR_PACKET_LOST(_packet) STAT_NUM_INCR(DPC_STAT_PACKET_LOST, _packet)
#define STAT_INCR_PACKET_RECV(_packet) STAT_NUM_INCR(DPC_STAT_PACKET_RECV, _packet)

#define STAT_ALL_PACKET(_type) (stat_ctx.dpc_stat[0]._type)
#define STAT_NAK_RECV (stat_ctx.dpc_stat[6].recv)
