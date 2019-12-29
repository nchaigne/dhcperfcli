/*
 * dhcperfcli.c
 */

/* Our own auto-configuration header.
 * Will define HAVE_LIBCURL if libcurl is available.
 */
#include "config.h"

#include "ncc_util.h"
#include "ncc_segment.h"
#include "ncc_xlat.h"

#include "dhcperfcli.h"
#include "dpc_packet_list.h"
#include "dpc_util.h"
#include "dpc_config.h"
#include "dpc_time_data.h"

#include <getopt.h>

static char const *fr_version = RADIUSD_VERSION_STRING_BUILD("FreeRADIUS");
static char const *prog_version = DHCPERFCLI_VERSION_STRING;

/*
 *	Global variables.
 */
TALLOC_CTX *global_ctx;
dpc_config_t *dpc_config;

/*
 *	Scheduling and time measurement are performed using FreeRADIUS time library, whichs is not susceptible
 *	to drifts that can occur when using gettimeofday.
 *
 *	Naming convention for FreeRADIUS time variables, depending on their purpose (for clarity):
 *	fte_ = fr_time_t ("epoch"), ftd_ = fr_time_delta_t ("delta").
 *
 *	("epoch" here means: number of nanoseconds since the start of the program)
 */

fr_time_t fte_program_start; /* Program execution start timestamp. */
fr_time_t fte_start;
int dpc_debug_lvl = 0;

static dpc_config_t default_config = {
	.xlat = true,
	.session_max_active = 1,
	.packet_trace_lvl = -1, /* If unspecified, figure out something automatically. */
	.progress_interval = 10.0,
	.request_timeout = 1.0,
	.retransmit_max = 2,

	.min_session_for_rps = 50,
	.min_time_for_rps = 0.5,
	.rate_limit_min_ref_time = 0.2,
	.rate_limit_time_lookahead = 0.02,
};

fr_dict_attr_t const *attr_packet_dst_ip_address;
fr_dict_attr_t const *attr_packet_dst_port;
fr_dict_attr_t const *attr_packet_src_ip_address;
fr_dict_attr_t const *attr_packet_src_port;

fr_dict_attr_t const *attr_input_name;
fr_dict_attr_t const *attr_encoded_data;
fr_dict_attr_t const *attr_authorized_server;
fr_dict_attr_t const *attr_workflow_type;
fr_dict_attr_t const *attr_start_delay;
fr_dict_attr_t const *attr_rate_limit;
fr_dict_attr_t const *attr_max_duration;
fr_dict_attr_t const *attr_max_use;
fr_dict_attr_t const *attr_segment;

extern fr_dict_attr_t const *attr_dhcp_hop_count;
extern fr_dict_attr_t const *attr_dhcp_transaction_id;
extern fr_dict_attr_t const *attr_dhcp_client_ip_address;
extern fr_dict_attr_t const *attr_dhcp_your_ip_address;
extern fr_dict_attr_t const *attr_dhcp_gateway_ip_address;
extern fr_dict_attr_t const *attr_dhcp_message_type;
fr_dict_attr_t const *attr_dhcp_server_identifier;
fr_dict_attr_t const *attr_dhcp_requested_ip_address;
/*
 * Except from the last two, all these dhcpv4 attributes are actually linked from src/protocols/dhcpv4/base.c
 * (and loaded when calling fr_dhcpv4_global_init)
 * The "extern" is not strictly required, but it's certainly less confusing.
 */


static char const *progname;
static pid_t my_pid;

/*
 *	Dictionaries and attributes.
 */
static char alt_dict_dir[PATH_MAX + 1] = ""; /* Alternate directory for dictionaries. */
static char const *dict_dir = DICTDIR;
static char const *dict_fn_freeradius = "freeradius/dictionary.freeradius.internal";
//static char const *dict_fn_dhcperfcli = "dhcperfcli/dictionary.dhcperfcli.internal";

static fr_dict_t const *dict_freeradius;
static fr_dict_t const *dict_dhcperfcli;
//fr_dict_t const *dict_dhcpv4;
static fr_dict_t const *dpc_dict_dhcpv4; /* Ensure we use our own. */

extern fr_dict_autoload_t dpc_dict_autoload[];
fr_dict_autoload_t dpc_dict_autoload[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" }, /* "freeradius" identifies internal dictionary - otherwise it's protocol. */
	{ .out = &dict_dhcperfcli, .proto = "dhcperfcli" },

	//{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	// ^ if we do that it works, but memory will not be freed... (FreeRADIUS bug ?)
	// ...and if we don't, we can't autoload attributes using "dict_dhcpv4"... so we need our own:
	{ .out = &dpc_dict_dhcpv4, .proto = "dhcpv4" },

	{ NULL }
};

extern fr_dict_attr_autoload_t dpc_dict_attr_autoload[];
fr_dict_attr_autoload_t dpc_dict_attr_autoload[] = {

	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },

	{ .out = &attr_input_name, .name = "Input-Name", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
	{ .out = &attr_encoded_data, .name = "DHCP-Encoded-Data", .type = FR_TYPE_OCTETS, .dict = &dict_dhcperfcli },
	{ .out = &attr_authorized_server, .name = "DHCP-Authorized-Server", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcperfcli },
	{ .out = &attr_workflow_type, .name = "DHCP-Workflow-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcperfcli },
	{ .out = &attr_start_delay, .name = "Start-Delay", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
	{ .out = &attr_rate_limit, .name = "Rate-Limit", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
	{ .out = &attr_max_duration, .name = "Max-Duration", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
	{ .out = &attr_max_use, .name = "Max-Use", .type = FR_TYPE_UINT32, .dict = &dict_dhcperfcli },
	{ .out = &attr_segment, .name = "Segment", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
/*
	{ .out = &attr_dhcp_hop_count, .name = "DHCP-Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_transaction_id, .name = "DHCP-Transaction-Id", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_client_ip_address, .name = "DHCP-Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_your_ip_address, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_gateway_ip_address, .name = "DHCP-Gateway-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },

	{ .out = &attr_dhcp_server_identifier, .name = "DHCP-DHCP-Server-Identifier", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_requested_ip_address, .name = "DHCP-Requested-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
*/

	{ .out = &attr_dhcp_requested_ip_address, .name = "DHCP-Requested-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dpc_dict_dhcpv4 },
	{ .out = &attr_dhcp_server_identifier, .name = "DHCP-DHCP-Server-Identifier", .type = FR_TYPE_IPV4_ADDR, .dict = &dpc_dict_dhcpv4 },

	{ NULL }
};

static char const *file_config; /* Optional configuration file. */
static char const *conf_inline;

static char const *instance;
static dpc_packet_list_t *pl; /* List of outgoing packets. */
static fr_event_list_t *event_list;

static bool with_stdin_input = false; /* Whether we have something from stdin or not. */
ncc_dlist_t input_list;

/* List of global time segments, and a pointer on the segment lastly in use.
 */
ncc_dlist_t *segment_list;
ncc_segment_t *segment_cur;

/* A default global segment, temporally all-encompassing: with no rate limit, if a global rate limit (-r) is not set.
 * Or with a fixed rate set to the global rate limit, otherwise.
 */
static ncc_segment_t segment_default = {
	.type = NCC_SEGMENT_RATE_UNBOUNDED,
	.name = "dflt"
};

/* Note: a global rate limit is enforced only if a global time segment is not currently in use.
 * If enforced, the global rate limit applies on the entire job execution. This entails that the instantaneous rate
 * can be higher or slower, if catching up or slowing down is necessary to reach the target global rate.
 */

static ncc_endpoint_t server_ep = {
	.ipaddr = { .af = AF_INET, .prefix = 32 },
	.port = DHCP_PORT_SERVER
};
static ncc_endpoint_t client_ep = {
	.ipaddr = { .af = AF_INET, .prefix = 32 },
	.port = DHCP_PORT_CLIENT
};

static ncc_dlist_t *gateway_list; /* List of gateways. */

static int packet_code = FR_CODE_UNDEFINED;
static int workflow_code = DPC_WORKFLOW_NONE;

static bool start_sessions_flag =  true; /* Allow starting new sessions. */
static fr_time_t fte_job_start; /* Job start timestamp. */
static fr_time_t fte_job_end; /* Job end timestamp. */
static fr_time_t fte_sessions_ini_start; /* Start timestamp of starting new sessions. */
static fr_time_t fte_sessions_ini_end; /* End timestamp of starting new sessions. */
static fr_time_t fte_last_session_in; /* Last time a session has been initialized from input. */

static fr_time_t fte_input_available; /* No item will be available before that point in time. */
static bool no_input_available = false; /* If there is currently no input available for starting sessions. */

static fr_time_t fte_snapshot; /* Snapshot of current time (for consistency when reporting linked values). */

static uint32_t input_num = 0; /* Number of input entries read. (They may not all be valid.) */
static uint32_t num_input_invalid = 0; /* Number of invalid input. */

static uint32_t session_num = 0; /* Total number of sessions initialized (including received requests). */
static uint32_t session_num_in = 0; /* Number of sessions initialized for sending requests. */
static uint32_t session_num_active = 0; /* Number of active sessions. */
static uint32_t session_num_in_active = 0; /* Number of active sessions from input. */
static uint32_t session_num_parallel = 0; /* Number of active sessions from input which are handling initial request. */

static bool job_done = false;
static bool signal_done = false;

static dpc_statistics_t stat_ctx; /* Statistics. */
static uint32_t *retr_breakdown; /* Retransmit breakdown by number of retransmissions. */
static fr_event_timer_t const *ev_progress_stats;
static fr_time_t fte_progress_stat; /* When next ongoing statistics is supposed to fire. */

static fr_time_delta_t ftd_loop_max_time = 50 * 1000 * 1000; /* Max time spent in each iteration of the start loop. */

static bool multi_offer = false;
#ifdef HAVE_LIBPCAP
static fr_pcap_t *pcap;
#endif

/*
 *	More concise version of dhcp_message_types defined in protocols/dhcpv4/base.c
 *	(Stripped of the "DHCP-" prefix. We only do DHCP.)
 */
char const *dpc_message_types[DHCP_MAX_MESSAGE_TYPE] = {
	"",
	"Discover",
	"Offer",
	"Request",
	"Decline",
	"Ack",
	"NAK",
	"Release",
	"Inform",
	"Force-Renew",
	"Lease-Query",
	"Lease-Unassigned",
	"Lease-Unknown",
	"Lease-Active",
	"Bulk-Lease-Query",
	"Lease-Query-Done"
};

static fr_table_num_sorted_t const request_types[] = {
	{ "-",           FR_CODE_UNDEFINED },
	{ "auto",        FR_CODE_UNDEFINED },
	{ "decline",     FR_DHCP_DECLINE },
	{ "discover",    FR_DHCP_DISCOVER },
	{ "inform",      FR_DHCP_INFORM },
	{ "lease_query", FR_DHCP_LEASE_QUERY },
	{ "release",     FR_DHCP_RELEASE },
	{ "request",     FR_DHCP_REQUEST }
};
static size_t request_types_len = NUM_ELEMENTS(request_types);

static fr_table_num_sorted_t const workflow_types[] = {
	{ "dora",        DPC_WORKFLOW_DORA },
	{ "doradec",     DPC_WORKFLOW_DORA_DECLINE },
	{ "dorarel",     DPC_WORKFLOW_DORA_RELEASE }
};
static size_t workflow_types_len = NUM_ELEMENTS(workflow_types);

/* Transaction type labels. */
static char const *transaction_types[DPC_TR_MAX] = {
	"(All)",
	"Discover:Offer",
	"Discover:Ack",
	"Request:Ack",
	"Request:Nak",
	"Lease-Query:Unassigned",
	"Lease-Query:Unknown",
	"Lease-Query:Active",
	"<DORA>"
};
#define LG_PAD_TR_TYPE_MAX 50 /* Limit transaction type name displayed. */
#define LG_PAD_STATS       20

char elapsed_buf[NCC_TIME_STRLEN];
#define ELAPSED ncc_fr_delta_time_snprint(elapsed_buf, sizeof(elapsed_buf), &fte_job_start, &fte_snapshot, DPC_DELTA_TIME_DECIMALS)


/*
 *	Static functions declaration.
 */
static void usage(int);
static void version_print(void);

static char *dpc_num_message_type_sprint(char *out, size_t outlen, dpc_packet_stat_field_t stat_type);
static void dpc_per_input_stats_fprint(FILE *fp, bool force);
static void dpc_progress_stats_fprint(FILE *fp, bool force);

static inline double dpc_job_elapsed_time_snapshot_set(void);
static inline void dpc_time_snapshot_clear(void);
static inline fr_time_t dpc_fr_time(void);
static inline fr_time_t dpc_elapsed_fr_time_get(fr_time_t start, fr_time_t end);
static inline fr_time_t dpc_job_elapsed_fr_time_get(void);
static inline double dpc_job_elapsed_time_get(void);

static double dpc_get_tr_rate(dpc_transaction_stats_t *my_stat);
static double dpc_get_session_in_rate(bool per_input);
static size_t dpc_tr_name_max_len(void);
static int dpc_tr_stat_fprint(FILE *fp, unsigned int pad_len, dpc_transaction_stats_t *my_stats, char const *name);
static void dpc_tr_stats_fprint(FILE *fp);
static void dpc_stats_fprint(FILE *fp);
static void dpc_tr_stats_update(dpc_transaction_type_t tr_type, fr_time_delta_t rtt);
static void dpc_statistics_update(dpc_session_ctx_t *session, DHCP_PACKET *request, DHCP_PACKET *reply);

static void dpc_progress_stats(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, UNUSED void *ctx);
static void dpc_event_add_progress_stats(void);
static void dpc_request_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx);
static void dpc_event_add_request_timeout(dpc_session_ctx_t *session, fr_time_delta_t *timeout_in);

static int dpc_send_one_packet(dpc_session_ctx_t *session, DHCP_PACKET **packet_p);
static int dpc_recv_one_packet(fr_time_delta_t ftd_wait_time);
static bool dpc_session_handle_reply(dpc_session_ctx_t *session, DHCP_PACKET *reply);
static bool dpc_session_dora_request(dpc_session_ctx_t *session);
static bool dpc_session_dora_release(dpc_session_ctx_t *session);
static bool dpc_session_dora_decline(dpc_session_ctx_t *session);
static void dpc_request_gateway_handle(DHCP_PACKET *packet, ncc_endpoint_t *gateway);
static DHCP_PACKET *dpc_request_init(TALLOC_CTX *ctx, dpc_session_ctx_t *session, dpc_input_t *input);
static int dpc_dhcp_encode(DHCP_PACKET *packet);

static void dpc_session_set_transport(dpc_session_ctx_t *session, dpc_input_t *input);

static bool dpc_item_available(dpc_input_t *item, fr_time_t *when);
static char dpc_item_get_status(dpc_input_t *input);
static double dpc_item_get_elapsed(dpc_input_t *input);
static bool dpc_item_get_rate(double *out_rate, dpc_input_t *input);
static ncc_segment_t *dpc_input_get_segment(dpc_input_t *input);
static bool dpc_item_rate_limited(dpc_input_t *input);
static dpc_input_t *dpc_get_input(void);
static dpc_session_ctx_t *dpc_session_init_from_input(TALLOC_CTX *ctx);
static void dpc_session_finish(dpc_session_ctx_t *session);

static double dpc_segment_get_elapsed(ncc_segment_t *segment);
static bool dpc_segment_get_rate(double *out_rate, ncc_segment_t *segment);
static ncc_segment_t *dpc_get_current_segment(ncc_dlist_t *list, ncc_segment_t *segment_pre);

static void dpc_loop_recv(void);
static bool dpc_rate_limit_calc_gen(uint32_t *max_new_sessions, bool strict, ncc_segment_t *segment, uint32_t cur_num_started);
static bool dpc_rate_limit_calc(uint32_t *max_new_sessions);
static void dpc_end_start_sessions(void);
static uint32_t dpc_loop_start_sessions(void);
static bool dpc_loop_check_done(void);
static void dpc_main_loop(void);

static int dpc_input_parse(TALLOC_CTX *ctx, dpc_input_t *input);
static int dpc_input_handle(dpc_input_t *input, ncc_dlist_t *dlist);
static int dpc_input_load_from_fp(TALLOC_CTX *ctx, FILE *fp, ncc_dlist_t *dlist, char const *filename);
static int dpc_input_load(TALLOC_CTX *ctx);

static int dpc_pair_list_xlat(DHCP_PACKET *packet, VALUE_PAIR *vps);

static int dpc_get_alt_dir(void);
static void dpc_dict_init(TALLOC_CTX *ctx);
static void dpc_event_list_init(TALLOC_CTX *ctx);
static void dpc_packet_list_init(TALLOC_CTX *ctx);
static int dpc_command_parse(char const *command);
static void dpc_gateway_parse(TALLOC_CTX *ctx, char const *in);
static void dpc_options_parse(int argc, char **argv);

static void dpc_signal(int sig);
static void dpc_end(void);
static void dpc_exit(void);


/*
 *	Print number of each type of message (sent, received, ...).
 */
char *dpc_num_message_type_sprint(char *out, size_t outlen, dpc_packet_stat_field_t stat_type)
{
	int i;
	char *p = out;
	size_t len = 0;

	*p = '\0';

#define MSG_TYPE_PRINT(_num, _label) \
{ \
	if (_num > 0) { \
		if (p != out) { \
			len = sprintf(p, ", "); \
			p += len; \
		} \
		len = sprintf(p, "%s: %u", _label, _num); \
		p += len; \
		remain -= _num; \
	} \
}

	uint32_t remain = PACKET_STAT_NUM_GET(stat_ctx.dpc_stat, stat_type, 0); /* Total. */

	for (i = 1; i < DHCP_MAX_MESSAGE_TYPE; i++) {
		MSG_TYPE_PRINT(PACKET_STAT_NUM_GET(stat_ctx.dpc_stat, stat_type, i), dpc_message_types[i]);
	}
	if (remain) { /* Unknown message types. */
		MSG_TYPE_PRINT(remain, "unknown");
	}
	return out;
}

/**
 * Print ongoing statistics for a given segment.
 * E.g.:
 * segment #1 <name> (2.000 - 8.000) fixed: use: 21, rate (/s): 20.999
 */
void dpc_segment_stats_fprint(FILE *fp, ncc_segment_t *segment)
{
	char buf[128];

	if (!ncc_segment_description_snprint(buf, sizeof(buf), segment, false)) return;
	fprintf(fp, "segment %s", buf);

	/* A "null" segment is not used. */
	if (segment->type != NCC_SEGMENT_RATE_NULL) {
		double rate = 0;
		bool with_rate = dpc_segment_get_rate(&rate, segment);

		fprintf(fp, ": use: %u", segment->num_use);
		if (with_rate) {
			fprintf(fp, ", rate (/s): %.3f", rate);
		}
	}
}

/**
 * Print ongoing statistics detail per input.
 * Either (a) as a digest on a single line, or (b) one line per input.
 * In the latter case, additional detail is provided, in particular the current input scoped segment (if applicable).
 *
 * E.g.:
 * (a)
 *  └─ per-input rate (/s): #0 (A): 2880.764, #1 (A): 2885.048
 * (b)
 *  └─ input #0 (A) use: 4645, rate (/s): 3015.712
 *  └─ input #1 (A) use: 4644, rate (/s): 3018.594 - segment #1 (2.000 - 8.000) fixed: use: 21, rate (/s): 20.999
 */
static void dpc_per_input_stats_fprint(FILE *fp, bool force)
{
	if (!CONF.pr_stat_per_input || !CONF.template) return;

	if (!force && !start_sessions_flag) return; /* Only trace this if we're still starting new sessions, or if force. */

	bool digest = CONF.pr_stat_per_input_digest;

	if (digest) {
		fprintf(fp, " └─ per-input rate (/s): ");
	}

	dpc_input_t *input = NCC_DLIST_HEAD(&input_list);
	int i = 0;

	while (input) {
		double rate = 0;
		char status = dpc_item_get_status(input);
		bool with_rate = dpc_item_get_rate(&rate, input);

		if (digest) {
			if (i) fprintf(fp, ", ");

			/* Print status: W = waiting, A = active, T = terminated. */
			fprintf(fp, "#%u (%c)", input->id, status);

			if (with_rate) {
				fprintf(fp, ": %.3f", rate);
			} else {
				fprintf(fp, ": N/A"); /* No relevant rate. */
			}

		} else {
			/*
			 * Print each input on a distinct line.
			 * Display input name if defined, or id otherwise.
			 */
			fprintf(fp, " └─ ");
			if (input->name) {
				fprintf(fp, "%s", input->name);
			} else {
				fprintf(fp, "input #%u", input->id);
			}
			fprintf(fp, " (%c) use: %u", status, input->num_use);

			if (with_rate) {
				fprintf(fp, ", rate (/s): %.3f", rate);
			}

			/* Print the current input scoped segment, if explicitly defined.
			 */
			input->segment_cur = dpc_get_current_segment(input->segments, input->segment_cur);

			if (input->segment_cur && input->segment_cur->alloc == NCC_SEGMENT_ALLOC_MANUAL) {
				fprintf(fp, " - ");
				dpc_segment_stats_fprint(fp, input->segment_cur);
			}

			fprintf(fp, "\n");
		}

		i++;
		if (CONF.pr_stat_per_input_max && i >= CONF.pr_stat_per_input_max) break;

		input = NCC_DLIST_NEXT(&input_list, input);
	}

	if (digest) {
		fprintf(fp, "\n");
	}
}

/**
 * Print ongoing job statistics summary.
 * Also print an additional line with the current global segment (if applicable).
 * E.g.:
 * (*) 17:14:20 t(8.000) (80.0%) sessions: [in: 39259 (31.8%), ongoing: 10], session rate (/s): 4905.023
 *  └─ segment #0 (0.000 - INF) use: 5792, rate (/s): 5791.051
 */
static void dpc_progress_stats_fprint(FILE *fp, bool force)
{
	/* Rewrite the file (instead of appending to it). */
	if (CONF.pr_stat_dst == PR_STAT_DST_FILE && CONF.pr_stat_file_rewrite) {
		fp = freopen(NULL, "w", fp);
		CONF.pr_stat_fp = fp;
	}

	/* Prefix to easily distinguish these ongoing statistics from packet traces and other logs. */
	fprintf(fp, "(*) ");

	/* Use a fixed reference time for consistency. */
	double elapsed = dpc_job_elapsed_time_snapshot_set();

	/* Absolute date/time. */
	if (CONF.pr_stat_timestamp) {
		char datetime_buf[NCC_DATETIME_STRLEN];
		fprintf(fp, "%s ", ncc_absolute_time_snprint(datetime_buf, sizeof(datetime_buf), NCC_TIME_FMT));
	}

	/* Elapsed time. */
	fprintf(fp, "t(%s)", ELAPSED);
	if (CONF.duration_start_max) {
		/* And percentage of max duration (if set). */
		double duration_progress = 100 * elapsed / CONF.duration_start_max;
		fprintf(fp, " (%.1f%%)", duration_progress);
	}

	/* Sessions. */
	if (session_num > 0) {
		fprintf(fp, " sessions: [in: %u", session_num_in);

		/* And percentage of max number of sessions (if set). Unless we're done starting new sessions. */
		if (CONF.session_max_num && start_sessions_flag) {
			double session_progress = 100 * (double)session_num_in / CONF.session_max_num;
			fprintf(fp, " (%.1f%%)", session_progress);
		}

		/* Ongoing (active) sessions. (== number of packets to which we're waiting for a reply) */
		fprintf(fp, ", ongoing: %u", session_num_active);

		/* Packets lost (for which a reply was expected, but we didn't get one. */
		if (STAT_ALL_PACKET(lost) > 0) {
			fprintf(fp, ", lost: %u", STAT_ALL_PACKET(lost));
		}

		/* NAK replies. */
		if (STAT_NAK_RECV > 0) {
			fprintf(fp, ", %s: %u", dpc_message_types[6], STAT_NAK_RECV);
		}

		fprintf(fp, "]");
	}

	/* Print input sessions rate, if: we've handled at least a few sessions, with sufficient elapsed time.
	 * And we're (still) starting sessions.
	 */
	if (session_num_in >= CONF.min_session_for_rps
	    && elapsed >= CONF.min_time_for_rps
		&& start_sessions_flag) {
		bool per_input = CONF.rate_limit ? false : true;
		fprintf(fp, ", session rate (/s): %.3f", dpc_get_session_in_rate(per_input));
	}

	fprintf(fp, "\n");

	/* Segment statistics line.
	 * Print the current global segment, if explicitly defined.
	 */
	segment_cur = dpc_get_current_segment(segment_list, segment_cur);

	if (segment_cur && segment_cur->alloc == NCC_SEGMENT_ALLOC_MANUAL) {
		fprintf(fp, " └─ ");
		dpc_segment_stats_fprint(fp, segment_cur);
		fprintf(fp, "\n");
	}

	/* Per-input statistics line(s). */
	dpc_per_input_stats_fprint(fp, force);

	/* Clear snapshot. */
	dpc_time_snapshot_clear();

	fflush(fp);
}


/**
 * Set a snapshot of the current time.
 * Return job elapsed time (up to the snapshot).
 */
static inline double dpc_job_elapsed_time_snapshot_set(void)
{
	if (fte_job_end) {
		fte_snapshot = fte_job_end;
	} else {
		fte_snapshot = fr_time();
	}

	return ncc_fr_time_to_float(fte_snapshot - fte_job_start);
}

/**
 * Clear the current time snapshot.
 */
static inline void dpc_time_snapshot_clear(void)
{
	fte_snapshot = 0;
}

/**
 * Get either the current time snapshot if set, or real current time otherwise.
 */
static inline fr_time_t dpc_fr_time(void)
{
	if (fte_snapshot) return fte_snapshot;
	else return fr_time();
}

/**
 * Get an elapsed time (difference between start and end).
 * If end is not set, use instead current time (or time snapshot if set).
 */
static inline fr_time_t dpc_elapsed_fr_time_get(fr_time_t start, fr_time_t end)
{
	if (!start) return 0; /* Start time not initialized yet. */

	if (end) {
		/* Time delta from start to end.
		 */
		return end - start;

	} else {
		/* Time delta from start to current time (or time snapshot if set).
		 */
		return dpc_fr_time() - start;
	}
}

/**
 * Obtain the job (either ongoing or finished) elapsed time.
 */
static inline fr_time_t dpc_job_elapsed_fr_time_get(void)
{
	return dpc_elapsed_fr_time_get(fte_job_start, fte_job_end);
}
static inline double dpc_job_elapsed_time_get(void)
{
	return ncc_fr_time_to_float(dpc_job_elapsed_fr_time_get());
}

/**
 * Obtain job elapsed time related to starting new sessions.
 */
static inline double dpc_start_sessions_elapsed_time_get(void)
{
	return ncc_fr_time_to_float(dpc_elapsed_fr_time_get(fte_sessions_ini_start, fte_sessions_ini_end));
}

/*
 *	Compute the effective rate (reply per second) of a given transaction type (or all).
 *	Note: for a workflow (DORA), this is based on the final reply (Ack).
 */
static double dpc_get_tr_rate(dpc_transaction_stats_t *my_stats)
{
	double elapsed = dpc_job_elapsed_time_get();

	if (elapsed <= 0) return 0; /* Should not happen. */
	return (double)my_stats->num / elapsed;
}

/*
 *	Compute the rate of input sessions per second.
 */
static double dpc_get_session_in_rate(bool per_input)
{
	double rate = 0;

	if (!per_input) {
		/* Compute a global session rate, from the start of the job
		 * up to now (if still starting new sessions) or when the last session was initialized.
		 */
		double elapsed;
		fr_time_t fte_end;
		fr_time_delta_t ftd_elapsed;

		if (!fte_sessions_ini_start || !fte_last_session_in) return 0;

		/* If not starting new sessions, use last session time as end time.
		 * Otherwise, use current time.
		 */
		if (!start_sessions_flag) {
			fte_end = fte_last_session_in;
		} else {
			fte_end = dpc_fr_time();
		}

		/* Compute elapsed time. */
		ftd_elapsed = fte_end - fte_job_start;
		elapsed = ncc_fr_time_to_float(ftd_elapsed);
		if (elapsed > 0) { /* Just to be safe. */
			rate = (double)session_num_in / elapsed;
		}

	} else {
		/* Compute the rate per input, and sum them. */
		dpc_input_t *input = NCC_DLIST_HEAD(&input_list);
		while (input) {
			if (!input->done) { /* Ignore item if we're done with it. */
				double input_rate = 0;
				if (dpc_item_get_rate(&input_rate, input)) {
					rate += input_rate;
				}
			}
			input = NCC_DLIST_NEXT(&input_list, input);
		}
	}

	return rate;
}

/*
 *	Get the longest name of actual transactions.
 */
static size_t dpc_tr_name_max_len(void)
{
	int i;
	size_t num_transaction_type = talloc_array_length(stat_ctx.dyn_tr_stats.names);
	size_t max_len = strlen(transaction_types[DPC_TR_ALL]); /* (All) */

	for (i = 0; i < num_transaction_type; i++) {
		size_t len = strlen(stat_ctx.dyn_tr_stats.names[i]);
		if (len > max_len) max_len = len;
	}
	return max_len;
}

/*
 *	Print statistics for a given transaction type.
 */
static int dpc_tr_stat_fprint(FILE *fp, unsigned int pad_len, dpc_transaction_stats_t *my_stats, char const *name)
{
	if (!my_stats || my_stats->num == 0) return 0;

	double rtt_avg = 1000 * ncc_fr_time_to_float(my_stats->rtt_cumul) / my_stats->num;
	double rtt_min = 1000 * ncc_fr_time_to_float(my_stats->rtt_min);
	double rtt_max = 1000 * ncc_fr_time_to_float(my_stats->rtt_max);

	fprintf(fp, "\t%-*.*s: num: %u, RTT (ms): [avg: %.3f, min: %.3f, max: %.3f]",
	        pad_len, pad_len, name, my_stats->num, rtt_avg, rtt_min, rtt_max);

	/* Print rate if job elapsed time is at least 1 s. */
	if (dpc_job_elapsed_time_get() >= 1.0) {
		fprintf(fp, ", rate (avg/s): %.3f", dpc_get_tr_rate(my_stats));
	}

	fprintf(fp, "\n");

	return 1;
}

/*
 *	Print per-transaction type statistics.
 */
static void dpc_tr_stats_fprint(FILE *fp)
{
	int i;
	int pad_len = 0;

	size_t num_transaction_type = talloc_array_length(stat_ctx.dyn_tr_stats.names);

	if (num_transaction_type == 0) return; /* We got nothing. */

	pad_len = dpc_tr_name_max_len() + 1;
	if (pad_len > LG_PAD_TR_TYPE_MAX) pad_len = LG_PAD_TR_TYPE_MAX;

	fprintf(fp, "*** Statistics (per-transaction):\n");

	/* only print "All" if we have more than one (otherwise it's redundant). */
	if (num_transaction_type > 1) {
		dpc_tr_stat_fprint(fp, pad_len, &stat_ctx.tr_stats[DPC_TR_ALL], transaction_types[DPC_TR_ALL]);
	}

	for (i = 0; i < num_transaction_type; i++) {
		dpc_tr_stat_fprint(fp, pad_len, &stat_ctx.dyn_tr_stats.stats[i], stat_ctx.dyn_tr_stats.names[i]);
	}

	/* print DORA if we have some. */
	if (stat_ctx.tr_stats[DPC_TR_DORA].num > 0) {
		dpc_tr_stat_fprint(fp, pad_len, &stat_ctx.tr_stats[DPC_TR_DORA], transaction_types[DPC_TR_DORA]);
	}
}

/*
 *	Print global statistics.
 */
static void dpc_stats_fprint(FILE *fp)
{
	if (!fp) return;

	char buffer[4096];

	fprintf(fp, "*** Statistics (global):\n");

	/* Job elapsed time, from start to end. */
	fprintf(fp, "\t%-*.*s: %s\n", LG_PAD_STATS, LG_PAD_STATS, "Elapsed time (s)",
	        ncc_fr_delta_time_snprint(elapsed_buf, sizeof(elapsed_buf), &fte_job_start, &fte_job_end, DPC_DELTA_TIME_DECIMALS));

	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Sessions", session_num);

	/* Packets sent (total, and of each message type). */
	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets sent", STAT_ALL_PACKET(sent));
	if (STAT_ALL_PACKET(sent) > 0) {
		fprintf(fp, " (%s)", dpc_num_message_type_sprint(buffer, sizeof(buffer), DPC_STAT_PACKET_SENT));
	}
	fprintf(fp, "\n");

	/* Packets received (total, and of each message type - if any). */
	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets received", STAT_ALL_PACKET(recv));
	if (STAT_ALL_PACKET(recv) > 0) {
		fprintf(fp, " (%s)", dpc_num_message_type_sprint(buffer, sizeof(buffer), DPC_STAT_PACKET_RECV));
	}
	fprintf(fp, "\n");

	/* Packets to which no response was received. */
	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Retransmissions", STAT_ALL_PACKET(retr));

	if (retr_breakdown && retr_breakdown[0] > 0) {
		fprintf(fp, "\t%-*.*s: %s\n", LG_PAD_STATS, LG_PAD_STATS, "  Retr breakdown",
		        dpc_retransmit_snprint(buffer, sizeof(buffer), STAT_ALL_PACKET(sent), retr_breakdown, CONF.retransmit_max));
	}

	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets lost", STAT_ALL_PACKET(lost));
	if (STAT_ALL_PACKET(lost) > 0) {
		fprintf(fp, " (%.1f%%)", 100 * (float)STAT_ALL_PACKET(lost) / STAT_ALL_PACKET(sent));
	}
	fprintf(fp, "\n");

	/* Packets received but which were not expected (timed out, sent to the wrong address, or whatever. */
	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Replies unexpected",
	        stat_ctx.num_packet_recv_unexpected);
}

/*
 *	Update statistics for a type of transaction.
 */
static void dpc_tr_stats_update(dpc_transaction_type_t tr_type, fr_time_delta_t rtt)
{
	if (tr_type < 0 || tr_type >= DPC_TR_MAX) return;
	if (!rtt) return;

	dpc_transaction_stats_t *my_stats = &stat_ctx.tr_stats[tr_type];

	dpc_tr_stats_update_values(my_stats, rtt);

	DEBUG3("Updated transaction stats: type: %d, num: %d, this rtt: %.6f, min: %.6f, max: %.6f",
	       tr_type, my_stats->num, ncc_fr_time_to_float(rtt),
	       ncc_fr_time_to_float(my_stats->rtt_min), ncc_fr_time_to_float(my_stats->rtt_max));
}

/*
 *	From a session context, update dynamically named transaction statistics.
 */
static void dpc_session_dyn_tr_stats_update(dpc_session_ctx_t *session, fr_time_delta_t rtt)
{
	char name[256];

	/* Build the transaction name. */
	dpc_session_transaction_snprint(name, sizeof(name), session);

	/* Update transaction statistics. */
	dpc_dyn_tr_stats_update(global_ctx, &stat_ctx.dyn_tr_stats, name, rtt);

	/* If time-data is enabled, also store in time-data context. */
	if (CONF.with_timedata) dpc_timedata_store_tr_stat(name, rtt);
}

/*
 *	Update statistics.
 */
static void dpc_statistics_update(dpc_session_ctx_t *session, DHCP_PACKET *request, DHCP_PACKET *reply)
{
	if (!request || !reply) return;

	fr_time_delta_t rtt;

	/* Get rtt previously computed. */
	rtt = session->ftd_rtt;

	/* Name the transaction and update its statistics. */
	dpc_session_dyn_tr_stats_update(session, rtt);

	/* Also update for 'All'. */
	dpc_tr_stats_update(DPC_TR_ALL, rtt);
}

/*
 *	Event callback: progress statistics summary.
 */
static void dpc_progress_stats(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, UNUSED void *ctx)
{
	/* Do statistics summary. */
	dpc_progress_stats_fprint(CONF.pr_stat_fp, false);

	/* ... and schedule next time. */
	dpc_event_add_progress_stats();
}

/*
 *	Add timer event: progress statistics summary.
 */
static void dpc_event_add_progress_stats(void)
{
	if (!CONF.ftd_progress_interval) return;

	/*
	 *	Generate uniformly spaced out statistics.
	 *	To avoid drifting, schedule next event relatively to the expected trigger of previous one.
	 */
	fr_time_t now = fr_time();

	if (!fte_progress_stat) {
		fte_progress_stat = now;
	}

	/* Ensure the scheduled time is in the future. */
	do {
		fte_progress_stat += CONF.ftd_progress_interval;
	} while (fte_progress_stat < now);

	if (fr_event_timer_at(global_ctx, event_list, &ev_progress_stats,
	                      fte_progress_stat, dpc_progress_stats, NULL) < 0) {
		/* Should never happen. */
		PERROR("Failed to insert progress statistics event");
	}
}

/*
 *	One request timed-out, but maybe we can retransmit.
 */
static bool dpc_retransmit(dpc_session_ctx_t *session)
{
	if (session->retransmit >= CONF.retransmit_max) {
		/* Give up. */
		return false;
	}

	/* Try again. */
	retr_breakdown[session->retransmit] ++;
	session->retransmit ++;

	if (dpc_send_one_packet(session, &session->request) < 0) {
		/* Caller will finish session. */
		return false;
	}

	/*
	 *	Arm request timeout.
	 */
	dpc_event_add_request_timeout(session, NULL);
	return true;
}

/*
 *	Event callback: request timeout.
 */
static void dpc_request_timeout(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, void *uctx)
{
	dpc_session_ctx_t *session = talloc_get_type_abort(uctx, dpc_session_ctx_t);

	if (session->state == DPC_STATE_WAIT_OTHER_REPLIES) {
		/*
		 *	We have received at least one reply. We've been waiting for more from other DHCP servers.
		 *	So do not track this as "packet lost".
		 */
		DEBUG3("Stop waiting for more replies");
	} else {
		DEBUG3("Request timed out (retransmissions so far: %u)", session->retransmit);

		if (!signal_done && dpc_retransmit(session)) {
			/* Packet has been successfully retransmitted. */
			STAT_INCR_PACKET_RETR(session->request);
			return;
		}

		if (CONF.packet_trace_lvl >= 1) dpc_packet_digest_fprint(fr_log_fp, session, session->request, DPC_PACKET_TIMEOUT);

		/* Statistics. */
		STAT_INCR_PACKET_LOST(session->request);
	}

	/* Finish the session. */
	dpc_session_finish(session);
}

/*
 *	Add timer event: request timeout.
 *	Note: even if timeout = 0 we do insert an event (in this case it will be triggered immediately).
 *	If timeout_in is not NULL: use this as timeout. Otherwise, use fixed global timeout.
 */
static void dpc_event_add_request_timeout(dpc_session_ctx_t *session, fr_time_delta_t *timeout_in)
{
	fr_time_t fte_event = fr_time();
	fte_event += (timeout_in ? *timeout_in : CONF.ftd_request_timeout);

	/* If there is an active event timer for this session, clear it before arming a new one. */
	if (session->event) {
		fr_event_timer_delete(event_list, &session->event);
		session->event = NULL;
	}

	if (fr_event_timer_at(session, event_list, &session->event,
	                      fte_event, dpc_request_timeout, session) < 0) {
		/* Should never happen. */
		PERROR("Failed to insert request timeout event");
	}
}

/**
 * Send one packet (initial or retransmission).
 * Grab a socket, insert packet in the packet list (and obtain an id), encode DHCP packet, and send it.
 *
 * @param[in] session   the session to which the packet belongs.
 * @param[in] packet_p  pointer on packet. Note: this is a 'DHCP_PACKET **', which is necessary for inserting
 *                      into the packet list rbtree (cf. dpc_packet_list_id_alloc).
 *
 * @return -1 = error, 0 = success.
 */
static int dpc_send_one_packet(dpc_session_ctx_t *session, DHCP_PACKET **packet_p)
{
	DHCP_PACKET *packet = *packet_p;
	int sockfd;
	int ret;

	DEBUG3("Preparing to send one packet");

	/* Get a socket to send this over.
	 */
#ifdef HAVE_LIBPCAP
	if (session->input->ext.with_pcap) {
		sockfd = pcap->fd;
	} else
#endif
	{
		sockfd = dpc_socket_provide(pl, &packet->src_ipaddr, packet->src_port);
	}
	if (sockfd < 0) {
		SPERROR("Failed to provide a suitable socket");
		return -1;
	}

	if (packet->id == DPC_PACKET_ID_UNASSIGNED) {
		/* Need to assign an xid to this packet. */
		bool rcode;

		/* Set packet->id to prefered value (if any).
		 * Note: it will be reset if allocation fails.
		 */
		packet->id = session->input->ext.xid;

		/* An xlat expression may have been provided. Go look in packet vps.
		 */
		if (packet->id == DPC_PACKET_ID_UNASSIGNED && CONF.xlat) {
			VALUE_PAIR *vp_xid = ncc_pair_find_by_da(packet->vps, attr_dhcp_transaction_id);
			if (vp_xid) packet->id = vp_xid->vp_uint32;
		}

		/* Allocate an id, and prepare the packet (socket fd, src addr)
		 */
		rcode = dpc_packet_list_id_alloc(pl, sockfd, packet_p);
		if (!rcode) {
			SERROR("Failed to allocate packet xid");
			return -1;
		}
	}

	ncc_assert(packet->id != DPC_PACKET_ID_UNASSIGNED);

	if (!packet->data) {
		/*
		 * Encode the packet.
		 * Note: it's already encoded if retransmitting.
		 */
		DEBUG3("Encoding packet");
		if (dpc_dhcp_encode(packet) < 0) { /* Should never happen. */
			SERROR("Failed to encode request packet");
			exit(EXIT_FAILURE);
		}
	}

	/* Send the packet.
	 */
	packet->timestamp = fr_time(); /* Store packet send time. */

	// shouldn't FreeRADIUS lib do that ? TODO.
	// on receive, reply timestamp is set by fr_dhcpv4_udp_packet_recv
	// - actual value is set in recvfromto right before returning

	packet->sockfd = sockfd;

#ifdef HAVE_LIBPCAP
	if (session->input->ext.with_pcap) {
		/*
		 * Send using pcap raw socket.
		 */
		packet->if_index = pcap->if_index; /* So we can trace it. */
		ret = fr_dhcpv4_pcap_send(pcap, eth_bcast, packet);
		/*
		 * Note: we're sending from our real Ethernet source address (from the selected interface,
		 * set by fr_pcap_open / fr_pcap_mac_addr), *not* field 'chaddr' from the DHCP packet
		 * (which is a fake hardware address).
		 * This because we want replies (sent by the DHCP server to our Ethernet address) to reach us.
		 */
	} else
#endif
	{
		/*
		 * Send using a connectionless UDP socket (sendfromto).
		 */
		ret = fr_dhcpv4_udp_packet_send(packet);
	}
	if (ret < 0) {
		SPERROR("Failed to send packet");
		return -1;
	}

	/* Print sent packet. */
	dpc_packet_fprint(fr_log_fp, session, packet, DPC_PACKET_SENT);

	/* Statistics. */
	if (session->retransmit == 0) {
		STAT_INCR_PACKET_SENT(packet);
	}

	return 0;
}

/*
 *	Receive one packet, maybe.
 *	If ftd_wait_time is not NULL, spend at most this time waiting for a packet. Otherwise do not wait.
 *	If a packet is received, it has to be a reply to something we sent. Look for that request in the packet list.
 *	Returns: -1 = error, 0 = nothing to receive, 1 = one packet received.
 */
static int dpc_recv_one_packet(fr_time_delta_t ftd_wait_time)
{
	fd_set set;
	struct timeval tvi_wait = { 0 };
	DHCP_PACKET *packet = NULL, **packet_p;
	dpc_session_ctx_t *session;
	int max_fd;
	char from_to_buf[DPC_FROM_TO_STRLEN] = "";

	/* Wait for packet, timing out as necessary */
	FD_ZERO(&set);

	max_fd = dpc_packet_list_fd_set(pl, &set);
	if (max_fd < 0) {
		/* no sockets to listen on! */
		return 0;
	}

	if (ftd_wait_time) {
		tvi_wait = fr_time_delta_to_timeval(ftd_wait_time);
		DEBUG3("Max wait time: %.6f", ncc_fr_time_to_float(ftd_wait_time));
	}

	/*
	 *	No packet was received.
	 */
	if (select(max_fd, &set, NULL, NULL, &tvi_wait) <= 0) {
		return 0;
	}

	/*
	 *	Fetch one incoming packet.
	 */
	packet = dpc_packet_list_recv(pl, &set); // warning: packet is allocated on NULL context.
	if (!packet) {
		PERROR("Received bad packet");
		return -1;
	}

	DEBUG3("Received packet %s, id: %u (0x%08x)",
	       dpc_packet_from_to_sprint(from_to_buf, packet, false), packet->id, packet->id);

	/*
	 *	Only allow replies from specific servers (overall policy set through option -a).
	 */
	if (CONF.authorized_servers && ncc_ipaddr_array_find(CONF.authorized_servers, &packet->src_ipaddr) < 0) {
		DEBUG("Received packet Id %u (0x%08x) from unauthorized server (%s): ignored",
		      packet->id, packet->id, fr_inet_ntop(from_to_buf, sizeof(from_to_buf), &packet->src_ipaddr));
		fr_radius_packet_free(&packet);
		return -1;
	}

	/*
	 *	Query the packet list to get the original packet to which this is a reply.
	 */
	packet_p = dpc_packet_list_find_byreply(pl, packet);
	if (!packet_p) {
		/*
		 *	We did not find the packet in the packet list. This can happen in several situations:
		 *	- The initial packet timed out and we receive the response later (likely the DHCP server is overloaded)
		 *	- The IP address to which the reply was sent does not match (maybe giaddr / source IP address mixup)
		 *	- The transaction ID does not match (DHCP server is broken)
		 */
		DEBUG("Received unexpected packet Id %u (0x%08x) %s length %zu",
		      packet->id, packet->id, dpc_packet_from_to_sprint(from_to_buf, packet, false), packet->data_len);

		stat_ctx.num_packet_recv_unexpected ++;
		fr_radius_packet_free(&packet);
		return -1;
	}

	/*
	 *	Retrieve the session to which belongs the original packet.
	 *	To do so we use fr_packet2myptr, this is a magical macro defined in include/packet.h
	 */
	session = fr_packet2myptr(dpc_session_ctx_t, request, packet_p);

	DEBUG3("Packet belongs to session id: %d", session->id);

	/*
	 *	Only allow replies from a specific server (per-packet policy set through attribute).
	 */
	if (session->input->authorized_servers && ncc_ipaddr_array_find(session->input->authorized_servers, &packet->src_ipaddr) < 0) {
		SDEBUG("Received packet Id %u (0x%08x) from unauthorized server (%s): ignored",
		       packet->id, packet->id, fr_inet_ntop(from_to_buf, sizeof(from_to_buf), &packet->src_ipaddr));
		fr_radius_packet_free(&packet);
		return -1;
	}

	/* Note: after a reply has been accepted, if we get more replies (from other DHCP servers) they will be "unexpected packets".
	 */

	/*
	 *	Decode the reply packet.
	 */
	if (fr_dhcpv4_packet_decode(packet) < 0) {
		SPERROR("Failed to decode reply packet (id: %u)", packet->id);
		fr_radius_packet_free(&packet);
		/*
		 *	Don't give hope and kill the session now. Maybe we'll receive something better.
		 *	If not, well... the timeout event will do its dirty job.
		 */
		return -1;
	}

	/* Statistics. */
	STAT_INCR_PACKET_RECV(packet);

	/*
	 *	Handle the reply, and decide if the session is finished or not yet.
	 */
	if (!dpc_session_handle_reply(session, packet)) {
		dpc_session_finish(session);
	}

	return 1;
}

/**
 * Handle a reply which belongs to a given ongoing session.
 *
 * @return true if the session is not finished (should be retained), false otherwise (will be terminated).
 */
static bool dpc_session_handle_reply(dpc_session_ctx_t *session, DHCP_PACKET *reply)
{
	if (!session || !reply) return false;

	if (   (session->state == DPC_STATE_DORA_EXPECT_OFFER && reply->code != FR_DHCP_OFFER)
		|| (session->state == DPC_STATE_DORA_EXPECT_ACK && reply->code != FR_DHCP_ACK) ) {
		/*
		 *	This is *not* a reply we've been expecting.
		 *	This can happen legitimately if, when handling a DORA, we've sent the Request and are
		 *	now expecting an Ack, but then we receive another Offer (from another DHCP server).
		 *
		 *	We can also receive a NAK, even though we're requesting a lease that we were offered.
		 *	This means someone acquired the lease before us. A DHCP server can offer the same lease more than once.
		 *	This is more likely to happen if the pool of remaining available addresses is small.
		 */
		DEBUG3("Discarding received reply code %d (session state: %d)", reply->code, session->state);

		dpc_packet_digest_fprint(fr_log_fp, session, reply, DPC_PACKET_RECEIVED_DISCARD);
		//TODO: print configurable? but not based on packet trace lvl (because this should not happen)

		/* If not broadcasting, don't retransmit if we get a NAK.
		 */
		bool retain = true;
		if (reply->code == FR_DHCP_NAK && !session->input->ext.with_pcap) {
			retain = false;
		}

		fr_radius_packet_free(&reply);
		return retain;
	}

	session->reply = reply;
	talloc_steal(session, reply); /* Reparent reply packet (allocated on NULL context) so we don't leak. */

	/* Compute rtt.
	 * Relative to initial request so we get the real rtt (regardless of retransmissions).
	 */
	session->ftd_rtt = session->reply->timestamp - session->fte_init;

	dpc_packet_fprint(fr_log_fp, session, reply, DPC_PACKET_RECEIVED); /* print reply packet. */

	/* Update statistics. */
	dpc_statistics_update(session, session->request, session->reply);

	/*
	 *	If dealing with a DORA transaction, after a valid Offer we need to send a Request.
	 */
	if (session->state == DPC_STATE_DORA_EXPECT_OFFER && session->reply->code == FR_DHCP_OFFER) {
		return dpc_session_dora_request(session);
	}

	/*
	 *	We've just completed a DORA transaction.
	 */
	if (session->state == DPC_STATE_DORA_EXPECT_ACK && session->reply->code == FR_DHCP_ACK) {
		/*
		 *	Update statistics for DORA workflows.
		 */
		fr_time_delta_t rtt;
		rtt = session->reply->timestamp - session->fte_start;
		dpc_tr_stats_update(DPC_TR_DORA, rtt);

		/*
		 *	Maybe send a Decline or Release now.
		 */
		if (session->input->ext.workflow == DPC_WORKFLOW_DORA_DECLINE) {
			return dpc_session_dora_decline(session);
		} else if (session->input->ext.workflow == DPC_WORKFLOW_DORA_RELEASE) {
			return dpc_session_dora_release(session);
		}

		return false; /* Session is done. */
	}

	/*
	 *	There may be more Offer replies, from other DHCP servers. Wait for them.
	 */
	if (multi_offer && session->input->ext.with_pcap && session->reply->code == FR_DHCP_OFFER) {
		DEBUG3("Waiting for more replies from other DHCP servers");
		session->state = DPC_STATE_WAIT_OTHER_REPLIES;
		/* Note: there is no need to arm a new event timeout. The initial timer is still running. */

		return true; /* Session is not finished. */
	}

	return false; /* Session is done. */
}

/*
 *	Handling of a DORA workflow. After receiving an Offer, try and build a Request.
 *	Encode and send the packet, then wait for the reply.
 *	Returns: true if Request was sent, false otherwise.
 */
static bool dpc_session_dora_request(dpc_session_ctx_t *session)
{
	VALUE_PAIR *vp_xid, *vp_yiaddr, *vp_server_id, *vp_requested_ip;
	DHCP_PACKET *packet;

	/* Get the Offer xid. */
	vp_xid = fr_pair_find_by_da(session->reply->vps, attr_dhcp_transaction_id, TAG_ANY);
	if (!vp_xid) { /* Should never happen (DHCP field). */
		return false;
	}

	/* Offer must provide yiaddr (DHCP-Your-IP-Address). */
	vp_yiaddr = fr_pair_find_by_da(session->reply->vps, attr_dhcp_your_ip_address, TAG_ANY);
	if (!vp_yiaddr || vp_yiaddr->vp_ipv4addr == 0) {
		DEBUG2("Session DORA: no yiaddr provided in Offer reply");
		return false;
	}

	/* Offer must contain option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	vp_server_id = fr_pair_find_by_da(session->reply->vps, attr_dhcp_server_identifier, TAG_ANY);
	if (!vp_server_id || vp_server_id->vp_ipv4addr == 0) {
		DEBUG2("Session DORA: no option 54 (server id) provided in Offer reply");
		return false;
	}

	/*
	 *	Prepare a new DHCP Request packet.
	 */
	DEBUG3("DORA: received valid Offer, now preparing Request");

	packet = dpc_request_init(session, session, session->input);
	if (!packet) return false;

	packet->code = FR_DHCP_REQUEST;
	session->state = DPC_STATE_DORA_EXPECT_ACK;

	/*
	 *	Use information from the Offer reply to complete the new packet.
	 */

	/*
	 *	Add option 50 Requested IP Address (DHCP-Requested-IP-Address) = yiaddr
	 *	First remove previous option 50 if one was provided (server may have offered a different lease).
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_requested_ip_address);
	vp_requested_ip = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_requested_ip_address);
	ncc_pair_copy_value(vp_requested_ip, vp_yiaddr);

	/* Add option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_server_id));

	/* Reset input xid to value obtained from the Offer reply. */
	session->input->ext.xid = vp_xid->vp_uint32;

	/*
	 *	New packet is ready. Free old packet and its reply. Then use the new packet.
	 */
	talloc_free(session->reply);
	session->reply = NULL;

	if (!dpc_packet_list_id_free(pl, session->request)) { /* Should never fail. */
		SERROR("Failed to free from packet list, id: %u", session->request->id);
	}
	talloc_free(session->request);
	session->request = packet;

	if (session->num_send == 1) {
		session_num_parallel --; /* Not a session "initial request" anymore. */

		SDEBUG2("Session post initial request - active sessions: %u (in: %u), parallel: %u",
		    session_num_active, session_num_in_active, session_num_parallel);
	}

	session->num_send ++;

	/*
	 *	Encode and send packet.
	 */
	if (dpc_send_one_packet(session, &session->request) < 0) {
		return false;
	}

	/*
	 *	Arm request timeout.
	 */
	dpc_event_add_request_timeout(session, NULL);

	return true; /* Session is not finished. */
}

/*
 *	Handling of a DORA workflow. After receiving an Ack, try and build a Release.
 *	Encode and send the packet. (no reply is expected)
 */
static bool dpc_session_dora_release(dpc_session_ctx_t *session)
{
	VALUE_PAIR *vp_yiaddr, *vp_server_id, *vp_ciaddr;
	DHCP_PACKET *packet;

	/* Ack provides IP address assigned to client in field yiaddr (DHCP-Your-IP-Address). */
	vp_yiaddr = fr_pair_find_by_da(session->reply->vps, attr_dhcp_your_ip_address, TAG_ANY);
	if (!vp_yiaddr || vp_yiaddr->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Release: no yiaddr provided in Ack reply");
		return false;
	}

	/* Ack must contain option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	vp_server_id = fr_pair_find_by_da(session->reply->vps, attr_dhcp_server_identifier, TAG_ANY);
	if (!vp_server_id || vp_server_id->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Release: no option 54 (server id) provided in Ack reply");
		return false;
	}

	/*
	 *	Prepare a new DHCP Release packet.
	 */
	DEBUG3("DORA-Release: received valid Ack, now preparing Release");

	packet = dpc_request_init(session, session, session->input);
	if (!packet) return false;

	packet->code = FR_DHCP_RELEASE;
	session->state = DPC_STATE_NO_REPLY;

	/*
	 *	Use information from the Ack reply to complete the new packet.
	 */

	/* Add field ciaddr (DHCP-Client-IP-Address) = yiaddr */
	vp_ciaddr = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_client_ip_address);
	ncc_pair_copy_value(vp_ciaddr, vp_yiaddr);

	/*
	 *	Remove eventual option 50 Requested IP Address.
	 *	(it may be provided for Discover, but must *not* be in Release)
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_requested_ip_address);

	/* Add option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_server_id));

	/* xid is supposed to be selected by client. Let the program pick a new one. */
	session->input->ext.xid = DPC_PACKET_ID_UNASSIGNED;

	/*
	 *	New packet is ready. Free old packet and its reply. Then use the new packet.
	 */
	talloc_free(session->reply);
	session->reply = NULL;

	if (!dpc_packet_list_id_free(pl, session->request)) { /* Should never fail. */
		SERROR("Failed to free from packet list, id: %u", session->request->id);
	}
	talloc_free(session->request);
	session->request = packet;

	if (session->num_send == 1) {
		session_num_parallel --; /* Not a session "initial request" anymore. */

		SDEBUG2("Session post initial request - active sessions: %u (in: %u), parallel: %u",
		    session_num_active, session_num_in_active, session_num_parallel);
	}

	session->num_send ++;

	/*
	 *	Encode and send packet.
	 */
	if (dpc_send_one_packet(session, &session->request) < 0) {
		return false;
	}
	// Note: if the DORA was broadcast, we're also broadcasting the Release. It works. But...
	// According to RFC 2131, a Release is supposed to be unicast. For this to work we would need the
	// IP address to be configured. Which is probably not the case. So it's better to just broadcast anyway.

	return false; /* Session is done. */
}

/*
 *	Handling of a DORA workflow. After receiving an Ack, try and build a Decline.
 *	Encode and send the packet. (no reply is expected)
 */
static bool dpc_session_dora_decline(dpc_session_ctx_t *session)
{
	VALUE_PAIR *vp_yiaddr, *vp_server_id, *vp_ciaddr, *vp_requested_ip;
	DHCP_PACKET *packet;

	/* Ack provides IP address assigned to client in field yiaddr (DHCP-Your-IP-Address). */
	vp_yiaddr = fr_pair_find_by_da(session->reply->vps, attr_dhcp_your_ip_address, TAG_ANY);
	if (!vp_yiaddr || vp_yiaddr->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Decline: no yiaddr provided in Ack reply");
		return false;
	}

	/* Ack must contain option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	vp_server_id = fr_pair_find_by_da(session->reply->vps, attr_dhcp_server_identifier, TAG_ANY);
	if (!vp_server_id || vp_server_id->vp_ipv4addr == 0) {
		DEBUG2("Session DORA-Decline: no option 54 (server id) provided in Ack reply");
		return false;
	}

	/*
	 *	Prepare a new DHCP Decline packet.
	 */
	DEBUG3("DORA-Decline: received valid Ack, now preparing Decline");

	packet = dpc_request_init(session, session, session->input);
	if (!packet) return false;

	packet->code = FR_DHCP_DECLINE;
	session->state = DPC_STATE_NO_REPLY;

	/*
	 *	Use information from the Ack reply to complete the new packet.
	 */

	/* Add field ciaddr (DHCP-Client-IP-Address) = yiaddr */
	vp_ciaddr = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_client_ip_address);
	ncc_pair_copy_value(vp_ciaddr, vp_yiaddr);

	/*
	 *	Add option 50 Requested IP Address (DHCP-Requested-IP-Address) = yiaddr
	 *	First remove previous option 50 if one was provided (server may have offered a different lease).
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_requested_ip_address);
	vp_requested_ip = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_requested_ip_address);
	ncc_pair_copy_value(vp_requested_ip, vp_yiaddr);

	/* Add option 54 Server Identifier (DHCP-DHCP-Server-Identifier). */
	fr_pair_add(&packet->vps, fr_pair_copy(packet, vp_server_id));

	/* xid is supposed to be selected by client. Let the program pick a new one. */
	session->input->ext.xid = DPC_PACKET_ID_UNASSIGNED;

	/*
	 *	New packet is ready. Free old packet and its reply. Then use the new packet.
	 */
	talloc_free(session->reply);
	session->reply = NULL;

	if (!dpc_packet_list_id_free(pl, session->request)) { /* Should never fail. */
		SERROR("Failed to free from packet list, id: %u", session->request->id);
	}
	talloc_free(session->request);
	session->request = packet;

	session->num_send ++;

	/*
	 *	Encode and send packet.
	 */
	if (dpc_send_one_packet(session, &session->request) < 0) {
		return false;
	}

	return false; /* Session is done. */
}

/*
 *	Prepare a request to be sent as if relayed through a gateway.
 */
static void dpc_request_gateway_handle(DHCP_PACKET *packet, ncc_endpoint_t *gateway)
{
	if (!gateway) return;

	char ep_buf[NCC_ENDPOINT_STRLEN] = "";
	DEBUG3("Assigning packet to gateway: %s", ncc_endpoint_sprint(ep_buf, gateway));

	/*
	 *	We've been told to handle sent packets as if relayed through a gateway.
	 *	This means:
	 *	- packet source IP / port = gateway IP / port (those we've already set)
	 *	- giaddr = gateway IP
	 *	- hops = 1 (arbitrary)
	 *	All of these can be overriden (entirely or partially) through input vps.
	 *	Note: the DHCP server will respond to the giaddr, not the packet source IP. Normally they are the same.
	 */
	VALUE_PAIR *vp_giaddr, *vp_hops;

	/* set giaddr if not specified in input vps (DHCP-Gateway-IP-Address). */
	vp_giaddr = fr_pair_find_by_da(packet->vps, attr_dhcp_gateway_ip_address, TAG_ANY);
	if (!vp_giaddr) {
		vp_giaddr = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_gateway_ip_address);
		vp_giaddr->vp_ipv4addr = gateway->ipaddr.addr.v4.s_addr;
		vp_giaddr->vp_ip.af = AF_INET;
		vp_giaddr->vp_ip.prefix = 32;
	}

	/* set hops if not specified in input vps (DHCP-Hop-Count). */
	vp_hops = fr_pair_find_by_da(packet->vps, attr_dhcp_hop_count, TAG_ANY);
	if (!vp_hops) {
		vp_hops = ncc_pair_create_by_da(packet, &packet->vps, attr_dhcp_hop_count);
		vp_hops->vp_uint8 = 1;
	}
}

/*
 *	Initialize a DHCP packet from an input item.
 */
static DHCP_PACKET *dpc_request_init(TALLOC_CTX *ctx, dpc_session_ctx_t *session, dpc_input_t *input)
{
	DHCP_PACKET *request;

	MEM(request = fr_radius_alloc(ctx, true)); /* Note: this sets id to -1. */

	session->retransmit = 0;
	session->ftd_rtt = 0;

	/* Store request initial time. */
	session->fte_init = fr_time();

	/* Fill in the packet value pairs. */
	ncc_pair_list_append(request, &request->vps, input->vps);

	if (input->do_xlat) {
		/*
		 *	Perform xlat expansions as required.
		 */
		ncc_xlat_set_num(input->id); /* Initialize xlat context for processing this input. */

		if (dpc_pair_list_xlat(request, request->vps) < 0) {
			talloc_free(request);
			return NULL;
		}
	}

	/* Prepare gateway handling. */
	dpc_request_gateway_handle(request, session->gateway);

	/*
	 *	Use values prepared earlier.
	 */
	request->code = input->ext.code;
	request->src_port = session->src.port;
	request->dst_port = session->dst.port;
	request->src_ipaddr = session->src.ipaddr;
	request->dst_ipaddr = session->dst.ipaddr;

	char from_to_buf[DPC_FROM_TO_STRLEN] = "";
	DEBUG3("New packet allocated (code: %u, %s)", request->code,
	       dpc_packet_from_to_sprint(from_to_buf, request, false));

	return request;
}

/*
 *	Encode a DHCP packet.
 */
static int dpc_dhcp_encode(DHCP_PACKET *packet)
{
	int r;
	VALUE_PAIR *vp;

	/*
	 *	If DHCP encoded data is provided, use it as is. Do not call fr_dhcpv4_packet_encode.
	 */
	if ((vp = ncc_pair_find_by_da(packet->vps, attr_encoded_data))) {
		packet->data_len = vp->vp_length;
		packet->data = talloc_zero_array(packet, uint8_t, packet->data_len);
		memcpy(packet->data, vp->vp_octets, vp->vp_length);

		/* Overwrite xid in packet data with id allocated. */
		if (packet->data_len >= 8) {
			uint32_t lvalue = htonl(packet->id);
			uint8_t *p = packet->data + 4;
			memcpy(p, &lvalue, 4);
		}
		return 0;
	}

	/*
	 *	Reset DHCP-Transaction-Id to xid allocated (it may not be what was asked for,
	 *	the requested id may not have been available).
	 *	Note: function fr_dhcpv4_packet_encode uses this to (re)write packet->id.
	 */
	fr_pair_delete_by_da(&packet->vps, attr_dhcp_transaction_id);
	vp = fr_pair_afrom_da(packet, attr_dhcp_transaction_id);
	vp->vp_uint32 = packet->id;
	fr_pair_add(&packet->vps, vp);

	r = fr_dhcpv4_packet_encode(packet); /* This always returns 0. */
	/* Note: fr_dhcpv4_packet_encode encodes a NAK if there is no message type provided. */

	fr_strerror(); /* Clear the error buffer */

	/*
	 *	Note: if packet data len < 300 (DEFAULT_PACKET_SIZE), fr_dhcpv4_packet_encode will pad with
	 *	zeroes at the end of the packet data to fill up 300 octets.
	 *	From protocols/dhcpv4/dhcpv4.h: "Some clients silently ignore responses less than 300 bytes."
	 *	(We are a client, but not that dumb.)
	 */

	return r;
}

/*
 *	Store transport information in session context.
 */
static void dpc_session_set_transport(dpc_session_ctx_t *session, dpc_input_t *input)
{
	/*
	 *	Default: use source / destination from input, if provided.
	 */
	session->src = input->ext.src;
	session->dst = input->ext.dst;

	/*
	 *	Associate session to gateway, if one is defined (or several).
	 */
	if (!is_ipaddr_defined(session->src.ipaddr) && gateway_list) {
		NCC_DLIST_USE_NEXT(gateway_list, session->gateway);
		session->src = *(session->gateway);
	}
}


/**
 * Check if a given input item is currently available for starting sessions.
 * If not get the time when it will be.
 *
 * @param[in]  input     item considered.
 * @param[out] fte_when  time when it will be available (0 if available now).
 *
 * @return true = input is available, false = input is not available.
 */
static bool dpc_item_available(dpc_input_t *input, fr_time_t *fte_when)
{
	fr_time_delta_t ftd_elapsed = dpc_job_elapsed_fr_time_get();
	fr_time_delta_t ftd_avail = 0;

	*fte_when = 0;

	/* Check for start delay.
	 */
	if (ftd_elapsed < input->ftd_start_delay) {
		ftd_avail = input->ftd_start_delay;
	}

	/* Check for null input segment.
	 */
	ncc_segment_t *segment = dpc_input_get_segment(input);
	if (segment && segment->type == NCC_SEGMENT_RATE_NULL) {
		if (segment->ftd_end > ftd_avail) {
			ftd_avail = segment->ftd_end;

		} else if (!segment->ftd_end) {
			/* This input will never be available again.
			 * We cannot return "infinity" so we arbitrarily add 10 seconds.
			 * And mark input as done.
			 */
			ftd_avail += ncc_float_to_fr_time(10);

			input->done = true;
			input->fte_end = fr_time();
		}
	}

	if (ftd_avail) {
		*fte_when = fte_job_start + ftd_avail;
		return false;
	}

	return true;
}

/*
 *	Get the usage status of an input item: waiting, active, or terminated.
 */
static char dpc_item_get_status(dpc_input_t *input)
{
	if (input->done) return 'T';
	if (!input->fte_start) return 'W';
	return 'A';
}

/*
 *	Get the elapsed time of an input item from when it started being used.
 */
static double dpc_item_get_elapsed(dpc_input_t *input)
{
	if (!input->fte_start) {
		return 0; /* Item has not been used yet. */
	}

	/* Get elapsed time from when this input started being used. */
	fr_time_delta_t ftd_elapsed;
	if (input->fte_end) {
		ftd_elapsed = input->fte_end - input->fte_start;
	} else {
		ftd_elapsed = dpc_fr_time() - input->fte_start;
	}

	return ncc_fr_time_to_float(ftd_elapsed);
}

/*
 *	Get the use rate of an input item, relative to the point at which it started being used,
 *	up to now (if it's still active) or the last time is was used.
 */
static bool dpc_item_get_rate(double *out_rate, dpc_input_t *input)
{
	*out_rate = 0;

	if (!input->fte_start) {
		return false; /* Item has not been used yet. */
	}

	double elapsed = dpc_item_get_elapsed(input);

	if (input->num_use < CONF.min_session_for_rps
	    || elapsed < CONF.min_time_for_rps) return false;

	*out_rate = (double)input->num_use / elapsed;
	return true;
}

/**
 * Get input current segment (or default).
 *
 * @return the segment.
 */
static ncc_segment_t *dpc_input_get_segment(dpc_input_t *input)
{
	input->segment_cur = dpc_get_current_segment(input->segments, input->segment_cur);

	ncc_segment_t *segment = input->segment_cur;
	if (!segment) {
		/*
		 * No current input segment: use input default.
		 */
		segment = input->segment_dflt;
	}

	return segment;
}

/*
 *	Check if an item is currently rate limited or not.
 *	Return: true = item is not allowed to start new sessions at the moment (rate limit enforced).
 */
static bool dpc_item_rate_limited(dpc_input_t *input)
{
	uint32_t max_new_sessions = 0;
	bool limit;

	ncc_segment_t *segment = dpc_input_get_segment(input);

	limit = dpc_rate_limit_calc_gen(&max_new_sessions, false, segment, segment->num_use);

	/* If no limit is currently enforced, item can be used.
	 * Otherwise, it can be used (at least once) if the max number of new sessions is not zero.
	 */
	if (!limit) return false;
	else return (max_new_sessions == 0);
}

/**
 * Get an eligible input item from input list (round robin on all inputs).
 * Ensure it can be used for starting new sessions.
 *
 * In non template mode, the selected item is removed from the list.
 *
 * @return input item, NULL if none is eligible at this time.
 */
static dpc_input_t *dpc_get_input(void)
{
	uint32_t checked = 0, not_done = 0;
	fr_time_t now = fr_time();

	if (no_input_available && fte_input_available > now) {
		/*
		 * We've already determined that no input is available at this time.
		 */
		return NULL;
	}
	no_input_available = false;
	fte_input_available = 0;

	while (checked < NCC_DLIST_SIZE(&input_list)) {
		dpc_input_t *input;
		NCC_DLIST_USE_NEXT(&input_list, input);

		checked++;

		if (input->done) continue;

		/* Check if input cannot be used anymore, if so tag it and store current timestamp.
		 */
		if (input->max_use && input->num_use >= input->max_use) {
			/* Max number of uses reached for this input. */
			DEBUG("Max number of uses (%u) reached for input (id: %u)", input->num_use, input->id);
			input->done = true;
			input->fte_end = now;
			continue;
		}
		if (input->fte_max_start && now > input->fte_max_start) {
			/* Max session start time reached for this input. */
			DEBUG("Max session start time reached for input (id: %u)", input->id);
			input->done = true;
			input->fte_end = now;
			continue;
		}

		/* Check if item can be used to start new sessions.
		 */
		fr_time_t when;
		if (!dpc_item_available(input, &when)) {

			/* Keep track of when any input will be available at the soonest. */
			if (!fte_input_available || when < fte_input_available) fte_input_available = when;

			/* Called function might have decided this input is done. */
			if (!input->done) not_done++;
			continue;
		}

		not_done++;

		if (dpc_item_rate_limited(input)) continue;

		if (!CONF.template) {
			/* In non-template mode, item is removed from the list. */
			NCC_DLIST_DRAW(&input_list, input);
		}
		return input;
	}

	if (not_done == 0) {
		INFO("No remaining active input: will not start any new session.");
		dpc_end_start_sessions();
	}

	no_input_available = true;
	return NULL;
}

/**
 * Initialize a new session from input.
 *
 * @param[in] ctx  talloc context.
 *
 * @return new session, NULL if unable to initialize one.
 */
static dpc_session_ctx_t *dpc_session_init_from_input(TALLOC_CTX *ctx)
{
	dpc_input_t *input = NULL;
	dpc_session_ctx_t *session = NULL;
	DHCP_PACKET *packet = NULL;

	input = dpc_get_input();
	if (!input) { /* No input: cannot create new session. */
		return NULL;
	}

	DEBUG3("Initializing a new session (id: %u) from input (id: %u)", session_num, input->id);

	/* Store time of first session initialized. */
	if (!fte_sessions_ini_start) {
		fte_sessions_ini_start = fr_time();
	}

	/* If this is the first time this input is used, store current time. */
	if (input->num_use == 0) {
		DEBUG("Input (id: %u) %s%sstart (max use: %u, duration: %.1f s, rate: %.1f)",
		      input->id, input->name ? input->name : "", input->name ? " " : "",
		      input->max_use, input->max_duration, input->rate_limit);

		input->fte_start = fr_time();

		/* Also store input max start time, if applicable. */
		if (input->max_duration) {
			input->fte_max_start = input->fte_start + ncc_float_to_fr_time(input->max_duration);
		}

		/* If there is a global max start time, store whichever comes first (input, global). */
		if (CONF.fte_start_max
		    && (!input->fte_max_start || input->fte_max_start > CONF.fte_start_max)) {
			input->fte_max_start = CONF.fte_start_max;
		}
	}

	input->num_use ++;

	/*
	 *	If not using a template, copy this input item if it has to be used again.
	 */
	if (!CONF.template && input->num_use < input->max_use) {
		DEBUG3("Input (id: %u) will be reused (num use: %u, max: %u)",
		       input->id, input->num_use, input->max_use);
		dpc_input_t *input_dup = dpc_input_item_copy(ctx, input);
		if (input_dup) {
			/*
			 *	Add it to the list of input items.
			 */
			NCC_DLIST_ENQUEUE(&input_list, input_dup);
		}
	}

	/*
	 *	Initialize the new session.
	 */
	MEM(session = talloc_zero(ctx, dpc_session_ctx_t));
	dpc_session_set_transport(session, input);

	/*
	 *	Prepare a DHCP packet to send for this session.
	 */
	packet = dpc_request_init(ctx, session, input);
	if (!packet) {
		/* Free this input now if we could not initialize a session from it. */
		PERROR("Failed to initialize session from input (id: %u)", input->id);

		talloc_free(session);

		/* Remove item from list before freeing. */
		NCC_DLIST_DRAW(&input_list, input);
		talloc_free(input);
		return NULL;
	}

	session->id = session_num ++;

	session->request = packet;
	talloc_steal(session, packet);

	session->input = input; /* Reference to the input (note: in template mode it doesn't belong to us). */
	if (!CONF.template) talloc_steal(session, input);

	/*
	 *	Prepare dealing with reply and workflow sequence.
	 */
	session->reply_expected = is_dhcp_reply_expected(packet->code); /* Some messages do not get a reply. */

	if (input->ext.workflow) {
		session->state = DPC_STATE_DORA_EXPECT_OFFER; /* All workflows start with a Discover. */
	} else {
		session->state = (session->reply_expected ? DPC_STATE_EXPECT_REPLY : DPC_STATE_NO_REPLY);
	}

	/* Store session start time. */
	session->fte_start = fr_time();

	session_num_in ++;
	session_num_active ++;
	session_num_in_active ++;
	session_num_parallel ++;
	fte_last_session_in = fr_time();

	SDEBUG2("New session initialized from input - active sessions: %u (in: %u), parallel: %u",
	        session_num_active, session_num_in_active, session_num_parallel);

	/* If time-data is enabled, store session in time-data context. */
	if (CONF.with_timedata) {
		uint32_t target_add = 0;
		ncc_segment_t *segment = input->segment_cur;

		if (segment) {
			/* Compute the segment target, which is the total number of sessions that should have been started
			 * using this segment to meet the specified rate.
			 */
			uint32_t target = 0;
			dpc_rate_limit_calc_gen(&target, true, segment, 0);
			target_add = target - segment->target;
			segment->target = target;
		}
		dpc_timedata_store_session_stat(input->id, input->name, segment, target_add);
	}

	/*
	 * Update segments usage.
	 */

	/* Always update default global segment. */
	segment_default.num_use ++;

	/* If the session belongs to a global time segment (explicitly defined, i.e. not the default), update it. */
	if (segment_cur) {
		segment_cur->num_use ++;
	}

	/* If session input has a default segment (which is the case if input is rate limited), update it. */
	if (input->segment_dflt) input->segment_dflt->num_use ++;

	/* If the session belongs to an input-scoped time segment (explicitly defined), update it. */
	if (input->segment_cur) {
		input->segment_cur->num_use ++;
	}

	return session;
}

/*
 *	One session is finished.
 */
static void dpc_session_finish(dpc_session_ctx_t *session)
{
	if (!session) return;

	DEBUG3("Terminating session (id: %u)", session->id);

	/* Remove the packet from the list, and free the id we've been using. */
	if (session->request && session->request->id != DPC_PACKET_ID_UNASSIGNED) {
		if (!dpc_packet_list_id_free(pl, session->request)) { /* Should never fail. */
			SERROR("Failed to free from packet list, id: %u", session->request->id);
		}
	}

	/* Clear the event timer if it is armed. */
	if (session->event) {
		fr_event_timer_delete(event_list, &session->event);
		session->event = NULL;
	}

	/* Update counters. */
	session_num_active --;
	if (session->input) {
		session_num_in_active --;
		if (session->num_send == 1) session_num_parallel --; /* This was a session "initial request". */
		//gettimeofday(&tve_last_session_in, NULL); // why ?? zzz
	}

	SDEBUG2("Session terminated - active sessions: %u (in: %u), parallel: %u",
	         session_num_active, session_num_in_active, session_num_parallel);
	talloc_free(session);
}

/*
 *	Receive and handle reply packets.
 */
static void dpc_loop_recv(void)
{
	bool done = false;
	fr_time_t now, when;
	fr_time_delta_t wait_max = 0;
	int ev_peek;
	bool start_ready;

	while (!done) {
		/*
		 * Do not listen with no delay if we don't have to.
		 * It will avoid needlessly hogging one full CPU, which is bad form.
		 */
		now = fr_time();

		/* Next scheduled event (if there is one). */
		ev_peek = ncc_fr_event_timer_peek(event_list, &when);

		/* Whether we are ready to start new sessions right now. */
		start_ready = (start_sessions_flag && session_num_parallel < CONF.session_max_active && !no_input_available);

		/* Don't wait if we are ready to start new sessions.
		 * Or if we're not starting new sessions.
		 */
		if (start_ready || !start_sessions_flag) {
			wait_max = 0;

		} else {
			/* Do not wait past a scheduled event.
			 * If we're waiting for a reply, we have at least one scheduled event.
			 */
			if (ev_peek) {
				if (when > now) wait_max = when - now; /* No negative. */
			}

			/* If we would like to start sessions, but cannot because no input is available at this point. */
			if (fte_input_available > now) {
				fr_time_delta_t delta = fte_input_available - now;
				if (!wait_max || delta < wait_max) wait_max = delta;
			}
		}

		/*
		 *	Receive and process packets until there's nothing left incoming.
		 */
		if (dpc_recv_one_packet(wait_max) < 1) break;
	}
}

/**
 * Get elapsed time from the start of a given time segment.
 */
static double dpc_segment_get_elapsed(ncc_segment_t *segment)
{
	fr_time_delta_t ftd_ref;
	fr_time_delta_t ftd_elapsed = dpc_job_elapsed_fr_time_get();

	if (ftd_elapsed < segment->ftd_start) {
		return 0; /* Segment is not started yet. */
	}

	if (segment->ftd_end && ftd_elapsed >= segment->ftd_end) {
		/*
		 * Current time is beyond segment end.
		 */
		ftd_ref = segment->ftd_end - segment->ftd_start;
	} else {
		ftd_ref = ftd_elapsed - segment->ftd_start;
	}

	return ncc_fr_time_to_float(ftd_ref);
}

/**
 * Get the use rate of a time segment.
 */
static bool dpc_segment_get_rate(double *out_rate, ncc_segment_t *segment)
{
	*out_rate = 0;

	double elapsed = dpc_segment_get_elapsed(segment);

	if (segment->num_use < CONF.min_session_for_rps
	    || elapsed < CONF.min_time_for_rps) return false;

	*out_rate = (double)segment->num_use / elapsed;
	return true;
}

/**
 * For a given segment list, get the time segment matching current elapsed time (if any).
 */
static ncc_segment_t *dpc_get_current_segment(ncc_dlist_t *list, ncc_segment_t *segment_pre)
{
	if (!list) return NULL;

	fr_time_delta_t ftd_elapsed = fr_time() - fte_job_start;
	ncc_segment_t *segment = ncc_segment_from_elapsed_time(list, segment_pre, ftd_elapsed);

	if (segment != segment_pre) {
		char interval_buf[NCC_SEGMENT_INTERVAL_STRLEN];

		if (segment) {
			DEBUG("Segment (id: %u) %s%s%s start (elapsed: %f)", segment->id,
			      segment->name ? segment->name : "", segment->name ? " " : "",
			      ncc_segment_interval_snprint(interval_buf, sizeof(interval_buf), segment),
			      ncc_fr_time_to_float(ftd_elapsed));
		} else {
			DEBUG("Segment (id: %u) %s is no longer eligible (elapsed: %f, num use: %u)", segment_pre->id,
			      ncc_segment_interval_snprint(interval_buf, sizeof(interval_buf), segment_pre),
			      ncc_fr_time_to_float(ftd_elapsed), segment_pre->num_use);
		}
	}

	return segment;
}

/**
 * Figure out how to enforce a rate limit. To do so we limit the number of new sessions allowed to be started.
 * This can be used globally (to enforce a global rate limit on all sessions), or per-input.
 *
 * Note: if we transition from a rate-limited segment to a global rate limit, this can lead to a temporary spike
 * in started sessions, which can be much higher than the specified global rate.
 * Although this is not a bug (the effective global rate is computed from the program start), this can be a bit odd
 * when looking at graphs.
 *
 * @param[out] max_new_sessions  limit of new sessions allowed to be started.
 * @param[in]  strict            perform strict calculation of limit at current time.
 *                               (false means try to be smart and allow a bit more to compensate for internal tasks)
 * @param[in]  segment           time segment on which the limit is to be computed.
 * @param[in]  cur_num_started   how many sessions have been started so far (within the segment).
 *                               (or 0 to compute the segment current target)
 *
 * @return true = a limit is to be enforced, false otherwise.
 */
static bool dpc_rate_limit_calc_gen(uint32_t *max_new_sessions, bool strict, ncc_segment_t *segment, uint32_t cur_num_started)
{
	double elapsed_ref;
	uint32_t session_limit;
	double segment_duration = 0;

	if (!segment) {
		/* No segment entails no limit. */
		return false;
	}

	ncc_assert(segment->type != NCC_SEGMENT_RATE_INVALID);

	if (segment->type == NCC_SEGMENT_RATE_UNBOUNDED
	   || (segment->type == NCC_SEGMENT_RATE_FIXED && !segment->rate_limit) ) {
		/* No limit. */
		return false;
	}

	if (segment->type == NCC_SEGMENT_RATE_NULL) {
		*max_new_sessions = 0;
		return true;
	}

	/* Get elapsed time. */
	elapsed_ref = dpc_segment_get_elapsed(segment);

	if (!strict) {
		if (elapsed_ref < CONF.rate_limit_min_ref_time) {
			/*
			 * Consider a minimum elapsed time interval for the beginning.
			 * We may start more sessions than the desired rate before this time, but this will be quickly corrected.
			 */
			elapsed_ref = CONF.rate_limit_min_ref_time;
		}

		/* Allow to start a bit more right now to compensate for server delay and our own internal tasks. */
		elapsed_ref += CONF.rate_limit_time_lookahead;
	}

	/* Don't go beyond segment end. */
	if (segment->ftd_end) {
		segment_duration = ncc_fr_time_to_float(segment->ftd_end - segment->ftd_start);
		if (elapsed_ref > segment_duration) elapsed_ref = segment_duration;
	}

	if (segment->type == NCC_SEGMENT_RATE_FIXED) {
		/*
		 * Fixed rate.
		 */
		session_limit = segment->rate_limit * elapsed_ref;

	} else {
		/*
		 * Linear rate.
		 * Note: segment end cannot be 0 (INF) in this case, so we always have a defined segment duration.
		 */
		double r1 = segment->rate_limit_range.start;
		double r2 = segment->rate_limit_range.end;
		double r3 = r1 + (r2 - r1) * (elapsed_ref / segment_duration);

		session_limit = (r1 * elapsed_ref) + (r3 - r1) * (elapsed_ref / 2);
	}

	if (!session_limit) {
		session_limit = 1; /* So we always start at least one session at the beginning. */
	}

	if (cur_num_started >= session_limit) {
		/* Already beyond limit, so don't start new sessions for now.
		 */
		*max_new_sessions = 0;
	} else {
		*max_new_sessions = session_limit - cur_num_started;
	}
	return true;
}

/*
 *	If a global rate limit is applicable, get the limit of new sessions allowed to be started for now.
 */
static bool dpc_rate_limit_calc(uint32_t *max_new_sessions)
{
	segment_cur = dpc_get_current_segment(segment_list, segment_cur);

	ncc_segment_t *segment = segment_cur;
	if (!segment) {
		/*
		 * No current segment: use default (with fixed global rate limit if set, otherwise unbounded).
		 */
		segment = &segment_default;
	}

	return dpc_rate_limit_calc_gen(max_new_sessions, false, segment, segment->num_use);
}


/*
 *	Stop starting new sessions.
 */
static void dpc_end_start_sessions(void)
{
	if (start_sessions_flag) {
		DEBUG2("Stop starting new sessions");

		start_sessions_flag = false;
		fte_sessions_ini_end = fr_time();

		/* Also mark all input as done. */
		dpc_input_t *input = NCC_DLIST_HEAD(&input_list);
		while (input) {
			input->done = true;
			input->fte_end = fte_sessions_ini_end;

			input = NCC_DLIST_NEXT(&input_list, input);
		}
	}
}

/*
 *	Start new sessions, if possible.
 *	Returns: number of new sessions effectively started.
 */
static uint32_t dpc_loop_start_sessions(void)
{
	bool done = false;
	uint32_t num_started = 0; /* Number of sessions started in this iteration. */

 	/* If we've flagged that sessions should be be started anymore, return immediately. */
	if (!start_sessions_flag) return 0;

	uint32_t limit_new_sessions = 0;
	bool do_limit = dpc_rate_limit_calc(&limit_new_sessions);

	/* Set a max allowed loop time - don't loop forever in case of packets not expecting replies. */
	fr_time_delta_t fte_loop_max = fr_time() + ftd_loop_max_time;

	/* Also limit time up to the next scheduled statistics event. */
	if (fte_progress_stat && fte_loop_max > fte_progress_stat) {
		fte_loop_max = fte_progress_stat;
	}

	while (!done) {
		/* Max loop time limit reached. */
		fr_time_t now = fr_time();
		if (now > fte_loop_max) {
			DEBUG3("Loop time limit reached, started: %u", num_started);
			break;
		}

		/* Max session limit reached. */
		if (CONF.session_max_num && session_num >= CONF.session_max_num) {
			INFO("Max number of sessions (%u) reached: will not start any new session.", CONF.session_max_num);
			dpc_end_start_sessions();
			break;
		}

		/* Time limit reached. */
		if (CONF.duration_start_max && dpc_job_elapsed_time_get() >= CONF.duration_start_max) {
			INFO("Max duration (%.3f s) reached: will not start any new session.", CONF.duration_start_max);
			dpc_end_start_sessions();
			break;
		}

		/* No more input. */
		if (!CONF.template && NCC_DLIST_SIZE(&input_list) == 0) {
			dpc_end_start_sessions();
			break;
		}

		/* Max active session reached. Try again later when we've finished some ongoing sessions.
		 * Note: this does not include sessions handling requests past the initial one (e.g. DORA).
		 */
		if (session_num_parallel >= CONF.session_max_active) break;

		/* Rate limit enforced and we've already started as many sessions as allowed for now. */
		if (do_limit && num_started >= limit_new_sessions) break;

		/*
		 *	Initialize a new session, if possible.
		 */
		dpc_session_ctx_t *session = dpc_session_init_from_input(global_ctx);
		if (!session) {
			/* There is no input available at this point. */

			break; /* Cannot initialize new sessions for now. */
		}

		session->num_send = 1;

		/* Send the packet. */
		if (dpc_send_one_packet(session, &session->request) < 0
		    || !session->reply_expected /* No reply is expected to this kind of packet (e.g. Release). */
		    || !CONF.request_timeout /* Do not wait for a reply. */
		    ) {
			dpc_session_finish(session);
		} else {
			/*
			 *	Arm request timeout.
			 */
			dpc_event_add_request_timeout(session, NULL);
		}

		num_started ++;
	}

	return num_started;
}

/*
 *	Handle timer events.
 */
static void dpc_loop_timer_events(fr_event_list_t *el)
{
	int num_processed = 0; /* Number of timers events triggered. */
	fr_time_t now;

	if (fr_event_list_num_timers(event_list) <= 0) return;

	now = fr_time();

	while (fr_event_timer_run(event_list, &now)) {
		num_processed ++;
	}
}

/*
 *	Check if we're done with the main processing loop.
 */
static bool dpc_loop_check_done(void)
{
	/* There are still ongoing requests, to which we expect a reply or wait for a timeout. */
	//if (dpc_packet_list_num_elements(pl) > 0) return false; // checking active sessions is enough.

	/* There are still active sessions. */
	if (session_num_active > 0) return false;

	/* There are still events to process (ignoring the progress statistics event if it is armed). */
	if (fr_event_list_num_timers(event_list) - ((ev_progress_stats != NULL) ? 1 : 0) > 0) return false;

	/* We still have sessions to start. */
	if (start_sessions_flag) return false;

	/* No more work. */
	job_done = true;
	return true;
}

/*
 *	Main processing loop.
 */
static void dpc_main_loop(void)
{
	job_done = false;

	while (!job_done) {
		/* Start new sessions. */
		dpc_loop_start_sessions();

		/* Receive and process reply packets. */
		dpc_loop_recv();

		/* Handle timer events. */
		dpc_loop_timer_events(event_list);

		/* Check if we're done. */
		dpc_loop_check_done();
	}
}

/*
 *	Pre-allocate a socket for an input item.
 */
static void dpc_input_socket_allocate(dpc_input_t *input)
{
	static bool warn_inaddr_any = true;

	/* We need a source IP address to pre-allocate the socket. */
	if (!is_ipaddr_defined(input->ext.src.ipaddr)) return;

#ifdef HAVE_LIBPCAP
	if (CONF.interface && (fr_ipaddr_is_inaddr_any(&input->ext.src.ipaddr) == 1)
	    && (dpc_ipaddr_is_broadcast(&input->ext.dst.ipaddr) == 1)
	   ) {
		DEBUG3("Input (id: %u) involves broadcast using pcap raw socket", input->id);

		input->ext.with_pcap = true;
		return;
	}
#endif

	/*
	 *	Allocate the socket now. If we can't, stop.
	 */
	if (dpc_socket_provide(pl, &input->ext.src.ipaddr, input->ext.src.port) < 0) {
		char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
		PERROR("Failed to provide a suitable socket (input id: %u, requested socket src: %s:%u)", input->id,
		       fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &input->ext.src.ipaddr), input->ext.src.port);
		exit(EXIT_FAILURE);
	}

	/*
	 *	If we're using INADDR_ANY, make sure we know what we're doing.
	 */
	if (warn_inaddr_any && fr_ipaddr_is_inaddr_any(&input->ext.src.ipaddr)) {
		WARN("You didn't specify a source IP address."
		     " Consequently, a socket was allocated with INADDR_ANY (0.0.0.0)."
		     " Please make sure this is really what you intended.");
		warn_inaddr_any = false; /* Once is enough. */
	}
}

/**
 * Parse and validate an input item.
 * Parse provided attributes, and prepare information necessary to build a packet.
 *
 * @param[in]     ctx    talloc context for allocations (may be the input itself, or global context).
 * @param[in,out] input  item to parse and validate.
 *
 * @return -1 = invalid input (discarded), 0 = success.
 */
static int dpc_input_parse(TALLOC_CTX *ctx, dpc_input_t *input)
{
	fr_cursor_t cursor;
	VALUE_PAIR *vp;
	VALUE_PAIR *vp_encoded_data = NULL, *vp_workflow_type = NULL;

	if (!input->vps) {
		WARN("Empty vps list. Discarding input (id: %u)", input->id);
		return -1;
	}

#define WARN_ATTR_VALUE { \
		PWARN("Invalid value for attribute %s. Discarding input (id: %u)", vp->da->name, input->id); \
		return -1; \
	}

	input->ext.code = FR_CODE_UNDEFINED;

	/* Default: global option -c, can be overriden through Max-Use attr. */
	input->max_use = CONF.input_num_use;

	/* Default: global option --input-rate, can be overriden through Rate-Limit attr. */
	input->rate_limit = CONF.input_rate_limit;

	/*
	 *	Check if we are provided with pre-encoded DHCP data.
	 *	If so, extract (if there is one) the message type and the xid.
	 *	All other DHCP attributes provided through value pairs are ignored.
	 */
	vp_encoded_data = ncc_pair_find_by_da(input->vps, attr_encoded_data);
	if (IS_VP_DATA(vp_encoded_data)) {
		input->ext.code = dpc_message_type_extract(vp_encoded_data);
		input->ext.xid = dpc_xid_extract(vp_encoded_data);
	} else {
		/* Memorize attribute DHCP-Workflow-Type for later (DHCP-Message-Type takes precedence). */
		vp_workflow_type = ncc_pair_find_by_da(input->vps, attr_workflow_type);
	}

	/* Allocate and initialize input segments list.
	 * Note: it may already have been initialized, if input is read from configuration file.
	 */
	if (!input->segments) {
		input->segments = talloc_zero(ctx, ncc_dlist_t);
	}
	NCC_DLIST_INIT(input->segments, ncc_segment_t);

	/*
	 *	Pre-process attributes (1: xlat).
	 */
	for (vp = fr_cursor_init(&cursor, &input->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {

		/*
		 * First ensure the operator makes sense. It should be '=' (T_OP_EQ) or ':=' (T_OP_SET).
 		 * Anything else is not allowed.
		 * These are the same that are allowed by the configuration parser (cf. function cf_section_read).
		 *
		 * Note: dhcpclient doesn't care, it allows all operators.
		 * It displays VPs after a "fr_dhcpv4_packet_decode" whichs sets all operators to '='.
		 */
		if (vp->op != T_OP_EQ && vp->op != T_OP_SET) {
			WARN("Invalid operator '%s' in assignment for attribute '%s'. Discarding input (id: %u)", fr_tokens[vp->op], vp->da->name, input->id);
			return -1;
		}
		vp->op = T_OP_EQ; /* Force to '=' for consistency. */

		/*
		 *	A value is identified as an xlat expression if it is a double quoted string which contains some %{...}
		 *	e.g. "foo %{tolower:Bar}"
		 *
		 *	In this case, the vp has no value, and keeps its original type (vp->vp_type and vp->da->type), which can be anything.
		 *	This entails that the result of xlat expansion would not necessarily be suitable for that vp.
		 */
		if (vp->type == VT_XLAT) {

			if (CONF.xlat) {
				input->do_xlat = true;

				xlat_exp_t *xlat = NULL;
				ssize_t slen;
				char *value;

				value = talloc_typed_strdup(ctx, vp->xlat); /* modified by xlat_tokenize */

				slen = xlat_tokenize(global_ctx, &xlat, value, NULL);
				/* Notes:
				 * - First parameter is talloc context.
				 *   We cannot use "input" as talloc context, because we may free the input and still need the parsed xlat expression.
				 *   This happens in non template mode, with "num use > 1".
				 * - Last parameter is "vp_tmpl_rules_t const *rules". (cf. vp_tmpl_rules_s in src/lib/server/tmpl.h)
				 *   NULL means default rules are used, which is fine.
				 */

				if (slen < 0) {
					WARN("Failed to parse '%s' expansion string. Discarding input (id: %u)", vp->da->name, input->id);
					NCC_LOG_MARKER(L_INFO, vp->xlat, (-slen), "%s", fr_strerror());

					talloc_free(value);
					talloc_free(xlat);

					return -1;
				}
				talloc_free(value);

				/*
				 *	Store the compiled xlat (xlat_exp_t).
				 *	For this we use the "generic pointer" vp_ptr (data.datum.ptr)
				 */
				vp->vp_ptr = xlat;

			} else {
				/*
				 *	Xlat expansions are not supported. Convert xlat to value box (if possible).
				 */
				if (ncc_pair_value_from_str(vp, vp->xlat) < 0) {
					WARN("Unsupported xlat expression for attribute '%s'. Discarding input (id: %u)", vp->da->name, input->id);
					return -1;
				}
			}
		}
	}

	/*
	 *	Pre-process attributes (2: control attributes).
	 */
	for (vp = fr_cursor_init(&cursor, &input->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {

		/*
		 *	Process special attributes. They take precedence over command line arguments.
		 *	Note: xlat is not supported for these.
		 */
		if (!IS_VP_DATA(vp)) continue;

		/*
		 * DHCP attributes.
		 * Note: if we have pre-encoded DHCP data (vp_encoded_data), all other DHCP attributes are silently ignored.
		 */
		if (vp->da == attr_dhcp_message_type) {
			/* Packet type. */
			if (!vp_encoded_data) input->ext.code = vp->vp_uint32;

		} else if (vp->da == attr_dhcp_transaction_id) {
			/* Prefered xid. */
			if (!vp_encoded_data) input->ext.xid = vp->vp_uint32;

		/*
		 * Control attributes
		 */
		} else if (vp->da == attr_packet_dst_port) {
			input->ext.dst.port = vp->vp_uint16;

		} else if (vp->da == attr_packet_dst_ip_address) {
			memcpy(&input->ext.dst.ipaddr, &vp->vp_ip, sizeof(input->ext.dst.ipaddr));

		} else if (vp->da == attr_packet_src_port) {
			input->ext.src.port = vp->vp_uint16;

		} else if (vp->da == attr_packet_src_ip_address) {
			memcpy(&input->ext.src.ipaddr, &vp->vp_ip, sizeof(input->ext.src.ipaddr));

		} else if (vp->da == attr_input_name) { /* Input-Name = <string> */
			input->name = talloc_strdup(ctx, vp->vp_strvalue);

		} else if (vp->da == attr_start_delay) { /* Start-Delay = <float> */
			double start_delay;
			if (!ncc_str_to_float(&start_delay, vp->vp_strvalue, false)) WARN_ATTR_VALUE;
			input->ftd_start_delay = ncc_float_to_fr_time(start_delay);

		} else if (vp->da == attr_rate_limit) { /* Rate-Limit = <float> */
			if (!ncc_str_to_float(&input->rate_limit, vp->vp_strvalue, false)) WARN_ATTR_VALUE;

		} else if (vp->da == attr_max_duration) { /* Max-Duration = <float> */
			if (!ncc_str_to_float(&input->max_duration, vp->vp_strvalue, false)) WARN_ATTR_VALUE;

		} else if (vp->da == attr_max_use) { /* Max-Use = <int> */
			input->max_use = vp->vp_uint32;

		} else if (vp->da == attr_segment) { /* Segment = <string> */
			if (!CONF.template) {
				WARN("Input segments are not allowed in non template mode. Discarding input (id: %u)", input->id);
				return -1;
			}
			if (ncc_segment_parse(ctx, input->segments, vp->vp_strvalue) < 0) WARN_ATTR_VALUE;

		} else if (vp->da == attr_authorized_server) { /* DHCP-Authorized-Server = <ipaddr> */
			TALLOC_REALLOC_ONE_SET(ctx, input->authorized_servers, fr_ipaddr_t, vp->vp_ip);

		}

	} /* loop over the input vps */

	/*
	 *	If not specified in input vps, use default values.
	 */
	if (!vp_encoded_data) {
		if (input->ext.code == FR_CODE_UNDEFINED) {
			/*
			 *	Handling a workflow. All workflows start with a Discover.
			 */
			if (vp_workflow_type && vp_workflow_type->vp_uint8 && vp_workflow_type->vp_uint8 < DPC_WORKFLOW_MAX) {
				input->ext.workflow = vp_workflow_type->vp_uint8;
				input->ext.code = FR_DHCP_DISCOVER;

			} else if (workflow_code) {
				input->ext.workflow = workflow_code;
				input->ext.code = FR_DHCP_DISCOVER;
			}
		}

		/* Fall back to message type provided through command line (if there is one). */
		if (input->ext.code == FR_CODE_UNDEFINED) input->ext.code = packet_code;
	}

	/*
	 *	If source (addr / port) is not defined in input vps, use gateway if one is specified.
	 *	If nothing goes, fall back to default.
	 */
	if (!input->ext.src.port) input->ext.src.port = client_ep.port;
	if (   !is_ipaddr_defined(input->ext.src.ipaddr)
	    && !gateway_list /* If using a gateway, let this unspecified for now. */
	   ) {
		input->ext.src.ipaddr = client_ep.ipaddr;
	}

	if (!input->ext.dst.port) input->ext.dst.port = server_ep.port;
	if (!is_ipaddr_defined(input->ext.dst.ipaddr)) input->ext.dst.ipaddr = server_ep.ipaddr;

	if (!vp_encoded_data && input->ext.code == FR_CODE_UNDEFINED) {
		WARN("No packet type specified in input vps or command line. Discarding input (id: %u)", input->id);
		return -1;
	}

	/*
	 *	Pre-allocate the socket for this input item.
	 *	Unless: in template mode *and* with gateway(s) (in which case we already have the sockets allocated).
	 */
	if (!CONF.template || !gateway_list) {
		dpc_input_socket_allocate(input);
	}

	/* Fill in the gaps in the list of segments. */
	if (ncc_segment_list_complete(ctx, input->segments, input->rate_limit) < 0) {
		PWARN("Failed to complete segment list. Discarding input (id: %u)", input->id);
		return -1;
	}

	/* Set a default segment for this input.
	 * This segment will enforce the input rate limit when no other input scoped segment is active.
	 */
	MEM(input->segment_dflt = talloc_zero(ctx, ncc_segment_t));
	input->segment_dflt->name = "dflt";

	if (input->rate_limit) {
		input->segment_dflt->type = NCC_SEGMENT_RATE_FIXED;
		input->segment_dflt->rate_limit = input->rate_limit;
	} else {
		input->segment_dflt->type = NCC_SEGMENT_RATE_UNBOUNDED;
	}

	/* Handle "Start-Delay" if set. Do not allow any traffic to start before that.
	 * Adjust segments so that rate calculations are relative to this new start.
	 */
	if (input->ftd_start_delay) {
		input->segment_dflt->ftd_start = input->ftd_start_delay;

		/* Override the start of segment list. */
		if (ncc_segment_list_override_start(ctx, input->segments, input->ftd_start_delay) < 0) {
			PWARN("Failed to override segment list start. Discarding input (id: %u)", input->id);
			return -1;
		}

		/* Note: for linear segments the start rate is not altered. This means we'll have a steeper profile. */
	}

	/* All good. */
	return 0;
}

/**
 * Handle a list of input vps we've just read.
 */
static int dpc_input_handle(dpc_input_t *input, ncc_dlist_t *dlist)
{
	TALLOC_CTX *ctx;

	/* Provide a talloc context, which is *not* the input if we're not in template mode.
	 * This makes it easier to duplicate input item without having to handle reparenting.
	 */
	ctx = (CONF.template ? input : global_ctx);

	input->id = input_num ++;
	input->ext.xid = DPC_PACKET_ID_UNASSIGNED;

	if (dpc_input_parse(ctx, input) < 0) {
		/*
		 * Invalid item. Discard.
		 */
		talloc_free(input);
		num_input_invalid++;
		return -1;
	}

	/*
	 * Add it to the list of input items.
	 */
	NCC_DLIST_ENQUEUE(dlist, input);
	return 0;
}

/*
 *	Load input vps from the provided file pointer.
 */
static int dpc_input_load_from_fp(TALLOC_CTX *ctx, FILE *fp, ncc_dlist_t *list, char const *filename)
{
	bool file_done = false;
	dpc_input_t *input;

	/*
	 *	Loop until the file is done.
	 */
	do {
		/* Stop reading if we know we won't need it. */
		if (!CONF.template && CONF.session_max_num && list->size >= CONF.session_max_num) break;

		MEM(input = talloc_zero(ctx, dpc_input_t));

		if (fr_pair_list_afrom_file(input, dict_dhcpv4, &input->vps, fp, &file_done) < 0) {
			PERROR("Failed to read input items from %s", filename);
			return -1;
		}
		if (!input->vps) {
			/* Last line might be empty, in this case we will obtain a NULL vps pointer. Silently ignore this. */
			talloc_free(input);
			break;
		}
		fr_strerror(); /* Clear the error buffer */
		/*
		 *	After calling fr_pair_list_afrom_file we get weird things in FreeRADIUS error buffer, e.g.:
		 *	"Invalid character ':' in attribute name".
		 *	This happens apparently when handling an ethernet address (which is a value, not an attribute name).
		 *	Just ignore this.
		*/

		dpc_input_handle(input, list);

	} while (!file_done);

	return 0;
}

/**
 * Load input vps: first, from stdin (if there is something to read), then from input files (if provided).
 */
static int dpc_input_load(TALLOC_CTX *ctx)
{
	FILE *fp = NULL;
	int ret, i;
	size_t len;

	/*
	 *	If there's something on stdin, read it.
	 */
	if (ncc_stdin_peek()) {
		with_stdin_input = true;

		DEBUG("Reading input from stdin");
		if (dpc_input_load_from_fp(ctx, stdin, &input_list, "stdin") < 0) return -1;
	} else {
		DEBUG3("Nothing to read on stdin");
	}

	/*
	 *	Read input from all provided input files.
	 */
	len = talloc_array_length(CONF.input_files);
	for (i = 0; i < len; i++) {
		char const *filename = CONF.input_files[i];
		if (strcmp(filename, "-") != 0) {
			DEBUG("Reading input from file: %s", filename);

			fp = fopen(filename, "r");
			if (!fp) {
				ERROR("Failed to open input file \"%s\": %s", filename, fr_syserror(errno));
				return -1;
			}

			ret = dpc_input_load_from_fp(ctx, fp, &input_list, filename);
			fclose(fp);
			if (ret < 0) return -1;
		}
	}

	return 0;
}


/*
 *	Handle xlat expansion on a list of value pairs (within a packet context).
 *
 *	Note: if one of the registered xlat complains (returns -1) the main xlat will consider it's fine.
 *	However, if the main xlat is unhappy, it will return -1 (and an empty string).
 */
static int dpc_pair_list_xlat(DHCP_PACKET *packet, VALUE_PAIR *vps)
{
	fr_cursor_t cursor;
	VALUE_PAIR *vp;
	ssize_t len;
	char buffer[DPC_XLAT_MAX_LEN];

	for (vp = fr_cursor_init(&cursor, &vps); vp; vp = fr_cursor_next(&cursor)) {
		/*
		 *	Handle xlat expansion for this attribute.
		 *	Allow any data type. Value will be cast by FreeRADIUS (if possible).
		 */
		if (vp->type == VT_XLAT) {
			/* Retrieve pre-compiled xlat, and use it to perform expansion. */
			xlat_exp_t *xlat = vp->vp_ptr;
			if (!xlat) {
				fr_strerror_printf("Cannot xlat %s = [%s]: expression was not compiled", vp->da->name, vp->xlat);
				return -1;
			}

			len = dpc_xlat_eval_compiled(buffer, sizeof(buffer), xlat, packet);
			if (len <= 0) { /* Consider empty string as failed expansion. */
				fr_strerror_printf_push("Failed to expand xlat '%s'", vp->da->name);
				return -1;
			}

			vp->vp_ptr = NULL; /* Otherwise fr_pair_value_strcpy would free our compiled xlat! */

			DEBUG3("xlat %s = [%s] => (len: %u) [%s]", vp->da->name, vp->xlat, len, buffer);

			/* Convert the xlat'ed string to the appropriate type. */
			if (ncc_pair_value_from_str(vp, buffer) < 0) {
				return -1;
			}
		}
	}
	return 0;
}

/*
 *	Initialize the pcap raw socket.
 */
#ifdef HAVE_LIBPCAP
static void dpc_pcap_init(TALLOC_CTX *ctx)
{
	char pcap_filter[255];

	pcap = fr_pcap_init(ctx, CONF.interface, PCAP_INTERFACE_IN_OUT);
	if (!pcap) {
		PERROR("Failed to initialize pcap");
		exit(EXIT_FAILURE);
	}

	if (fr_pcap_open(pcap) < 0) {
		PERROR("Failed to open pcap interface");
		exit(EXIT_FAILURE);
	}

	sprintf(pcap_filter, "udp");
	/*
	 *	Note: destination of a reply to a broadcast request is not necessarily 255.255.255.255.
	 *	This is the case only if the Broadcast flag is set in the request. See section 4.1 of RFC 2131.
	 */

	if (fr_pcap_apply_filter(pcap, pcap_filter) < 0) {
		PERROR("Failed to apply pcap filter");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Add a raw socket to our list of managed sockets.
	 *	Note: even though we tag it with source port 68 (the DHCP port for clients), we can really
	 *	send using any source port with it (it's a raw socket) if we want to. The DHCP server probably
	 *	won't care, but will send the response using destination port 68.
	 */
	if (dpc_pcap_socket_add(pl, pcap, &client_ep.ipaddr, 68) < 0) {
		exit(EXIT_FAILURE);
	}
}
#endif

/*
 *	Get alternate (fallback) dictionaries directory, relative to the program location.
 *	As follows: <prog dir>/../share/freeradius/dictionary
 *	<prog dir> is obtained through a "readlink" on /proc/<pid>/exe
 *	Note: this is *not* portable. It works on Linux, but not on all Unixes.
 */
static int dpc_get_alt_dir(void)
{
#ifndef __linux__ /* Don't even try if this is not Linux. */
	DEBUG("Not Linux: won't get program real location");
	return -1;
#else
	char buf[32] = "";
	char prog_path[PATH_MAX + 1] = "";
	char *prog_dir, *up_dir;

	sprintf(buf, "/proc/%d/exe", getpid());
	if (readlink(buf, prog_path, sizeof(prog_path) - 1) == -1) {
		ERROR("Cannot get program execution path from link '%s'", buf);
		return -1;
	}

	prog_dir = dirname(prog_path);
	up_dir = dirname(prog_dir);

	snprintf(alt_dict_dir, PATH_MAX, "%s/share/freeradius/dictionary", up_dir);
	DEBUG("Using alternate dictionaries dir: %s", alt_dict_dir);
	return 0;
#endif
}

/*
 *	Initialize and load dictionaries.
 */
static void dpc_dict_init(TALLOC_CTX *ctx)
{
	/*
	 *	fr_dict_from_file cannot be called twice (or very bad things happen).
	 *	Probably need to free stuff for that.
	 *	To simplify, first check if the default directory exists before doing anything.
	 */
	char dict_path_freeradius[PATH_MAX + 1] = "";
	sprintf(dict_path_freeradius, "%s/%s", dict_dir, dict_fn_freeradius); // no "access_printf" or something!? damn.
	if (access(dict_path_freeradius, R_OK) < 0) {
		DEBUG("Cannot access dictionary file: %s", dict_path_freeradius);

		/* Get alternate directory (if possible). */
		if (dpc_get_alt_dir() != 0 || access(alt_dict_dir, R_OK) < 0) {
			PERROR("Failed to initialize dictionary: unable to locate dictionary files");
			exit(EXIT_FAILURE);
		}
		dict_dir = alt_dict_dir;
	}

	/*
	 *	Initialize dictionaries.
	 */
	if (!fr_dict_global_ctx_init(ctx, dict_dir)) {
		PERROR("Failed to initialize dictionary");
		exit(EXIT_FAILURE);
	}

	/* Preload dictionaries. */
	if (fr_dict_autoload(dpc_dict_autoload) < 0) {
		PERROR("Failed to autoload dictionaries");
		exit(EXIT_FAILURE);
	}

	/* Preload dictionary attributes that we need. */
	if (fr_dict_attr_autoload(dpc_dict_attr_autoload) < 0) {
		PERROR("Failed to autoload dictionary attributes");
		exit(EXIT_FAILURE);
	}

	/* Also need to load attributes required by DHCP library. */
	if (fr_dhcpv4_global_init() < 0) {
		PERROR("Failed to initialize DHCP library");
		exit(EXIT_FAILURE);
	}

	fr_strerror(); /* Clear the error buffer */
}

/*
 *	Initialize event list.
 */
static void dpc_event_list_init(TALLOC_CTX *ctx)
{
	event_list = fr_event_list_alloc(ctx, NULL, NULL);
	if (!event_list) {
		PERROR("Failed to create event list");
		exit(EXIT_FAILURE);
	}
}

/*
 *	Initialize the packet list.
 */
static void dpc_packet_list_init(TALLOC_CTX *ctx)
{
	pl = dpc_packet_list_create(ctx, CONF.base_xid);
	if (!pl) {
		ERROR("Failed to create packet list");
		exit(EXIT_FAILURE);
	}
}

/*
 *	See what kind of request we want to send, or workflow to handle.
 */
static int dpc_command_parse(char const *command)
{
	/* If an integer, assume this is the packet type (1 = discover, ...). */
	if (is_integer(command)) {
		int message = atoi(command);
		if (message > 255) return -1;
		packet_code = atoi(command);
		return 0;
	}

	/* Maybe it's a workflow. */
	workflow_code = fr_table_value_by_str(workflow_types, command, DPC_WORKFLOW_NONE);
	if (workflow_code != DPC_WORKFLOW_NONE) return 0;

	/* Or a packet type. */
	packet_code = fr_table_value_by_str(request_types, command, -1);
	if (packet_code != -1) return 0;

	/* Nothing goes. */
	return -1;
}

/*
 *	Parse and handle configured gateway(s).
 */
static void dpc_gateway_parse(TALLOC_CTX *ctx, char const *in)
{
	DEBUG3("Parsing list of gateway endpoints: [%s]", in);

	if (ncc_endpoint_list_parse(global_ctx, &gateway_list, in,
	                            &(ncc_endpoint_t) { .port = DHCP_PORT_RELAY }) < 0) {
		PERROR("Failed to parse gateways");
		exit(EXIT_FAILURE);
	}
}


/* Short options. */
#define OPTSTR_BASE "a:c:CD:f:g:hI:L:Mn:N:p:P:r:s:t:TvxX"
#ifdef HAVE_LIBPCAP
  #define OPTSTR_LIBPCAP "Ai:"
#else
  #define OPTSTR_LIBPCAP ""
#endif
#define OPTSTR OPTSTR_BASE OPTSTR_LIBPCAP

static struct option long_options[] = {
	/* Long options with no short option equivalent.
	 * Note: these must be defined at the beginning, because they are identified by their index in this array.
	 */
	{ "conf-file",              required_argument, NULL, 1 },
	{ "conf-inline",            required_argument, NULL, 1 },
	{ "debug",                  no_argument,       NULL, 1 },
	{ "input-rate",             required_argument, NULL, 1 },
	{ "retransmit",             required_argument, NULL, 1 },
	{ "segment",                required_argument, NULL, 1 },
	{ "xlat",                   optional_argument, NULL, 1 },
	{ "xlat-file",              required_argument, NULL, 1 },

	/* Long options with short option equivalent. */
	{ "conf-check",             no_argument,       NULL, 'C' },
	{ "dict-dir",               required_argument, NULL, 'D' },
	{ "help",                   no_argument,       NULL, 'h' },
	{ "input-file",             required_argument, NULL, 'f' },
	{ "duration-start-max",     required_argument, NULL, 'L' },
	{ "session-max",            required_argument, NULL, 'N' },
	{ "parallel",               required_argument, NULL, 'p' },
	{ "rate",                   required_argument, NULL, 'r' },
	{ "template",               no_argument,       NULL, 'T' },
	{ "timeout",                required_argument, NULL, 't' },
	{ "packet-trace",           required_argument, NULL, 'P' },

	/* Long options flags can be handled automaticaly.
	 * Note: this requires an "int" as flag variable. A boolean cannot be handled automatically.
	 */
	//{ "xlat",                   no_argument, &with_xlat, 1 },

	{ 0, 0, 0, 0 }
};

typedef enum {
	/* Careful: numbering here is important.
	 * It must match long_options order defined above.
	 */
	LONGOPT_IDX_CONF_FILE = 0,
	LONGOPT_IDX_CONF_INLINE,
	LONGOPT_IDX_DEBUG,
	LONGOPT_IDX_INPUT_RATE,
	LONGOPT_IDX_RETRANSMIT,
	LONGOPT_IDX_SEGMENT,
	LONGOPT_IDX_XLAT,
	LONGOPT_IDX_XLAT_FILE,
	LONGOPT_IDX_MAX
} longopt_index_t;

/*
 *	Process command line options and arguments.
 *	Initialize configuration elements that can be set through command-line options.
 *	Note: Those may later be overriden with values read from configuration files.
 */
static void dpc_options_parse(int argc, char **argv)
{
	int argval;
	int opt_index = -1; /* Stores the option index for long options. */
	int i, num_arg;
	int ret;

#define ERROR_PARSE_OPT { \
		PERROR("Option \"%s\"", opt_buf); \
		usage(EXIT_FAILURE); \
	}

#define WARN_PARSE_OPT { \
		PWARN("Option \"%s\"", opt_buf); \
	}

#define PARSE_OPT(_to, _type) if (ncc_value_from_str(&_to, _type, optarg, -1) < 0) ERROR_PARSE_OPT;

#define PARSE_OPT_CTX(_to, _type, _ctx) {\
	ret = ncc_parse_value_from_str(&(_to), _type, optarg, -1, _ctx);\
	if (ret < 0) ERROR_PARSE_OPT else if (ret) WARN_PARSE_OPT;\
}

	/* The getopt API allows for an option with has_arg = "optional_argument"
	 * to be passed as "--arg" or "--arg=val", but not "--arg val".
	 * We have to handle this case ourselves: look at the next argument if there is one.
	 * If it's not an option, then consider it is our value.
	 *
	 * Likewise for short options with an optional value ("a::"), the API allows for "-a" or "-av", but not "-a v".
	 * This can be handled the same way.
	 *
	 * Note: if non-option arguments immediately follow an optional argument with no value, then they must be
	 * explicitely separated with "--".
	 */
#define OPTIONAL_ARG(_dflt) { \
		if (!optarg && argv[optind] && argv[optind][0] != '-') optarg = argv[optind++]; \
		if (!optarg && _dflt) optarg = _dflt; \
	}

	/* Parse options: first pass.
	 * Get debug level, and set logging accordingly.
	 */
	optind = 0;
	opterr = 0; /* No error messages. */
	while (1)
	{
		argval = getopt_long(argc, argv, "-hvx", long_options, &opt_index);
		/*
		 * "If the first character of optstring is '-', then each nonoption argv-element is handled
		 *  as if it were the argument of an option with character code 1."
		 * This prevents getopt_long from modifying argv, as it would normally do.
		 * Also, argument "long_options" must be provided so that options starting with "--x" are not parsed as "-x".
		 */
		if (argval == -1) break;

		switch (argval) {
		case 'h':
			usage(EXIT_SUCCESS);

		case 'v':
			version_print();
			exit(EXIT_SUCCESS);

		case 'x':
			dpc_debug_lvl ++;
			break;
		}
	}

	ncc_log_init(stdout, dpc_debug_lvl); /* Initialize logging. */

	/* Parse options: second pass.
	 */
	optind = 0;
	opterr = 1; /* Now we want errors. */
	while (1)
	{
		opt_index = -1;
		argval = getopt_long(argc, argv, OPTSTR, long_options, &opt_index);
		if (argval == -1) break;

		/* Reformat current option in case we need to print it.
		 * Note: "opt_index" is set only if the long version was actually used.
		 */
		char opt_buf[64] = "";
		if (opt_index >= 0) {
			sprintf(opt_buf, "--%s", long_options[opt_index].name);
		} else {
			sprintf(opt_buf, "-%c", argval);
			/* If the option is not recognized we will have "-?", but this won't be used. */
		}

		switch (argval) {
		case 'a':
		{
			fr_ipaddr_t server;
			PARSE_OPT(server, FR_TYPE_IPV4_ADDR);
			TALLOC_REALLOC_ONE_SET(global_ctx, CONF.authorized_servers, fr_ipaddr_t, server);
		}
			break;

		case 'A':
			multi_offer = true;
			break;

		case 'c':
			PARSE_OPT(CONF.input_num_use, FR_TYPE_UINT32);
			break;

		case 'C':
			check_config = true;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'f':
			TALLOC_REALLOC_ONE_SET(global_ctx, CONF.input_files, char const *, optarg);
			break;

		case 'g':
			TALLOC_REALLOC_ONE_SET(global_ctx, CONF.gateways, char const *, optarg);
			break;

#ifdef HAVE_LIBPCAP
		case 'i':
			CONF.interface = optarg;
			break;
#endif

		case 'I':
			/* Stored as uint64_t because it is required by the config parser. */
			PARSE_OPT_CTX(CONF.base_xid, FR_TYPE_UINT64, PARSE_CTX_BASE_XID);
			break;

		case 'L':
			PARSE_OPT_CTX(CONF.duration_start_max, FR_TYPE_FLOAT64, PARSE_CTX_FLOAT64_NOT_NEGATIVE);
			break;

		case 'M':
			CONF.talloc_memory_report = true;
			break;

		case 'n':
			instance = optarg;
			break;

		case 'N':
			PARSE_OPT(CONF.session_max_num, FR_TYPE_UINT32);
			break;

		case 'p':
			PARSE_OPT_CTX(CONF.session_max_active, FR_TYPE_UINT32, PARSE_CTX_SESSION_MAX_ACTIVE);
			break;

		case 'P':
			PARSE_OPT_CTX(CONF.packet_trace_lvl, FR_TYPE_INT32, PARSE_CTX_PACKET_TRACE_LEVEL);
			break;

		case 'r':
			PARSE_OPT_CTX(CONF.rate_limit, FR_TYPE_FLOAT64, PARSE_CTX_FLOAT64_NOT_NEGATIVE);
			break;

		case 's':
			PARSE_OPT_CTX(CONF.progress_interval, FR_TYPE_FLOAT64, PARSE_CTX_PROGRESS_INTERVAL);
			break;

		case 't':
			PARSE_OPT_CTX(CONF.request_timeout, FR_TYPE_FLOAT64, PARSE_CTX_REQUEST_TIMEOUT);

			/* 0 is allowed, it means we don't wait for replies, ever.
			 * This entails that:
			 * - we won't have "timed out" requests
			 * - we won't have rtt statistics
			 * - and we probably will have "unexpected replies" (if the server is responsive)
			 */
			break;

		case 'T':
			CONF.template = true;
			break;

		case 'x': /* Handled in first pass. */
			break;

		case 'X':
			fr_debug_lvl = dpc_debug_lvl;
			break;

		case 0: /* Long option flag set, nothing to do. */
			break;

		case 1:
			/*	Long options with no short option equivalent.
			 *	Option is identified by its index in the option[] array.
			 */
			switch (opt_index) {
			case LONGOPT_IDX_CONF_FILE: // --conf-file
				file_config = optarg;
				break;

			case LONGOPT_IDX_CONF_INLINE: // --conf-inline
				conf_inline = optarg;
				break;

			case LONGOPT_IDX_DEBUG: // --debug
				CONF.debug_dev = true;
				break;

			case LONGOPT_IDX_INPUT_RATE: // --input-rate
				PARSE_OPT_CTX(CONF.input_rate_limit, FR_TYPE_FLOAT64, PARSE_CTX_FLOAT64_NOT_NEGATIVE);
				break;

			case LONGOPT_IDX_RETRANSMIT: // --retransmit
				PARSE_OPT(CONF.retransmit_max, FR_TYPE_UINT32);
				break;

			case LONGOPT_IDX_SEGMENT: // --segment
				if (ncc_segment_parse(global_ctx, segment_list, optarg) < 0) {
					PERROR("Failed to parse segment \"%s\"", optarg);
					exit(EXIT_FAILURE);
				}
				break;

			case LONGOPT_IDX_XLAT: // --xlat
				OPTIONAL_ARG("yes");
				PARSE_OPT(CONF.xlat, FR_TYPE_BOOL);
				break;

			case LONGOPT_IDX_XLAT_FILE: // --xlat-file
				TALLOC_REALLOC_ONE_SET(global_ctx, CONF.xlat_files, char const *, optarg);
				break;

			default:
				printf("Error: Unexpected 'option index': %d\n", opt_index);
				usage(EXIT_FAILURE);
				break;
			}
			break;

		default:
			usage(EXIT_FAILURE);
			break;
		}
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	/* Configure talloc debugging features. */
	if (CONF.talloc_memory_report) {
		talloc_enable_null_tracking();
	} else {
		talloc_disable_null_tracking();
	}

	CONF.debug_level = dpc_debug_lvl;

	ncc_log_init(stdout, dpc_debug_lvl); /* Update with actual options. */
	ncc_default_log.line_number = dpc_config->debug_dev;

	/* Trace remaining (non-option) arguments, which start at argv[1] at this point. */
	num_arg = argc - 1;
	for (i = 1; i < argc; i++) DEBUG4("argv[%u]: %s", i, argv[i]);

	/*
	 *	Resolve server host address and port.
	 */
	if (num_arg >= 1 && strcmp(argv[1], "-") != 0) {
		ncc_host_addr_resolve(&server_ep, argv[1]);
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (num_arg >= 2) {
		if (dpc_command_parse(argv[2]) != 0) {
			ERROR("Unrecognised command \"%s\"", argv[2]);
			usage(EXIT_FAILURE);
		}
	}
}

/*
 *	Signal handler.
 */
static void dpc_signal(int sig)
{
	if (!signal_done) {
		/* Allow ongoing sessions to be finished gracefully. */
		INFO("Received signal [%d] (%s): will not start any new session.", sig, strsignal(sig));
		INFO("Send another signal if you wish to terminate immediately.");
		signal_done = true;
		dpc_end_start_sessions();
	} else {
		/* ... unless someone's getting really impatient. */
		INFO("Received signal [%d] (%s): Aborting.", sig, strsignal(sig));
		dpc_end();
	}
}

/*
 *	The end.
 */
static void dpc_end(void)
{
	/* Job end timestamp. */
	fte_job_end = fr_time();

	if (!check_config) {
		/* Stop time-data handler if it is running. */
		ncc_timedata_stop();

		/* If we're producing progress statistics, do it one last time. */
		if (CONF.ftd_progress_interval && dpc_job_elapsed_fr_time_get() > CONF.ftd_progress_interval) {
			dpc_progress_stats_fprint(CONF.pr_stat_fp, true);
		}

		/* End statistics report.
		 */
		dpc_job_elapsed_time_snapshot_set(); /* Fixed reference time for consistency. */

		dpc_stats_fprint(stdout);
		dpc_tr_stats_fprint(stdout);
	}

	dpc_exit();
}

/**
 * Free resources and exit.
 */
static void dpc_exit(void)
{
	bool talloc_memory_report = false;

	if (dpc_config) talloc_memory_report = dpc_config->talloc_memory_report; /* Grab this before we free the config */

	/* Free memory.
	 */
	ncc_xlat_free(); // Note: this removes reference on "internal" (freeradius) dictionary
	ncc_xlat_core_free();

	// If using non static "dict_dhcpv4" from FreeRADIUS, then dictionary "DHCPv4" has *two* talloc references
	// i.e. two parents in addition to the initial one (cf. talloc_reference_count).
	// This is one more than expected (why ??) and thus prevents memory being properly freed.
	// fr_dhcpv4_global_free() and fr_dict_autofree(dpc_dict_autoload) will each remove one of the two references.

	fr_dhcpv4_global_free();

	fr_dict_autofree(dpc_dict_autoload);
	// Now all dictionaries have been freed.

	/* Free parsed configuration.
	 */
	dpc_config_free(&dpc_config);

	TALLOC_FREE(pl);
	TALLOC_FREE(event_list);
	TALLOC_FREE(global_ctx);

	fr_strerror_free();

	/*
	 * Anything not cleaned up by the above is allocated in
	 * the NULL top level context, and is likely leaked memory.
	 */
	if (talloc_memory_report) {
		fprintf(stdout, "--> EXIT talloc memory report:\n");
		fr_log_talloc_report(NULL);
		fprintf(stdout, "<-- EXIT talloc memory report END.\n");
	}

	/* And we're done. */
	exit(EXIT_SUCCESS);
}


/*
 *	The main guy.
 */
int main(int argc, char **argv)
{
	char *p;
	unsigned int i;

	/* FreeRADIUS global debug (defined in src/lib/util/log.c).
	 */
	fr_debug_lvl = 0;

	dpc_debug_lvl = 0; /* Our own debug. */
	fr_log_fp = stdout; /* Everything will go there. */

	/* Ensure stdout is line buffered (it is not if redirected to a file).
	 * Note: stderr is always unbuffered by default.
	 */
	setlinebuf(stdout);
	setlinebuf(stderr);

	global_ctx = talloc_new(talloc_autofree_context());

	fr_time_start();

	fte_program_start = fr_time(); /* Program start timestamp. */

	/*
	 *	Allocate the main config structure.
	 */
	dpc_config = dpc_config_alloc(global_ctx);
	if (!dpc_config) {
		fprintf(stderr, "Failed to allocate main configuration\n"); /* Logging is not initialized yet. */
		exit(EXIT_FAILURE);
	}
	/* Set default (static) configuration values. */
	*dpc_config = default_config;

	/* Get program name from argv. */
	p = strrchr(argv[0], FR_DIR_SEP);
	if (!p) {
		progname = argv[0];
	} else {
		progname = p + 1;
	}
	dpc_config_name_set_default(dpc_config, progname, false);

	my_pid = getpid();

	/*
	 *	Initialize chained lists (input items, global segments).
	 */
	NCC_DLIST_INIT(&input_list, dpc_input_t);

	/* Segments list is talloc'ed. */
	segment_list = talloc_zero(global_ctx, ncc_dlist_t);
	NCC_DLIST_INIT(segment_list, ncc_segment_t);

	/*
	 *	Parse the command line options.
	 */
	dpc_options_parse(argc, argv);

	/* If no instance name is set, use a default name: <program>.<PID>.
	 */
	if (!instance) {
		instance = talloc_asprintf(global_ctx, "%s.%u", progname, my_pid);
	}
	dpc_config_name_set_default(dpc_config, instance, true);

	/*
	 *	Mismatch between the binary and the libraries it depends on.
	 */
	DEBUG4("FreeRADIUS magic number: %016lx", RADIUSD_MAGIC_NUMBER);
	if (fr_check_lib_magic(RADIUSD_MAGIC_NUMBER) < 0) {
		PERROR("Libraries check");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Initialize dictionaries and preload attributes.
	 */
	dpc_dict_init(global_ctx);

	/*
	 *	Initialize the xlat framework, and register xlat expansion functions.
	 */
	if (ncc_xlat_register() < 0) exit(EXIT_FAILURE);

	/*
	 *	Initialize event list and packet list.
	 */
	dpc_event_list_init(global_ctx);
	dpc_packet_list_init(global_ctx);

	/*
	 *	Read the configuration file (if provided), and parse configuration.
	 */
	if (dpc_config_init(dpc_config, file_config, conf_inline) < 0) exit(EXIT_FAILURE);

	if (dpc_timedata_config_load(dpc_config) < 0) exit(EXIT_FAILURE);

	if (dpc_config_load_segments(dpc_config, segment_list) < 0) exit(EXIT_FAILURE);

	/* Parse configured gateway(s).
	 * Note: This *must* be done before any input is parsed (either from configuration file, or from input file or stdin).
	 */
	for (i = 0; i < talloc_array_length(CONF.gateways); i++) {
		dpc_gateway_parse(global_ctx, CONF.gateways[i]);
	}

	/* Read input from configuration.
	 */
	if (dpc_config_load_input(dpc_config, dpc_input_handle) < 0) exit(EXIT_FAILURE);

	/* Fill in the gaps in the list of global segments.
	 */
	if (ncc_segment_list_complete(global_ctx, segment_list, CONF.rate_limit) < 0) {
		PERROR("Failed to complete global segment list");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Other configuration-related initializations.
	 */
	for (i = 0; i < talloc_array_length(CONF.xlat_files); i++) {
		if (ncc_xlat_file_add(CONF.xlat_files[i]) != 0) {
			exit(EXIT_FAILURE);
		}
	}

	if (CONF.retransmit_max > 0) {
		retr_breakdown = talloc_zero_array(global_ctx, uint32_t, CONF.retransmit_max);
	}

	CONF.ftd_progress_interval = ncc_float_to_fr_time(CONF.progress_interval);
	CONF.ftd_request_timeout = ncc_float_to_fr_time(CONF.request_timeout);
	if (!CONF.template && CONF.input_num_use == 0) CONF.input_num_use = 1;

	if (CONF.rate_limit) {
		segment_default.type = NCC_SEGMENT_RATE_FIXED;
		segment_default.rate_limit = CONF.rate_limit;
	}

	/*
	 *	Allocate sockets for gateways.
	 */
	if (gateway_list) {
		ncc_endpoint_t *ep = NCC_DLIST_HEAD(gateway_list);
		while (ep) {
			if (dpc_socket_provide(pl, &ep->ipaddr, ep->port) < 0) {
				char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
				PERROR("Failed to provide a suitable socket for gateway \"%s:%u\"",
				       fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &ep->ipaddr) ? src_ipaddr_buf : "(undef)",
				       ep->port);
				exit(EXIT_FAILURE);
			}

			ep = NCC_DLIST_NEXT(gateway_list, ep);
		}
	}

	/*
	 *	And a pcap raw socket (if we need one).
	 */
#ifdef HAVE_LIBPCAP
	if (CONF.interface) {
		dpc_pcap_init(global_ctx);
	}
#endif

	/* Read input from stdin and input files.
	 */
	if (dpc_input_load(global_ctx) < 0) {
		exit(EXIT_FAILURE);
	}

	/* Debug configuration.
	 */
	dpc_config_debug(dpc_config);
	ncc_segment_list_debug(0, segment_list, (dpc_debug_lvl >= 4));
	dpc_input_list_debug(&input_list);

	/*
	 *	If packet trace level is unspecified, figure out something automatically.
	 */
	if (CONF.packet_trace_lvl < 0) {
		if (CONF.session_max_num == 1 || (!CONF.template && input_list.size == 1 && CONF.input_num_use == 1)) {
			/* Only one request: full packet print. */
			CONF.packet_trace_lvl = 2;
		} else if (CONF.session_max_active == 1) {
			/*
			 *	Several requests, but no parallelism.
			 *	If the number of sessions, or the max duration, are reasonably small: print packets header.
			 *	Otherwise: no packet print.
			 */
			if ( (CONF.session_max_num && CONF.session_max_num <= 50)
			  || (CONF.duration_start_max && CONF.duration_start_max <= 0.5)
			  || (!CONF.template && input_list.size * CONF.input_num_use <= 50)
			  ) {
				CONF.packet_trace_lvl = 1;
			} else {
				CONF.packet_trace_lvl = 0;
			}
		} else {
			/* Several request in parallel: no packet print. */
			CONF.packet_trace_lvl = 0;
		}
		DEBUG("Packet trace level set to: %u", CONF.packet_trace_lvl);
	}

#ifdef HAVE_LIBPCAP
	if (CONF.interface) {
		/*
		 *	Now that we've opened all the sockets we need, build the pcap filter.
		 */
		dpc_pcap_filter_build(pl, pcap);
	}
#endif

	fte_start = fte_job_start = fr_time(); /* Job start timestamp. */

	if (CONF.duration_start_max) { /* Set timestamp limit for starting new input sessions. */
		CONF.fte_start_max = ncc_float_to_fr_time(CONF.duration_start_max) + fte_job_start;
	}

	if (!CONF.ignore_invalid_input && num_input_invalid > 0) {
		ERROR("Invalid input configuration");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Everything seems to have loaded OK, exit gracefully.
	 */
	if (check_config) {
		DEBUG("Configuration appears to be OK");
		dpc_end();
	}

	/*
	 *	Ensure we have something to work with.
	 */
	DEBUG3("Input list size: %u", NCC_DLIST_SIZE(&input_list));
	if (NCC_DLIST_SIZE(&input_list) == 0) {
		if (!with_stdin_input && argc < 2) usage(EXIT_SUCCESS); /* If no input nor arguments, show usage. */

		WARN("No valid input loaded, nothing to do");
		dpc_exit();
	}

	/*
	 * Set signal handler.
	 */
	if ( (fr_set_signal(SIGHUP, dpc_signal) < 0) ||
	     (fr_set_signal(SIGINT, dpc_signal) < 0) ||
	     (fr_set_signal(SIGTERM, dpc_signal) < 0))
	{
		PERROR("Failed to install signal handler");
		exit(EXIT_FAILURE);
	}

	/* Arm a timer to produce periodic statistics. */
	dpc_event_add_progress_stats();

	/* Execute the main processing loop. */
	dpc_main_loop();

	/* This is the end. */
	dpc_end();
}

/**
 * Print program version and optional dependencies.
 */
#ifdef HAVE_LIBPCAP
  #define BUILT_WITH_LIBPCAP "yes"
#else
 #define BUILT_WITH_LIBPCAP "no"
#endif

#ifdef HAVE_LIBCURL
  #define BUILT_WITH_LIBCURL "yes"
#else
  #define BUILT_WITH_LIBCURL "no"
#endif

#ifdef HAVE_JSON
  #define BUILT_WITH_LIBJSON "yes"
#else
  #define BUILT_WITH_LIBJSON "no"
#endif

static void version_print(void)
{
	printf("%s version %s: %s\n", progname, prog_version, fr_version);
	printf("Program was built with:\n");
	printf("- libpcap: " BUILT_WITH_LIBPCAP "\n");
	printf("- libcurl: " BUILT_WITH_LIBCURL "\n");
	printf("- libjson: " BUILT_WITH_LIBJSON "\n");
}

/*
 *	Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *fp = status ? stderr : stdout;

	/* General usage should only be printed when specifically requested by the user.
	 */
	if (status) {
		fprintf(fp, "Try '%s --help' for more information.\n", progname);
		exit(status);
	}

	fprintf(fp, "Usage: %s [options] [<server>[:<port>] [<command>]]\n", progname);
	fprintf(fp, "  <server>:<port>  The DHCP server. If omitted, it must be specified in input items.\n");
	fprintf(fp, "  <command>        One of (message type): discover, request, decline, release, inform, lease_query.\n");
	fprintf(fp, "                   (or the message type numeric value: 1 = Discover, 2 = Request, ...).\n");
	fprintf(fp, "                   Or (workflow): dora, doradec (DORA / Decline), dorarel (DORA / Release).\n");
	fprintf(fp, "                   If omitted, message type must be specified in input items.\n");
	fprintf(fp, " Options:\n");
	fprintf(fp, "  -a <ipaddr>      Authorized server. Only allow replies from this server. Can be set more than once.\n");
#ifdef HAVE_LIBPCAP
	fprintf(fp, "  -A               Wait for multiple Offer replies to a broadcast Discover (requires option -i).\n");
#endif
	fprintf(fp, "  -c <num>         Use each input item up to <num> times.\n");
	fprintf(fp, "  -C               Check configuration and exit.\n");
	fprintf(fp, "  -D <dir>         Dictionaries main directory (default: directory share/freeradius/dictionary of FreeRADIUS installation).\n");
	fprintf(fp, "  -f <file>        Read input items from <file>, in addition to stdin. Can be set more than once.\n");
	fprintf(fp, "  -g <gw>[:port]   Handle sent packets as if relayed through giaddr <gw> (hops: 1, src: giaddr:port).\n");
	fprintf(fp, "                   A comma-separated list may be specified, in which case packets will be sent using all\n");
	fprintf(fp, "                   of those gateways in a round-robin fashion.\n");
	fprintf(fp, "  -h               Print this help message.\n");
#ifdef HAVE_LIBPCAP
	fprintf(fp, "  -i <interface>   Use this interface for unconfigured clients to broadcast through a raw socket.\n");
#endif
	fprintf(fp, "  -I <num>         Start generating xid values with <num>.\n");
	fprintf(fp, "  -L <seconds>     Limit duration for starting new input sessions.\n");
	fprintf(fp, "  -n <name>        Label this instance of the program.\n");
	fprintf(fp, "  -N <num>         Start at most <num> sessions from input items.\n");
	fprintf(fp, "  -p <num>         Send up to <num> session initial requests in parallel.\n");
	fprintf(fp, "  -P <num>         Packet trace level (0: none, 1: header, 2: and attributes, 3: and hex data).\n");
	fprintf(fp, "  -r <num>         Rate limit. Maximum new input sessions initialized per second.\n");
	fprintf(fp, "  -s <seconds>     Display ongoing statistics information at periodic time intervals.\n");
	fprintf(fp, "  -t <seconds>     Maximum time spent waiting for a reply to a request previously sent.\n");
	fprintf(fp, "  -T               Template mode.\n");
	fprintf(fp, "  -v               Print version information.\n");
	fprintf(fp, "  -x               Turn on additional debugging. (-xx gives more debugging).\n");
	fprintf(fp, "  -X               Turn on FreeRADIUS libraries debugging (use this in conjunction with -x).\n");
	fprintf(fp, "\n");
	fprintf(fp, "Refer to manual for the full usage (with long options).\n");

	exit(status);
}
