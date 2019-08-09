/*
 * dhcperfcli.c
 */

#include "dhcperfcli.h"
#include "ncc_util.h"
#include "ncc_xlat.h"
#include "dpc_packet_list.h"
#include "dpc_util.h"
#include "dpc_xlat.h"
#include "dpc_config.h"

#include <getopt.h>

static char const *prog_version = RADIUSD_VERSION_STRING_BUILD("FreeRADIUS");


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

fr_time_t fte_start; /* Program execution start timestamp. */
int dpc_debug_lvl = 0;

dpc_context_t exe_ctx = {
	.progress_interval = 10.0,
	.session_max_active = 1,

	.pr_stat_per_input = 1,
	.pr_stat_per_input_max = 20,

	.min_session_for_rps = 50,
	.min_session_time_for_rps = 0.9,
	.min_ref_time_rate_limit = 0.2,
	.rate_limit_time_lookahead = 0.02,
};

static dpc_config_t default_config = {
	.request_timeout = 1.0,
	.retransmit_max = 2,
};

fr_dict_attr_t const *attr_packet_dst_ip_address;
fr_dict_attr_t const *attr_packet_dst_port;
fr_dict_attr_t const *attr_packet_src_ip_address;
fr_dict_attr_t const *attr_packet_src_port;

fr_dict_attr_t const *attr_encoded_data;
fr_dict_attr_t const *attr_authorized_server;
fr_dict_attr_t const *attr_workflow_type;
fr_dict_attr_t const *attr_start_delay;
fr_dict_attr_t const *attr_rate_limit;
fr_dict_attr_t const *attr_max_duration;
fr_dict_attr_t const *attr_max_use;
fr_dict_attr_t const *attr_request_label;

fr_dict_attr_t const *attr_dhcp_hop_count;
fr_dict_attr_t const *attr_dhcp_transaction_id;
fr_dict_attr_t const *attr_dhcp_client_ip_address;
fr_dict_attr_t const *attr_dhcp_your_ip_address;
fr_dict_attr_t const *attr_dhcp_gateway_ip_address;
fr_dict_attr_t const *attr_dhcp_server_identifier;
fr_dict_attr_t const *attr_dhcp_requested_ip_address;
fr_dict_attr_t const *attr_dhcp_message_type;

static char const *progname;

/*
 *	Dictionaries and attributes.
 */
static char alt_dict_dir[PATH_MAX + 1] = ""; /* Alternate directory for dictionaries. */
static char const *dict_dir = DICTDIR;
static char const *dict_fn_freeradius = "freeradius/dictionary.freeradius.internal";
//static char const *dict_fn_dhcperfcli = "dhcperfcli/dictionary.dhcperfcli.internal";

static fr_dict_t *dict_freeradius;
static fr_dict_t *dict_dhcperfcli;
fr_dict_t *dict_dhcpv4;

extern fr_dict_autoload_t dpc_dict_autoload[];
fr_dict_autoload_t dpc_dict_autoload[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" }, /* "freeradius" identifies internal dictionary - otherwise it's protocol. */
	{ .out = &dict_dhcpv4, .proto = "dhcpv4" },
	{ .out = &dict_dhcperfcli, .proto = "dhcperfcli" },
	{ NULL }
};

extern fr_dict_attr_autoload_t dpc_dict_attr_autoload[];
fr_dict_attr_autoload_t dpc_dict_attr_autoload[] = {

	{ .out = &attr_packet_dst_ip_address, .name = "Packet-Dst-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_dst_port, .name = "Packet-Dst-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_ip_address, .name = "Packet-Src-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_freeradius },
	{ .out = &attr_packet_src_port, .name = "Packet-Src-Port", .type = FR_TYPE_UINT16, .dict = &dict_freeradius },

	{ .out = &attr_encoded_data, .name = "DHCP-Encoded-Data", .type = FR_TYPE_OCTETS, .dict = &dict_dhcperfcli },
	{ .out = &attr_authorized_server, .name = "DHCP-Authorized-Server", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcperfcli },
	{ .out = &attr_workflow_type, .name = "DHCP-Workflow-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcperfcli },
	{ .out = &attr_start_delay, .name = "Start-Delay", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
	{ .out = &attr_rate_limit, .name = "Rate-Limit", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
	{ .out = &attr_max_duration, .name = "Max-Duration", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },
	{ .out = &attr_max_use, .name = "Max-Use", .type = FR_TYPE_UINT32, .dict = &dict_dhcperfcli },
	{ .out = &attr_request_label, .name = "Request-Label", .type = FR_TYPE_STRING, .dict = &dict_dhcperfcli },

	{ .out = &attr_dhcp_hop_count, .name = "DHCP-Hop-Count", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_transaction_id, .name = "DHCP-Transaction-Id", .type = FR_TYPE_UINT32, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_client_ip_address, .name = "DHCP-Client-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_your_ip_address, .name = "DHCP-Your-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_gateway_ip_address, .name = "DHCP-Gateway-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },

	{ .out = &attr_dhcp_server_identifier, .name = "DHCP-DHCP-Server-Identifier", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_requested_ip_address, .name = "DHCP-Requested-IP-Address", .type = FR_TYPE_IPV4_ADDR, .dict = &dict_dhcpv4 },
	{ .out = &attr_dhcp_message_type, .name = "DHCP-Message-Type", .type = FR_TYPE_UINT8, .dict = &dict_dhcpv4 },

	{ NULL }
};

static char const *file_config; /* Optional configuration file. */
static int with_debug_dev = 0;
static int packet_trace_lvl = -1; /* If unspecified, figure out something automatically. */

static dpc_packet_list_t *pl; /* List of outgoing packets. */
static fr_event_list_t *event_list;

static bool with_stdin_input = false; /* Whether we have something from stdin or not. */
static char const *file_input;
ncc_list_t input_list;
static int with_template = 0;
static int with_xlat = 0;
static ncc_list_item_t *template_input_prev; /* In template mode, previous used input item. */

static ncc_endpoint_t server_ep = {
	.ipaddr = { .af = AF_INET, .prefix = 32 },
	.port = DHCP_PORT_SERVER
};
static ncc_endpoint_t client_ep = {
	.ipaddr = { .af = AF_INET, .prefix = 32 },
	.port = DHCP_PORT_CLIENT
};

static ncc_endpoint_list_t *gateway_list; /* List of gateways. */
static fr_ipaddr_t allowed_server; /* Only allow replies from a specific server. */

static int packet_code = FR_CODE_UNDEFINED;
static int workflow_code = DPC_WORKFLOW_NONE;

static bool start_sessions_flag =  true; /* Allow starting new sessions. */
static fr_time_t fte_job_start; /* Job start timestamp. */
static fr_time_t fte_job_end; /* Job end timestamp. */
static fr_time_t fte_sessions_ini_start; /* Start timestamp of starting new sessions. */
static fr_time_t fte_sessions_ini_end; /* End timestamp of starting new sessions. */
static fr_time_t fte_last_session_in; /* Last time a session has been initialized from input. */

static uint32_t input_num = 0; /* Number of input entries read. (They may not all be valid.) */
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
static char *iface;
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

static const FR_NAME_NUMBER request_types[] = {
	{ "discover",    FR_DHCP_DISCOVER },
	{ "request",     FR_DHCP_REQUEST },
	{ "decline",     FR_DHCP_DECLINE },
	{ "release",     FR_DHCP_RELEASE },
	{ "inform",      FR_DHCP_INFORM },
	{ "lease_query", FR_DHCP_LEASE_QUERY },
	{ "auto",        FR_CODE_UNDEFINED },
	{ "-",           FR_CODE_UNDEFINED },
	{ NULL, 0}
};

static const FR_NAME_NUMBER workflow_types[] = {
	{ "dora",        DPC_WORKFLOW_DORA },
	{ "doradec",     DPC_WORKFLOW_DORA_DECLINE },
	{ "dorarel",     DPC_WORKFLOW_DORA_RELEASE },
	{ NULL, 0}
};

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

static ncc_str_array_t *arr_tr_types; /* Store dynamically encountered transaction types. */

char elapsed_buf[NCC_TIME_STRLEN];
#define ELAPSED ncc_fr_delta_time_sprint(elapsed_buf, &fte_job_start, NULL, DPC_DELTA_TIME_DECIMALS)


/*
 *	Static functions declaration.
 */
static void usage(int);
static void version_print(void);

static char *dpc_num_message_type_sprint(char *out, size_t outlen, dpc_packet_stat_t stat_type);
static void dpc_per_input_stats_fprint(FILE *fp, bool force);
static void dpc_progress_stats_fprint(FILE *fp, bool force);
static double dpc_job_elapsed_time_get(void);
static double dpc_start_sessions_elapsed_time_get(void);
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
static int dpc_recv_one_packet(fr_time_delta_t *ftd_wait_time);
static bool dpc_session_handle_reply(dpc_session_ctx_t *session, DHCP_PACKET *reply);
static bool dpc_session_dora_request(dpc_session_ctx_t *session);
static bool dpc_session_dora_release(dpc_session_ctx_t *session);
static bool dpc_session_dora_decline(dpc_session_ctx_t *session);
static void dpc_request_gateway_handle(DHCP_PACKET *packet, ncc_endpoint_t *gateway);
static DHCP_PACKET *dpc_request_init(TALLOC_CTX *ctx, dpc_session_ctx_t *session, dpc_input_t *input);
static int dpc_dhcp_encode(DHCP_PACKET *packet);

static void dpc_session_set_transport(dpc_session_ctx_t *session, dpc_input_t *input);

static bool dpc_item_available(dpc_input_t *item);
static char dpc_item_get_status(dpc_input_t *input);
static double dpc_item_get_elapsed(dpc_input_t *input);
static bool dpc_item_get_rate(double *input_rate, dpc_input_t *input);
static bool dpc_item_rate_limited(dpc_input_t *input);
static dpc_input_t *dpc_get_input_from_template(TALLOC_CTX *ctx);
static dpc_input_t *dpc_get_input(void);
static dpc_session_ctx_t *dpc_session_init_from_input(TALLOC_CTX *ctx);
static void dpc_session_finish(dpc_session_ctx_t *session);

static void dpc_loop_recv(void);
static bool dpc_rate_limit_calc_gen(uint32_t *max_new_sessions, float rate_limit_ref, float elapsed_ref, uint32_t cur_num_started);
static bool dpc_rate_limit_calc(uint32_t *max_new_sessions);
static void dpc_end_start_sessions(void);
static uint32_t dpc_loop_start_sessions(void);
static bool dpc_loop_check_done(void);
static void dpc_main_loop(void);

static bool dpc_input_parse(dpc_input_t *input);
void dpc_input_handle(dpc_input_t *input, ncc_list_t *list);
static int dpc_input_load_from_fp(TALLOC_CTX *ctx, FILE *fp, ncc_list_t *list, char const *filename);
static int dpc_input_load(TALLOC_CTX *ctx);
static int dpc_pair_list_xlat(DHCP_PACKET *packet, VALUE_PAIR *vps);

static int dpc_get_alt_dir(void);
static void dpc_dict_init(TALLOC_CTX *ctx);
static void dpc_event_list_init(TALLOC_CTX *ctx);
static void dpc_packet_list_init(TALLOC_CTX *ctx);
static int dpc_command_parse(char const *command);
static ncc_endpoint_list_t *dpc_addr_list_parse(TALLOC_CTX *ctx, ncc_endpoint_list_t **ep_list, char const *in,
                                                ncc_endpoint_t *default_ep);
static void dpc_options_parse(int argc, char **argv);

static void dpc_signal(int sig);
static void dpc_end(void);


/*
 *	Print number of each type of message (sent, received, ...).
 */
char *dpc_num_message_type_sprint(char *out, size_t outlen, dpc_packet_stat_t stat_type)
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

	uint32_t *num_packet = stat_ctx.dpc_stat[stat_type];
	uint32_t remain = num_packet[0]; /* Total. */

	for (i = 1; i < DHCP_MAX_MESSAGE_TYPE; i ++) {
		MSG_TYPE_PRINT(num_packet[i], dpc_message_types[i]);
	}
	if (remain) { /* Unknown message types. */
		MSG_TYPE_PRINT(remain, "unknown");
	}
	return out;
}

/*
 *	Print ongoing statistics detail per input.
 */
static void dpc_per_input_stats_fprint(FILE *fp, bool force)
{
	if (!ECTX.pr_stat_per_input || !with_template || input_list.size < 2) return;

	if (!force && !start_sessions_flag) return; /* Only trace this if we're still starting new sessions, or if force. */

	fprintf(fp, " └─ per-input rate (/s): ");

	ncc_list_item_t *list_item = input_list.head;
	int i = 0;
	while (list_item) {
		dpc_input_t *input = (dpc_input_t *)list_item;
		if (i) fprintf(fp, ", ");

		/* also print status: W = waiting, A = active, T = terminated. */
		char status = dpc_item_get_status(input);
		fprintf(fp, "#%u (%c)", input->id, status);

		if (status != 'W') {
			double input_rate = 0;
			if (dpc_item_get_rate(&input_rate, input)) {
				fprintf(fp, ": %.3f", input_rate);
			} else {
				fprintf(fp, ": N/A"); /* No relevant rate. */
			}
		}

		i++;
		if (i >= ECTX.pr_stat_per_input_max) break;

		list_item = list_item->next;
	}
	fprintf(fp, "\n");
}

/*
 *	Print ongoing job statistics summary.
 *	E.g.:
 *	(*) t(8.001) (80.0%) sessions: [started: 39259 (31.8%), ongoing: 10], rate (/s): 4905.023
 */
static void dpc_progress_stats_fprint(FILE *fp, bool force)
{
	/* Prefix to easily distinguish these ongoing statistics from packet traces and other logs. */
	fprintf(fp, "(*) ");

	/* Elapsed time. */
	fprintf(fp, "t(%s)", ELAPSED);
	if (ECTX.duration_start_max) {
		/* And percentage of max duration (if set). */
		double duration_progress = 100 * dpc_job_elapsed_time_get() / ECTX.duration_start_max;
		fprintf(fp, " (%.1f%%)", duration_progress);
	}

	/* Sessions. */
	if (session_num > 0) {
		fprintf(fp, " sessions: [in: %u", session_num_in);

		/* And percentage of max number of sessions (if set). Unless we're done starting new sessions. */
		if (ECTX.session_max_num && start_sessions_flag) {
			double session_progress = 100 * (double)session_num_in / ECTX.session_max_num;
			fprintf(fp, " (%.1f%%)", session_progress);
		}

		/* Ongoing (active) sessions. (== number of packets to which we're waiting for a reply) */
		fprintf(fp, ", ongoing: %u", session_num_active);

		/* Packets lost (for which a reply was expected, but we didn't get one. */
		if (STAT_ALL_LOST > 0) {
			fprintf(fp, ", lost: %u", STAT_ALL_LOST);
		}

		/* NAK replies. */
		if (STAT_NAK_RECV > 0) {
			fprintf(fp, ", %s: %u", dpc_message_types[6], STAT_NAK_RECV);
		}

		fprintf(fp, "]");
	}

	/* Print input sessions rate, if: we've handled at least a few sessions, with sufficient job elapsed time.
	 * And we're (still) starting sessions.
	 */
	if (session_num_in >= ECTX.min_session_for_rps
	    && dpc_job_elapsed_time_get() >= ECTX.min_session_time_for_rps
		&& start_sessions_flag) {
		bool per_input = ECTX.rate_limit ? false : true;
		fprintf(fp, ", session rate (/s): %.3f", dpc_get_session_in_rate(per_input));
	}

	fprintf(fp, "\n");

	/* Per-input statistics line. */
	if (session_num_in >= ECTX.min_session_for_rps) {
		dpc_per_input_stats_fprint(fp, force);
	}
}

/*
 *	Obtain the job (either ongoing or finished) elapsed time.
 */
static double dpc_job_elapsed_time_get(void)
// or maybe we should just return a fr_time_t ? TODO.
{
	fr_time_delta_t ftd_elapsed;

	/*
	 *	If job is finished, get elapsed time from start to end.
	 *	Otherwise, get elapsed time from start to now.
	 */
	if (fte_job_end) {
		ftd_elapsed = fte_job_end - fte_job_start;
	} else {
		fr_time_t now = fr_time();
		ftd_elapsed = now - fte_job_start;
	}

	return ncc_fr_time_to_float(ftd_elapsed);
}

/*
 *	Obtain job elapsed time related to starting new sessions.
 */
static double dpc_start_sessions_elapsed_time_get(void)
{
	fr_time_delta_t ftd_elapsed;

	if (!fte_sessions_ini_start) return 0; /* No session started yet. */

	/*
	 *	If we've stopped starting new sessions, get elapsed time from start to this timestamp.
	 *	Otherwise, get elapsed time from start to now.
	 */
	if (fte_sessions_ini_end) {
		ftd_elapsed = fte_sessions_ini_end - fte_sessions_ini_start;
	} else {
		fr_time_t now = fr_time();
		ftd_elapsed = now - fte_sessions_ini_start;
	}

	return ncc_fr_time_to_float(ftd_elapsed);
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
		/* Compute a global session rate:
		 * From when the first session was initialized,
		 * To now (if still starting new sessions) or when the last session was initialized.
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
			fte_end = fr_time();
		}

		/* Compute elapsed time. */
		ftd_elapsed = fte_end - fte_sessions_ini_start;
		elapsed = ncc_fr_time_to_float(ftd_elapsed);
		if (elapsed > 0) { /* Just to be safe. */
			rate = (double)session_num_in / elapsed;
		}

	} else {
		/* Compute the rate per input, and sum them. */
		ncc_list_item_t *list_item = input_list.head;
		while (list_item) {
			dpc_input_t *input = (dpc_input_t *)list_item;

			if (!input->done) { /* Ignore item if we're done with it. */
				double input_rate = 0;
				if (dpc_item_get_rate(&input_rate, input)) {
					rate += input_rate;
				}
			}
			list_item = list_item->next;
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
	size_t max_len = strlen(transaction_types[DPC_TR_ALL]); /* (All) */

	for (i = 0; i < stat_ctx.num_transaction_type; i++) {
		size_t len = strlen(arr_tr_types->strings[i]);
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

	if (stat_ctx.num_transaction_type == 0) return; /* We got nothing. */

	pad_len = dpc_tr_name_max_len() + 1;
	if (pad_len > LG_PAD_TR_TYPE_MAX) pad_len = LG_PAD_TR_TYPE_MAX;

	fprintf(fp, "*** Statistics (per-transaction):\n");

	/* only print "All" if we have more than one (otherwise it's redundant). */
	if (stat_ctx.num_transaction_type > 1) {
		dpc_tr_stat_fprint(fp, pad_len, &stat_ctx.tr_stats[DPC_TR_ALL], transaction_types[DPC_TR_ALL]);
	}

	for (i = 0; i < stat_ctx.num_transaction_type; i++) {
		dpc_tr_stat_fprint(fp, pad_len, &stat_ctx.dyn_tr_stats[i], arr_tr_types->strings[i]);
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
	        ncc_fr_delta_time_sprint(elapsed_buf, &fte_job_start, &fte_job_end, DPC_DELTA_TIME_DECIMALS));

	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Sessions", session_num);

	/* Packets sent (total, and of each message type). */
	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets sent", STAT_ALL_PACKET_SENT);
	if (stat_ctx.dpc_stat[DPC_STAT_PACKET_SENT][0] > 0) {
		fprintf(fp, " (%s)", dpc_num_message_type_sprint(buffer, sizeof(buffer), DPC_STAT_PACKET_SENT));
	}
	fprintf(fp, "\n");

	/* Packets received (total, and of each message type - if any). */
	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets received", stat_ctx.dpc_stat[DPC_STAT_PACKET_RECV][0]);
	if (stat_ctx.dpc_stat[DPC_STAT_PACKET_RECV][0] > 0) {
		fprintf(fp, " (%s)", dpc_num_message_type_sprint(buffer, sizeof(buffer), DPC_STAT_PACKET_RECV));
	}
	fprintf(fp, "\n");

	/* Packets to which no response was received. */
	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Retransmissions", stat_ctx.dpc_stat[DPC_STAT_PACKET_RETR][0]);

	if (retr_breakdown && retr_breakdown[0] > 0) {
		fprintf(fp, "\t%-*.*s: %s\n", LG_PAD_STATS, LG_PAD_STATS, "  Retr breakdown",
		        dpc_retransmit_sprint(buffer, sizeof(buffer), STAT_ALL_PACKET_SENT, retr_breakdown, CONF.retransmit_max));
	}

	fprintf(fp, "\t%-*.*s: %u", LG_PAD_STATS, LG_PAD_STATS, "Packets lost", STAT_ALL_LOST);
	if (STAT_ALL_LOST > 0) {
		fprintf(fp, " (%.1f%%)", 100 * (float)STAT_ALL_LOST / STAT_ALL_PACKET_SENT);
	}
	fprintf(fp, "\n");

	/* Packets received but which were not expected (timed out, sent to the wrong address, or whatever. */
	fprintf(fp, "\t%-*.*s: %u\n", LG_PAD_STATS, LG_PAD_STATS, "Replies unexpected",
	        stat_ctx.num_packet_recv_unexpected);
}

/*
 *	Update a type of transaction statistics, with one newly completed transaction:
 *	number of such transactions, cumulated rtt, min/max rtt.
 */
static void dpc_tr_stats_update_values(dpc_transaction_stats_t *my_stats, fr_time_delta_t rtt)
{
	if (!rtt) return;

	/* Update 'rtt_min'. */
	if (my_stats->num == 0 || rtt < my_stats->rtt_min) {
		my_stats->rtt_min = rtt;
	}

	/* Update 'rtt_max'. */
	if (my_stats->num == 0 || rtt > my_stats->rtt_max) {
		my_stats->rtt_max = rtt;
	}

	/* Update 'rtt_cumul' and 'num'. */
	my_stats->rtt_cumul += rtt;
	my_stats->num ++;
}

/*
 *	Update statistics for a type of transaction
 */
static void dpc_tr_stats_update(dpc_transaction_type_t tr_type, fr_time_delta_t rtt)
{
	if (tr_type < 0 || tr_type >= DPC_TR_MAX) return;
	if (!rtt) return;

	dpc_transaction_stats_t *my_stats = &stat_ctx.tr_stats[tr_type];

	dpc_tr_stats_update_values(my_stats, rtt);

	DEBUG_TRACE("Updated transaction stats: type: %d, num: %d, this rtt: %.6f, min: %.6f, max: %.6f",
	            tr_type, my_stats->num, ncc_fr_time_to_float(rtt),
	            ncc_fr_time_to_float(my_stats->rtt_min), ncc_fr_time_to_float(my_stats->rtt_max));
}

/*
 *	Update statistics for a dynamically named transaction type.
 */
static void dpc_dyn_tr_stats_update(dpc_session_ctx_t *session, fr_time_delta_t rtt)
{
	char name[256];

	/* Build the transaction name. */
	dpc_session_transaction_sprint(name, sizeof(name), session);

	/* Get the transaction name id. */
	int i = ncc_str_array_index(global_ctx, &arr_tr_types, name);

	if (i >= stat_ctx.num_transaction_type) {
		TALLOC_REALLOC_ZERO(global_ctx, stat_ctx.dyn_tr_stats,
		                    dpc_transaction_stats_t, stat_ctx.num_transaction_type, i + 1);

		stat_ctx.num_transaction_type = i + 1;
	}

	dpc_transaction_stats_t *my_stats = &stat_ctx.dyn_tr_stats[i];
	dpc_tr_stats_update_values(my_stats, rtt);

	DEBUG_TRACE("Updated named transaction stats: id: %u, name: [%s], num: %u, this rtt: %.6f, min: %.6f, max: %.6f",
	            i, name, my_stats->num, ncc_fr_time_to_float(rtt),
	            ncc_fr_time_to_float(my_stats->rtt_min), ncc_fr_time_to_float(my_stats->rtt_max));
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
	dpc_dyn_tr_stats_update(session, rtt);

	/* Also update for 'All'. */
	dpc_tr_stats_update(DPC_TR_ALL, rtt);
}

/*
 *	Event callback: progress statistics summary.
 */
static void dpc_progress_stats(UNUSED fr_event_list_t *el, UNUSED fr_time_t now, UNUSED void *ctx)
{
	/* Do statistics summary. */
	dpc_progress_stats_fprint(stdout, false);

	/* ... and schedule next time. */
	dpc_event_add_progress_stats();
}

/*
 *	Add timer event: progress statistics summary.
 */
static void dpc_event_add_progress_stats(void)
{
	if (!ECTX.ftd_progress_interval) return;

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
		fte_progress_stat += ECTX.ftd_progress_interval;
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
		DEBUG_TRACE("Stop waiting for more replies");
	} else {
		DEBUG_TRACE("Request timed out (retransmissions so far: %u)", session->retransmit);

		if (!signal_done && dpc_retransmit(session)) {
			/* Packet has been successfully retransmitted. */
			STAT_INCR_PACKET_RETR(session->request);
			return;
		}

		if (packet_trace_lvl >= 1) dpc_packet_digest_fprint(fr_log_fp, session, session->request, DPC_PACKET_TIMEOUT);

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
	fte_event += (timeout_in ? *timeout_in : ECTX.ftd_request_timeout);

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

/*
 *	Send one packet.
 *	Grab a socket, insert packet in the packet list (and obtain an id), encode DHCP packet, and send it.
 *	Returns: 0 = success, -1 = error.
 */
static int dpc_send_one_packet(dpc_session_ctx_t *session, DHCP_PACKET **packet_p)
// note: we need a 'DHCP_PACKET **' for dpc_packet_list_id_alloc.
{
	DHCP_PACKET *packet = *packet_p;
	int my_sockfd;
	int ret;

	DEBUG_TRACE("Preparing to send one packet");

	/*
	 *	Get a socket to send this over.
	 */
#ifdef HAVE_LIBPCAP
	if (session->input->ext.with_pcap) {
		my_sockfd = pcap->fd;
	} else
#endif
	{
		my_sockfd = dpc_socket_provide(pl, &packet->src_ipaddr, packet->src_port);
	}
	if (my_sockfd < 0) {
		SPERROR("Failed to provide a suitable socket");
		return -1;
	}

	if (packet->id == DPC_PACKET_ID_UNASSIGNED) {
		/* Need to assign an xid to this packet. */
		bool rcode;

		/*
		 *	Set packet->id to prefered value (if any). Note: it will be reset if allocation fails.
		 */
		packet->id = session->input->ext.xid;

		/* An xlat expression may have been provided. Go look in packet vps. */
		if (packet->id == DPC_PACKET_ID_UNASSIGNED && with_xlat) {
			VALUE_PAIR *vp_xid = ncc_pair_find_by_da(packet->vps, attr_dhcp_transaction_id);
			if (vp_xid) packet->id = vp_xid->vp_uint32;
		}

		/*
		 *	Allocate an id, and prepare the packet (socket fd, src addr)
		 */
		rcode = dpc_packet_list_id_alloc(pl, my_sockfd, packet_p);
		if (!rcode) {
			SERROR("Failed to allocate packet xid");
			return -1;
		}
	}

	dpc_assert(packet->id != DPC_PACKET_ID_UNASSIGNED);
	dpc_assert(packet->data == NULL);

	/*
	 *	Encode the packet.
	 */
	DEBUG_TRACE("Encoding and sending packet");
	if (dpc_dhcp_encode(packet) < 0) { /* Should never happen. */
		SERROR("Failed to encode request packet");
		exit(EXIT_FAILURE);
	}

	/*
	 *	Send the packet.
	 */
	packet->timestamp = fr_time(); /* Store packet send time. */

	// shouldn't FreeRADIUS lib do that ? TODO.
	// on receive, reply timestamp is set by fr_dhcpv4_udp_packet_recv
	// - actual value is set in recvfromto right before returning

	packet->sockfd = my_sockfd;

#ifdef HAVE_LIBPCAP
	if (session->input->ext.with_pcap) {
		/* Send using pcap raw socket. */
		packet->if_index = pcap->if_index; /* So we can trace it. */
		ret = fr_dhcpv4_pcap_send(pcap, eth_bcast, packet);
		/*
		 *	Note: we're sending from our real Ethernet source address (from the selected interface,
		 *	set by fr_pcap_open / fr_pcap_mac_addr), *not* field 'chaddr' from the DHCP packet
		 *	(which is a fake hardware address).
		 *	This because we want replies (sent by the DHCP server to our Ethernet address) to reach us.
		 */
	} else
#endif
	{
		/* Send using a connectionless UDP socket (sendfromto). */
		ret = fr_dhcpv4_udp_packet_send(packet);
	}
	if (ret < 0) {
		SPERROR("Failed to send packet");
		return -1;
	}

	dpc_packet_fprint(fr_log_fp, session, packet, DPC_PACKET_SENT, packet_trace_lvl); /* Print request packet. */

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
static int dpc_recv_one_packet(fr_time_delta_t *ftd_wait_time)
{
	fd_set set;
	struct timeval tvi_wait = { 0 };
	DHCP_PACKET *packet = NULL, **packet_p;
	VALUE_PAIR *vp;
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
		tvi_wait = fr_time_delta_to_timeval(*ftd_wait_time);
		DEBUG_TRACE("Max wait time: %.6f", ncc_timeval_to_float(&tvi_wait));
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

	DEBUG_TRACE("Received packet %s, id: %u (0x%08x)",
	            dpc_packet_from_to_sprint(from_to_buf, packet, false), packet->id, packet->id);

	if (is_ipaddr_defined(allowed_server)) {
		/*
		 *	Only allow replies from a specific server (overall policy set through option -a).
		 */
		if (fr_ipaddr_cmp(&packet->src_ipaddr, &allowed_server) != 0) {
			DEBUG("Received packet Id %u (0x%08x) from unauthorized server (%s): ignored.",
			      packet->id, packet->id, fr_inet_ntop(from_to_buf, sizeof(from_to_buf), &packet->src_ipaddr));
			fr_radius_packet_free(&packet);
			return -1;
		}
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

	DEBUG_TRACE("Packet belongs to session id: %d", session->id);

	if ((vp = ncc_pair_find_by_da(session->request->vps, attr_authorized_server))) {
		/*
		 *	Only allow replies from a specific server (per-packet policy set through attribute).
		 */
		if (fr_ipaddr_cmp(&packet->src_ipaddr, &vp->vp_ip) != 0) {
			SDEBUG("Received packet Id %u (0x%08x) from unauthorized server (%s): ignored.",
			       packet->id, packet->id, fr_inet_ntop(from_to_buf, sizeof(from_to_buf), &packet->src_ipaddr));
			fr_radius_packet_free(&packet);
			return -1;
		}
		// note: we can get "unexpected packets" with this.
		// TODO: keep a context of broadcast packets for a little while so we can wait for all responses ?
	}

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

/*
 *	Handle a reply which belongs to a given ongoing session.
 *	Returns true if we're not done with the session (so it should not be terminated yet), false otherwise.
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
		 */
		DEBUG_TRACE("Discarding received reply code %d (session state: %d)", reply->code, session->state);

		dpc_packet_digest_fprint(fr_log_fp, session, reply, DPC_PACKET_RECEIVED_DISCARD);
		fr_radius_packet_free(&reply);

		return true; /* Session is not finished. */
	}

	session->reply = reply;
	talloc_steal(session, reply); /* Reparent reply packet (allocated on NULL context) so we don't leak. */

	/* Compute rtt.
	 * Relative to initial request so we get the real rtt (regardless of retransmissions).
	 */
	session->ftd_rtt = session->reply->timestamp - session->fte_init;
	DEBUG_TRACE("Packet response time: %.6f", ncc_fr_time_to_float(session->ftd_rtt));

	dpc_packet_fprint(fr_log_fp, session, reply, DPC_PACKET_RECEIVED, packet_trace_lvl); /* print reply packet. */

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
		DEBUG_TRACE("Waiting for more replies from other DHCP servers");
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
	DEBUG_TRACE("DORA: received valid Offer, now preparing Request");

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
	DEBUG_TRACE("DORA-Release: received valid Ack, now preparing Release");

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
	DEBUG_TRACE("DORA-Decline: received valid Ack, now preparing Decline");

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
	DEBUG_TRACE("Assigning packet to gateway: %s", ncc_endpoint_sprint(ep_buf, gateway));

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
	DEBUG_TRACE("New packet allocated (code: %u, %s)", request->code,
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
		session->gateway = ncc_ep_list_get_next(gateway_list);
		session->src = *(session->gateway);
	}
}


/*
 *	Check if a given input item is available for starting sessions.
 *	Return true if it is.
 */
static bool dpc_item_available(dpc_input_t *item)
{
	/* Check if this input is available for starting sessions. */
	if (!item->start_delay || dpc_job_elapsed_time_get() >= item->start_delay) {
		return true;
	}
	return false;
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
		ftd_elapsed = fr_time() - input->fte_start;
	}

	return ncc_fr_time_to_float(ftd_elapsed);
}

/*
 *	Get the use rate of an input item, relative to the point at which it started being used,
 *	up to now (if it's still active) or the last time is was used.
 */
static bool dpc_item_get_rate(double *input_rate, dpc_input_t *input)
{
	if (!input->fte_start) {
		return false; /* Item has not been used yet. */
	}

	double elapsed = dpc_item_get_elapsed(input);

	if (input->num_use < ECTX.min_session_for_rps
	    || elapsed < ECTX.min_session_time_for_rps) return false;

	*input_rate = (double)input->num_use / elapsed;
	return true;
}

/*
 *	Check if an item is currently rate limited or not.
 *	Return: true = item is not allowed to start new sessions at the moment (rate limit enforced).
 */
static bool dpc_item_rate_limited(dpc_input_t *input)
{
	if (!input->rate_limit) return false; /* No rate limit applies to this input. */

	float elapsed_ref = dpc_item_get_elapsed(input);
	uint32_t max_new_sessions = 0;

	dpc_rate_limit_calc_gen(&max_new_sessions, input->rate_limit, elapsed_ref, input->num_use);
	return (max_new_sessions == 0);
}

/*
 *	Get an input item from template (round robin on all template inputs).
 */
static dpc_input_t *dpc_get_input_from_template(TALLOC_CTX *ctx)
{
	uint32_t checked = 0, not_done = 0;
	fr_time_t now = fr_time();

	while (checked < input_list.size) {
		if (!template_input_prev) template_input_prev = input_list.head;

		dpc_input_t *input = (dpc_input_t *)template_input_prev; /* No need for a copy (read-only). This is faster. */
		template_input_prev = template_input_prev->next;

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

		not_done++;

		if (!dpc_item_rate_limited(input) && dpc_item_available(input)) return input;
	}

	if (not_done == 0) {
		INFO("No remaining active input: will not start any new session.");
		dpc_end_start_sessions();
	}

	return NULL;
}

/*
 *	Get an input item. If using a template, dynamically generate a new item.
 */
static dpc_input_t *dpc_get_input()
{
	if (!with_template) {
		return NCC_LIST_DEQUEUE(&input_list);
	} else {
		return dpc_get_input_from_template(global_ctx);
	}
}

/*
 *	Initialize a new session.
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

	DEBUG_TRACE("Initializing a new session (id: %u)", session_num);

	/* Store time of first session initialized. */
	if (!fte_sessions_ini_start) {
		fte_sessions_ini_start = fr_time();
	}

	/* If this is the first time this input is used, store current time. */
	if (input->num_use == 0) {
		DEBUG("Input (id: %u) start (max use: %u, duration: %.1f s, rate: %.1f)",
		      input->id, input->max_use, input->max_duration, input->rate_limit);

		input->fte_start = fr_time();

		/* Also store input max start time, if applicable. */
		if (input->max_duration) {
			input->fte_max_start = input->fte_start + ncc_float_to_fr_time(input->max_duration);
		}

		/* If there is a global max start time, store whichever comes first (input, global). */
		if (ECTX.fte_start_max
		    && (!input->fte_max_start || input->fte_max_start > ECTX.fte_start_max)) {
			input->fte_max_start = ECTX.fte_start_max;
		}
	}

	input->num_use ++;

	/*
	 *	If not using a template, copy this input item if it has to be used again.
	 */
	if (!with_template && input->num_use < input->max_use) {
		DEBUG_TRACE("Input (id: %u) will be reused (num use: %u, max: %u)",
		            input->id, input->num_use, input->max_use);
		dpc_input_t *input_dup = dpc_input_item_copy(ctx, input);
		if (input_dup) {
			/*
			 *	Add it to the list of input items.
			 */
			NCC_LIST_ENQUEUE(&input_list, input_dup);
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
		NCC_LIST_DRAW(input);
		talloc_free(input);
		return NULL;
	}

	session->id = session_num ++;

	session->request = packet;
	talloc_steal(session, packet);

	session->input = input; /* Reference to the input (note: it doesn't belong to us). */

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

	return session;
}

/*
 *	One session is finished.
 */
static void dpc_session_finish(dpc_session_ctx_t *session)
{
	if (!session) return;

	DEBUG_TRACE("Terminating session (id: %u)", session->id);

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

	while (!done) {
		/*
		 *	Allow to block waiting until the next scheduled event.
		 *	We know we don't have anything else to do until then. It will avoid needlessly hogging one full CPU.
		 */
		fr_time_t now, when;
		fr_time_delta_t wait_max = 0;

		if (session_num_active >= ECTX.session_max_active && ncc_fr_event_timer_peek(event_list, &when)) {
			now = fr_time();
			if (when > now) wait_max = when - now; /* No negative. */
		}

		/*
		 *	Receive and process packets until there's nothing left incoming.
		 */
		if (dpc_recv_one_packet(&wait_max) < 1) break;
	}
}

/*
 *	Figure out how to enforce a rate limit. To do so we limit the number of new sessions allowed to be started.
 *	This can be used globally (to enforce a global rate limit on all sessions), or per-input.
 *
 *	Returns: true if a limit has to be enforced at the moment, false otherwise.
 */
static bool dpc_rate_limit_calc_gen(uint32_t *max_new_sessions, float rate_limit_ref, float elapsed_ref, uint32_t cur_num_started)
{
	if (elapsed_ref < ECTX.min_ref_time_rate_limit) {
		/*
		 *	Consider a minimum elapsed time interval for the beginning.
		 *	We may start more sessions than the desired rate before this time, but this will be quickly corrected.
		 */
		elapsed_ref = ECTX.min_ref_time_rate_limit;
	}

	/* Allow to start a bit more right now to compensate for server delay and our own internal tasks. */
	elapsed_ref += ECTX.rate_limit_time_lookahead;

	uint32_t session_limit = rate_limit_ref * elapsed_ref + 1; /* + 1 so we always start at least one at the beginning. */

	if (cur_num_started >= session_limit) {
		/* Already beyond limit, don't start new sessions for now. */
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
	if (!ECTX.rate_limit) return false;

	float elapsed_ref = dpc_start_sessions_elapsed_time_get();
	return dpc_rate_limit_calc_gen(max_new_sessions, ECTX.rate_limit, elapsed_ref, session_num);
}


/*
 *	Stop starting new sessions.
 */
static void dpc_end_start_sessions(void)
{
	if (start_sessions_flag) {
		start_sessions_flag = false;
		fte_sessions_ini_end = fr_time();

		/* Also mark all input as done. */
		ncc_list_item_t *list_item = input_list.head;
		while (list_item) {
			dpc_input_t *input = (dpc_input_t *)list_item;
			input->done = true;
			input->fte_end = fte_sessions_ini_end;

			list_item = list_item->next;
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
			DEBUG_TRACE("Loop time limit reached, started: %u", num_started);
			break;
		}

		/* Max session limit reached. */
		if (ECTX.session_max_num && session_num >= ECTX.session_max_num) {
			INFO("Max number of sessions (%u) reached: will not start any new session.", ECTX.session_max_num);
			start_sessions_flag = false;
			break;
		}

		/* Time limit reached. */
		if (ECTX.duration_start_max && dpc_job_elapsed_time_get() >= ECTX.duration_start_max) {
			INFO("Max duration (%.3f s) reached: will not start any new session.", ECTX.duration_start_max);
			start_sessions_flag = false;
			break;
		}

		/* No more input. */
		if (!with_template && input_list.size == 0) {
			start_sessions_flag = false;
			break;
		}

		/* Max active session reached. Try again later when we've finished some ongoing sessions.
		 * Note: this does not include sessions handling requests past the initial one (e.g. DORA).
		 */
		if (session_num_parallel >= ECTX.session_max_active) break;

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
static void dpc_loop_timer_events(void)
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
		dpc_loop_timer_events();

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
	if (iface && (fr_ipaddr_is_inaddr_any(&input->ext.src.ipaddr) == 1)
	    && (dpc_ipaddr_is_broadcast(&input->ext.dst.ipaddr) == 1)
	   ) {
		DEBUG_TRACE("Input (id: %u) involves broadcast using pcap raw socket", input->id);

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

/*
 *	Parse an input item and prepare information necessary to build a packet.
 */
static bool dpc_input_parse(dpc_input_t *input)
{
	fr_cursor_t cursor;
	VALUE_PAIR *vp;
	VALUE_PAIR *vp_encoded_data = NULL, *vp_workflow_type = NULL;

#define WARN_ATTR_VALUE(_l) { \
		PWARN("Invalid value for attribute %s (expected: %s). Discarding input (id: %u)", vp->da->name, _l, input->id); \
		return false; \
	}

	input->ext.code = FR_CODE_UNDEFINED;

	/* Default: global option -c, can be overriden through Max-Use attr. */
	input->max_use = ECTX.input_num_use;

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

	/*
	 *	Pre-process attributes (1: xlat).
	 */
	for (vp = fr_cursor_init(&cursor, &input->vps);
	     vp;
	     vp = fr_cursor_next(&cursor)) {

		/*
		 *	A value is identified as an xlat expression if it is a double quoted string which contains some %{...}
		 *	e.g. "foo %{tolower:Bar}"
		 *
		 *	In this case, the vp has no value, and keeps its original type (vp->vp_type and vp->da->type), which can be anything.
		 *	This entails that the result of xlat expansion would not necessarily be suitable for that vp.
		 */
		if (vp->type == VT_XLAT) {

			if (with_xlat) {
				input->do_xlat = true;

				xlat_exp_t *xlat = NULL;
				ssize_t slen;
				char *value;

				value = talloc_typed_strdup(input, vp->xlat); /* modified by xlat_tokenize */

				slen = xlat_tokenize(global_ctx, &xlat, value, NULL);
				/* Notes:
				 * - First parameter is talloc context.
				 *   We cannot use "input" as talloc context, because we may free the input and still need the parsed xlat expression.
				 *   This happens in non template mode, with "num use > 1".
				 * - Last parameter is "vp_tmpl_rules_t const *rules". (cf. vp_tmpl_rules_s in src/lib/server/tmpl.h)
				 *   NULL means default rules are used, which is fine.
				 */

				if (slen < 0) {
					char *spaces, *text;
					fr_canonicalize_error(input, &spaces, &text, slen, vp->xlat);

					WARN("Failed to parse '%s' expansion string. Discarding input (id: %u)", vp->da->name, input->id);
					INFO("%s", text);
					INFO("%s^ %s", spaces, fr_strerror());

					talloc_free(spaces);
					talloc_free(text);
					talloc_free(value);
					talloc_free(xlat);

					return false;
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
					return false;
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

		} else if (vp->da == attr_start_delay) { /* Start-Delay = <n> */
			if (!ncc_str_to_float(&input->start_delay, vp->vp_strvalue, false)) WARN_ATTR_VALUE("positive floating point number");

		} else if (vp->da == attr_rate_limit) { /* Rate-Limit = <n> */
			if (!ncc_str_to_float(&input->rate_limit, vp->vp_strvalue, false)) WARN_ATTR_VALUE("positive floating point number");

		} else if (vp->da == attr_max_duration) { /* Max-Duration = <n> */
			if (!ncc_str_to_float(&input->max_duration, vp->vp_strvalue, false)) WARN_ATTR_VALUE("positive floating point number");

		} else if (vp->da == attr_max_use) { /* Max-Use = <n> */
			input->max_use = vp->vp_uint32;

		} else if (vp->da == attr_request_label) { /* Request-Label = <string> */
			input->request_label = talloc_strdup(input, vp->vp_strvalue);
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
		return false;
	}

	/*
	 *	Pre-allocate the socket for this input item.
	 *	Unless: in template mode *and* with gateway(s) (in which case we already have the sockets allocated).
	 */
	if (!with_template || !gateway_list) {
		dpc_input_socket_allocate(input);
	}

	/* All good. */
	return true;
}

/*
 *	Debug an input item.
 */
static void dpc_input_debug(dpc_input_t *input)
{
	char ep_buf[NCC_ENDPOINT_STRLEN] = "";

	if (!input || dpc_debug_lvl < 2) return;

	DEBUG2("Input (id: %u) vps read:", input->id);
	ncc_pair_list_fprint(fr_log_fp, input->vps);

	if (dpc_debug_lvl < 3) return;

	if (input->max_use) {
		DEBUG3("  Max use: %u", input->max_use);
	}

	if (input->ext.code) {
		DEBUG3("  Packet code: %u", input->ext.code);
	}
	if (input->ext.workflow) {
		DEBUG3("  Workflow: %u", input->ext.workflow);
	}
	if (input->ext.xid != DPC_PACKET_ID_UNASSIGNED) {
		DEBUG3("  Xid: %u", input->ext.xid);
	}

	if (is_ipaddr_defined(input->ext.src.ipaddr)) {
		DEBUG3("  Src: %s", ncc_endpoint_sprint(ep_buf, &input->ext.src));
	}
	if (is_ipaddr_defined(input->ext.dst.ipaddr)) {
		DEBUG3("  Dst: %s", ncc_endpoint_sprint(ep_buf, &input->ext.dst));
	}
}

/*
 *	Handle a list of input vps we've just read.
 */
void dpc_input_handle(dpc_input_t *input, ncc_list_t *list)
{
	input->id = input_num ++;
	input->ext.xid = DPC_PACKET_ID_UNASSIGNED;

	if (!dpc_input_parse(input)) {
		/*
		 *	Invalid item. Discard.
		 */
		talloc_free(input);
		return;
	}

	/* Trace what we've read. */
	dpc_input_debug(input);

	/*
	 *	Add it to the list of input items.
	 */
	NCC_LIST_ENQUEUE(list, input);
}

/*
 *	Load input vps from the provided file pointer.
 */
static int dpc_input_load_from_fp(TALLOC_CTX *ctx, FILE *fp, ncc_list_t *list, char const *filename)
{
	bool file_done = false;
	dpc_input_t *input;

	/*
	 *	Loop until the file is done.
	 */
	do {
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

		/* Stop reading if we know we won't need it. */
		if (!with_template && ECTX.session_max_num && list->size >= ECTX.session_max_num) break;

	} while (!file_done);

	return 0;
}

/*
 *	Load input vps: first, from stdin (if there is something to read), then from input file (if one is specified).
 */
static int dpc_input_load(TALLOC_CTX *ctx)
{
	FILE *fp = NULL;
	int ret;

	/*
	 *	If there's something on stdin, read it.
	 */
	if (ncc_stdin_peek()) {
		with_stdin_input = true;

		DEBUG("Reading input from stdin");
		if (dpc_input_load_from_fp(ctx, stdin, &input_list, "stdin") < 0) return -1;
	} else {
		DEBUG_TRACE("Nothing to read on stdin");
	}

	/*
	 *	If an input file is provided, read it.
	 */
	if (file_input && strcmp(file_input, "-") != 0) {
		DEBUG("Reading input from file: %s", file_input);

		fp = fopen(file_input, "r");
		if (!fp) {
			ERROR("Failed to open file \"%s\": %s", file_input, strerror(errno));
			return -1;
		}

		ret = dpc_input_load_from_fp(ctx, fp, &input_list, file_input);
		fclose(fp);
		if (ret < 0) return -1;
	}

	DEBUG("Done reading input, list size: %u", input_list.size);

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
				fr_strerror_printf("Failed to expand xlat '%s': %s", vp->da->name, fr_strerror());
				return -1;
			}

			vp->vp_ptr = NULL; /* Otherwise fr_pair_value_strcpy would free our compiled xlat! */

			DEBUG_TRACE("xlat %s = [%s] => (len: %u) [%s]", vp->da->name, vp->xlat, len, buffer);

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

	pcap = fr_pcap_init(ctx, iface, PCAP_INTERFACE_IN_OUT);
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
	if (fr_dict_global_init(ctx, dict_dir) < 0) {
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
	pl = dpc_packet_list_create(ctx, ECTX.base_xid);
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
	workflow_code = fr_str2int(workflow_types, command, DPC_WORKFLOW_NONE);
	if (workflow_code != DPC_WORKFLOW_NONE) return 0;

	/* Or a packet type. */
	packet_code = fr_str2int(request_types, command, -1);
	if (packet_code != -1) return 0;

	/* Nothing goes. */
	return -1;
}

/*
 *	Parse a list of endpoint addresses (gateways, option -g).
 *	Create and populate an endpoint list (sic_endpoint_list_t) with the results.
 */
static ncc_endpoint_list_t *dpc_addr_list_parse(TALLOC_CTX *ctx, ncc_endpoint_list_t **ep_list, char const *in,
                                                ncc_endpoint_t *default_ep)
{
	if (!ep_list || !in) return NULL;

	if (!*ep_list) {
		MEM(*ep_list = talloc_zero(ctx, ncc_endpoint_list_t));
	}

	char *in_dup = talloc_strdup(ctx, in); /* Working copy (strsep alters the string it's dealing with). */
	char *str = in_dup;

	char *p = strsep(&str, ",");
	while (p) {
		/* First trim string of eventual spaces. */
		ncc_str_trim(p, p, strlen(p));

		/* Add this to our list of endpoints. */
		ncc_endpoint_t *ep = ncc_ep_list_add(ctx, *ep_list, p, default_ep);
		if (!ep) {
			PERROR("Failed to create endpoint \"%s\"", p);
			exit(EXIT_FAILURE);
		}
		char ep_buf[NCC_ENDPOINT_STRLEN] = "";
		DEBUG_TRACE("Added endpoint list item #%u: [%s]", (*ep_list)->num - 1, ncc_endpoint_sprint(ep_buf, ep));

		p = strsep(&str, ",");
	}
	talloc_free(in_dup);
	return *ep_list;
}


/* Short options. */
#define OPTSTR_BASE "a:c:C:D:f:g:hI:L:MN:p:P:r:s:t:TvxX"
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
	{ "retransmit",             required_argument, NULL, 1 },
	{ "xlat-file",              required_argument, NULL, 1 },

	/* Long options with short option equivalent. */
	{ "conf-check",             no_argument,       NULL, 'C' },
	{ "dict-dir",               required_argument, NULL, 'D' },
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
	{ "debug",                  no_argument, &with_debug_dev, 1 },
	{ "xlat",                   no_argument, &with_xlat, 1 },

	{ 0, 0, 0, 0 }
};

typedef enum {
	/* Careful: numbering here is important.
	 * It must match long_options order defined above.
	 */
	LONGOPT_IDX_CONF_FILE = 0,
	LONGOPT_IDX_RETRANSMIT,
	LONGOPT_IDX_XLAT_FILE,
} longopt_index_t;

/*
 *	Process command line options and arguments.
 */
static void dpc_options_parse(int argc, char **argv)
{
	int argval;
	int opt_index = -1; /* Stores the option index for long options. */

#define ERROR_OPT_VALUE(_l) { \
		ERROR("Invalid value for option -%c (expected: %s)", argval, _l); \
		usage(1); \
	}

#define ERROR_LONGOPT_VALUE(_l) { \
		ERROR("Invalid value for option --%s (expected: %s)", long_options[opt_index].name, _l); \
		usage(1); \
	}

	/* Parse options: first pass.
	 * Get debug level, and set logging accordingly.
	 */
	optind = 0;
	opterr = 0; /* No error messages. */
	while (1)
	{
		argval = getopt_long(argc, argv, "-x", long_options, &opt_index);
		/*
		 * "If the first character of optstring is '-', then each nonoption argv-element is handled
		 *  as if it were the argument of an option with character code 1."
		 * This prevents getopt_long from modifying argv, as it would normally do.
		 * Also, argument "long_options" must be provided so that options starting with "--x" are not parsed as "-x".
		 */
		if (argval == -1) break;

		switch (argval) {
		case 'x':
			dpc_debug_lvl ++;
			break;
		}
	}

	ECTX.debug_lvl = dpc_debug_lvl;
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

		switch (argval) {
		case 'a':
			if (fr_inet_pton(&allowed_server, optarg, strlen(optarg), AF_INET, false, false) < 0)
				ERROR_OPT_VALUE("ip addr");
			break;

		case 'A':
			multi_offer = true;
			break;

		case 'c':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			ECTX.input_num_use = atoi(optarg);
			break;

		case 'C':
			check_config = true;
			break;

		case 'D':
			dict_dir = optarg;
			break;

		case 'f':
			file_input = optarg;
			break;

		case 'g':
			DEBUG_TRACE("Parsing list of gateway endpoints: [%s]", optarg);
			dpc_addr_list_parse(global_ctx, &gateway_list, optarg, &(ncc_endpoint_t) { .port = DHCP_PORT_RELAY });
			break;

		case 'h':
			usage(0);
			break;

#ifdef HAVE_LIBPCAP
		case 'i':
			iface = optarg;
			break;
#endif

		case 'I':
			if (!ncc_str_to_uint32(&ECTX.base_xid, optarg)) ERROR_OPT_VALUE("integer or hex string");
			break;

		case 'L':
			if (!ncc_str_to_float(&ECTX.duration_start_max, optarg, false)) ERROR_OPT_VALUE("positive floating point number");
			break;

		case 'M':
			ECTX.talloc_memory_report = true;
			break;

		case 'N':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			ECTX.session_max_num = atoi(optarg);
			break;

		case 'p':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			ECTX.session_max_active = atoi(optarg);
			break;

		case 'P':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			packet_trace_lvl = atoi(optarg);
			break;

		case 'r':
			if (!is_integer(optarg)) ERROR_OPT_VALUE("integer");
			ECTX.rate_limit = atoi(optarg);
			break;

		case 's':
			if (!ncc_str_to_float(&ECTX.progress_interval, optarg, false)) ERROR_OPT_VALUE("positive floating point number");
			if (ECTX.progress_interval < 0.1) ECTX.progress_interval = 0.1; /* Don't allow absurdly low values. */
			else if (ECTX.progress_interval > 864000) ECTX.progress_interval = 0; /* Just don't. */
			break;

		case 't':
			if (!ncc_str_to_float32(&CONF.request_timeout, optarg, false)) ERROR_OPT_VALUE("positive floating point number");
			/* 0 is allowed, it means we don't wait for replies, ever.
			 * This entails that:
			 * - we won't have "timed out" requests
			 * - we won't have rtt statistics
			 * - and we probably will have "unexpected replies" (if the server is responsive)
			 */
			if (CONF.request_timeout) {
				/* Don't allow absurd values. */
				if (CONF.request_timeout < 0.01) CONF.request_timeout = 0.01;
				else if (CONF.request_timeout > 3600) CONF.request_timeout = 3600;
			}
			break;

		case 'T':
			with_template = 1;
			break;

		case 'v':
			version_print();
			exit(EXIT_SUCCESS);

		case 'x': /* Handled in first pass. */
			break;

		case 'X':
			fr_debug_lvl = rad_debug_lvl = dpc_debug_lvl;
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

			case LONGOPT_IDX_RETRANSMIT: // --retransmit
				if (!is_integer(optarg)) ERROR_LONGOPT_VALUE("integer");
				CONF.retransmit_max = atoi(optarg);
				break;

			case LONGOPT_IDX_XLAT_FILE: // --xlat-file
				if (ncc_xlat_file_add(optarg) != 0) {
					exit(EXIT_FAILURE);
				}
				break;

			default:
				printf("Error: Unexpected 'option index': %d\n", opt_index);
				usage(1);
				break;
			}
			break;

		default:
			usage(1);
			break;
		}
	}
	argc -= (optind - 1);
	argv += (optind - 1);

	/* Configure talloc debugging features. */
	if (ECTX.talloc_memory_report) {
		talloc_enable_null_tracking();
	} else {
		talloc_disable_null_tracking();
	}

	/*
	 *	Initialize configuration elements that can be set through command-line options.
	 *	Note: Those may later be overriden with values read from configuration files.
	 */
	dpc_config->debug_level = dpc_debug_lvl;
	dpc_config->debug_dev = (with_debug_dev == 1);

	ncc_log_init(stdout, dpc_debug_lvl); /* Update with actual options. */
	ncc_default_log.line_number = dpc_config->debug_dev;

	/*
	 *	Resolve server host address and port.
	 */
	if (argc - 1 >= 1 && strcmp(argv[1], "-") != 0) {
		ncc_host_addr_resolve(&server_ep, argv[1]);
	}

	/*
	 *	See what kind of request we want to send.
	 */
	if (argc - 1 >= 2) {
		if (dpc_command_parse(argv[2]) != 0) {
			ERROR("Unrecognised command \"%s\"", argv[2]);
			usage(1);
		}
	}

	if (ECTX.session_max_active == 0) ECTX.session_max_active = 1;
	ECTX.ftd_progress_interval = ncc_float_to_fr_time(ECTX.progress_interval);

	/* Xlat is automatically enabled in template mode. */
	if (with_template) with_xlat = 1;

	if (!with_template && ECTX.input_num_use == 0) ECTX.input_num_use = 1;
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
		start_sessions_flag = false;
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

	/* If we're producing progress statistics, do it one last time. */
	if (ECTX.ftd_progress_interval) dpc_progress_stats_fprint(stdout, true);

	/* Statistics report. */
	dpc_stats_fprint(stdout);
	dpc_tr_stats_fprint(stdout);

	/* Free memory. */
	ncc_xlat_free();
	ncc_xlat_core_free();

	fr_dhcpv4_global_free();
	// not working !? stuff allocated when calling fr_dhcpv4_global_init is not freed.
	fr_dict_autofree(dpc_dict_autoload);

	fr_dict_free(&fr_dict_internal); /* Loaded by fr_dict_autoload, but not freed by fr_dict_autofree. */
	// (maybe temporary - FreeRADIUS might fix this in the future)
	//fr_dict_free(&dict_dhcpv4); // <- nope. :'(

	fr_strerror_free();
	TALLOC_FREE(pl);
	TALLOC_FREE(event_list);
	TALLOC_FREE(global_ctx);

	/*
	 * Anything not cleaned up by the above is allocated in
	 * the NULL top level context, and is likely leaked memory.
	 */
	if (ECTX.talloc_memory_report) {
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

	/* FreeRADIUS libraries debug (defined in src/lib/util/log.c).
	 * We have our own logging functions so this should be unused.
	 */
	fr_debug_lvl = 0;

	/* FreeRADIUS global debug (defined in src/lib/server/log.c).
	 * Used (among other things) by the config parser (cf. "DEBUG_ENABLED").
	 */
	rad_debug_lvl = 0;

	dpc_debug_lvl = 0; /* Our own debug. */
	fr_log_fp = stdout; /* Everything will go there. */

	global_ctx = talloc_autofree_context();

	fr_time_start();

	fte_start = fr_time(); /* Program start timestamp. */

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

	/* Parse the command line options. */
	dpc_options_parse(argc, argv);

	/*
	 *	Mismatch between the binary and the libraries it depends on.
	 */
	DEBUG2("FreeRADIUS magic number: %016lx", RADIUSD_MAGIC_NUMBER);
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
	 *	Read the configuration file (if provided), and parse configuration.
	 */
	if (dpc_config_init(dpc_config, file_config) < 0) exit(EXIT_FAILURE);

	dpc_config_debug(dpc_config);

	if (CONF.retransmit_max > 0) {
		retr_breakdown = talloc_zero_array(global_ctx, uint32_t, CONF.retransmit_max);
	}
	ECTX.ftd_request_timeout = ncc_float_to_fr_time(CONF.request_timeout);

	dpc_event_list_init(global_ctx);
	dpc_packet_list_init(global_ctx);

	/*
	 *	Allocate sockets for gateways.
	 */
	if (gateway_list) {
		for (i = 0; i < gateway_list->num; i++) {
			ncc_endpoint_t *this = &gateway_list->eps[i];

			if (dpc_socket_provide(pl, &this->ipaddr, this->port) < 0) {
				char src_ipaddr_buf[FR_IPADDR_STRLEN] = "";
				PERROR("Failed to provide a suitable socket for gateway \"%s:%u\"",
				       fr_inet_ntop(src_ipaddr_buf, sizeof(src_ipaddr_buf), &this->ipaddr) ? src_ipaddr_buf : "(undef)",
				       this->port);
				exit(EXIT_FAILURE);
			}
		}
	}

	/*
	 *	And a pcap raw socket (if we need one).
	 */
#ifdef HAVE_LIBPCAP
	if (iface) {
		dpc_pcap_init(global_ctx);
	}
#endif

	/*
	 *	Set signal handler.
	 */
	if ( (fr_set_signal(SIGHUP, dpc_signal) < 0) ||
	     (fr_set_signal(SIGINT, dpc_signal) < 0) ||
	     (fr_set_signal(SIGTERM, dpc_signal) < 0))
	{
		PERROR("Failed to install signal handler");
		exit(EXIT_FAILURE);
	}

	/* Load input data used to build the packets. */
	if (dpc_input_load(global_ctx) < 0) {
		exit(EXIT_FAILURE);
	}

	/*
	 *	Ensure we have something to work with.
	 */
	if (input_list.size == 0) {
		if (!with_stdin_input && argc < 2) usage(0); /* If no input nor arguments, show usage. */

		WARN("No valid input loaded, nothing to do");
		exit(0);
	}

	/*
	 *	If packet trace level is unspecified, figure out something automatically.
	 */
	if (packet_trace_lvl == -1) {
		if (ECTX.session_max_num == 1 || (!with_template && input_list.size == 1 && ECTX.input_num_use == 1)) {
			/* Only one request: full packet print. */
			packet_trace_lvl = 2;
		} else if (ECTX.session_max_active == 1) {
			/*
			 *	Several requests, but no parallelism.
			 *	If the number of sessions and the max duration are reasonably small, print packets header.
			 *	Otherwise: no packet print.
			 */
			if (ECTX.session_max_num > 50 || ECTX.duration_start_max > 1.0) {
				packet_trace_lvl = 0;
			} else {
				packet_trace_lvl = 1;
			}
		} else {
			/* Several request in parallel: no packet print. */
			packet_trace_lvl = 0;
		}
		DEBUG_TRACE("Packet trace level set to: %d", packet_trace_lvl);
	}

#ifdef HAVE_LIBPCAP
	if (iface) {
		/*
		 *	Now that we've opened all the sockets we need, build the pcap filter.
		 */
		dpc_pcap_filter_build(pl, pcap);
	}
#endif

	fte_job_start = fr_time(); /* Job start timestamp. */

	if (ECTX.duration_start_max) { /* Set timestamp limit for starting new input sessions. */
		ECTX.fte_start_max = ncc_float_to_fr_time(ECTX.duration_start_max) + fte_job_start;
	}

	/* Arm a timer to produce periodic statistics. */
	dpc_event_add_progress_stats();

	/* Execute the main processing loop. */
	dpc_main_loop();

	/* This is the end. */
	dpc_end();
}

/*
 *	Print program version.
 */
static void version_print(void)
{
	printf("%s: %s\n", progname, prog_version);
	printf("Built with libpcap: %s\n",
#ifdef HAVE_LIBPCAP
		"yes"
#else
		"no"
#endif
	);
}

/*
 *	Display the syntax for starting this program.
 */
static void NEVER_RETURNS usage(int status)
{
	FILE *fp = status ? stderr : stdout;

	fprintf(fp, "Usage: %s [options] [<server>[:<port>] [<command>]]\n", progname);
	fprintf(fp, "  <server>:<port>  The DHCP server. If omitted, it must be specified in input items.\n");
	fprintf(fp, "  <command>        One of (message type): discover, request, decline, release, inform, lease_query.\n");
	fprintf(fp, "                   (or the message type numeric value: 1 = Discover, 2 = Request, ...).\n");
	fprintf(fp, "                   Or (workflow): dora, doradec (DORA / Decline), dorarel (DORA / Release).\n");
	fprintf(fp, "                   If omitted, message type must be specified in input items.\n");
	fprintf(fp, " Options:\n");
	fprintf(fp, "  -a <ipaddr>      Authorized server. Only allow replies from this server.\n");
#ifdef HAVE_LIBPCAP
	fprintf(fp, "  -A               Wait for multiple Offer replies to a broadcast Discover (requires option -i).\n");
#endif
	fprintf(fp, "  -c <num>         Use each input item up to <num> times.\n");
	fprintf(fp, "  -C <file>        Read configuration from <file>.\n");
	fprintf(fp, "  -D <dictdir>     Dictionaries main directory (default: directory share/freeradius/dictionary of FreeRADIUS installation).\n");
	fprintf(fp, "  -f <file>        Read input items from <file>, in addition to stdin.\n");
	fprintf(fp, "  -g <gw>[:port]   Handle sent packets as if relayed through giaddr <gw> (hops: 1, src: giaddr:port).\n");
	fprintf(fp, "                   A comma-separated list may be specified, in which case packets will be sent using all\n");
	fprintf(fp, "                   of those gateways in a round-robin fashion.\n");
	fprintf(fp, "  -h               Print this help message.\n");
#ifdef HAVE_LIBPCAP
	fprintf(fp, "  -i <interface>   Use this interface for unconfigured clients to broadcast through a raw socket.\n");
#endif
	fprintf(fp, "  -I <num>         Start generating xid values with <num>.\n");
	fprintf(fp, "  -L <seconds>     Limit duration for starting new input sessions.\n");
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
	fprintf(fp, "\n");

	exit(status);
}
