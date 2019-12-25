#pragma once
/*
 * dpc_config.h
 */

typedef struct dpc_config_s dpc_config_t;

extern dpc_config_t *dpc_config; //!< Global configuration singleton.
#define CONF (*dpc_config)


extern fr_table_num_ordered_t const dpc_packet_trace_table[];
extern size_t dpc_packet_trace_table_len;


typedef enum {
	PR_STAT_DST_STDOUT = 1, //!< Write to stdout.
	PR_STAT_DST_FILE,       //!< Write to a file on disk.
} dpc_progress_stat_dst_t;

/*
 *	Main configuration
 */
struct dpc_config_s {
	char const *name;            //!< Name of the daemon.
	bool overwrite_config_name;  //!< Overwrite the configured name, as this
	                             ///< was specified by the user on the command line.
	CONF_SECTION *root_cs;       //!< Root of the main config.

	char const *log_destination;     //<! Log destination type (string).
	int debug_level;                 //!< The base debug level.
	bool debug_dev;                  //!< Enable extended debug information for developper.
	bool debug_basename;             //!< Print only file base name.
	bool log_timestamp;              //!< Add timestamp to log messages.

	double progress_interval;        //<! Time interval between periodic progress statistics.
	fr_time_delta_t ftd_progress_interval;
	char const *pr_stat_destination; //<! Progress statistics destination type (string).
	dpc_progress_stat_dst_t pr_stat_dst;
	char const *pr_stat_file;        //<! Progress statistics file name (for "file" destination).
	bool pr_stat_file_rewrite;       //<! Rewrite file contents with the latest data (instead of appending).
	FILE *pr_stat_fp;
	bool pr_stat_timestamp;          //!< Add timestamp to progress statistics.
	bool pr_stat_per_input;          //<! Print per-input progress statistics (if multiple input).
	bool pr_stat_per_input_digest;   //<! Print the per-input progress statistics condensed on a single line.
	uint32_t pr_stat_per_input_max;  //<! Max number of input items shown in progress statistics.

	bool template;                   //<! Template mode.
	bool xlat;                       //<! Xlat enabled on input items.
	char const **input_files;        //<! Files from which input items are read.
	char const **xlat_files;         //<! Files containing values for xlat "file" expansions.
	uint64_t base_xid;               //<! Base value for xid generated in DHCP packets.
	// Note: This is really a uint32_t, but the config parser requires a uint64_t.
	bool ignore_invalid_input;       //<! Ignore invalid input (discard), or exit in error.

	char const *interface;           //<! Interface used for unconfigured clients to broadcast through a raw socket.
	char const **gateways;           //<! Gateways simulated for sending DHCP packets.
	fr_ipaddr_t *authorized_servers; //<! Only allow replies from explicitly authorized servers.

	int32_t packet_trace_lvl;        //<! Packet trace level (0: none, 1: header, 2: and attributes, 3: and encoded hex data).
	bool packet_trace_elapsed;       //<! Prefix packet trace with elapsed time.
	bool packet_trace_timestamp;     //<! Prefix packet trace with current timestamp.
	double request_timeout;          //<! Max time waiting for a reply to a request we've sent.
	fr_time_delta_t ftd_request_timeout;
	uint32_t retransmit_max;         //<! Max retransmissions of a request not replied to (not including first packet).

	double rate_limit;               //<! Limit rate/s of sessions initialized from input (global - all transactions combined).
	double input_rate_limit;         //<! Limit rate/s of sessions initialized from each input item.
	double duration_start_max;       //<! Limit duration for starting new input sessions.
	fr_time_t fte_start_max;         //<! Time after which no input session is allowed to be started.
	uint32_t input_num_use;          //<! Max number of uses of each input item (default: unlimited in template mode, 1 otherwise).
	uint32_t session_max_num;        //<! Limit number of sessions initialized from input items.
	uint32_t session_max_active;     //<! Max number of session packets sent concurrently (default: 1).

	bool with_timedata;              //<! Whether time-data statistics are enabled.
	bool talloc_memory_report;       //!< On exit, print a memory report on what's left unfreed.

	double min_time_for_rps;          //<! Min elapsed time to compute a rate per second.
	uint32_t min_session_for_rps;     //<! Min number of sessions started from input to compute a rate per second.
	double rate_limit_min_ref_time;   //<! Min reference time considered for rate limit.
	double rate_limit_time_lookahead; //<! Time lookahead for rate limit enforcement (allows to factor in processing time).
};

/*
 *	Segment configuration
 */
typedef struct {
	char const *name;
	double start;
	double end;
	char const *type;
	double rate;
	double rate_start;
	double rate_end;
} dpc_segment_config_t;

typedef int (*fn_input_handle_t)(dpc_input_t *, ncc_dlist_t *);

void dpc_config_name_set_default(dpc_config_t *config, char const *name, bool overwrite_config);
dpc_config_t *dpc_config_alloc(TALLOC_CTX *ctx);
int dpc_config_init(dpc_config_t *config, char const *conf_file, char const *conf_inline);
void dpc_config_free(dpc_config_t **config);
int dpc_config_load_input(dpc_config_t *config, fn_input_handle_t fn_input_handle);
int dpc_config_load_segments(dpc_config_t *config, ncc_dlist_t *segment_list);
void dpc_config_debug(dpc_config_t *config);


/*
 *	Specific parsing contexts.
 */
#define PARSE_CTX_LOG_DESTINATION &(ncc_parse_ctx_t){ .type = FR_TYPE_STRING, \
		.type_check = NCC_TYPE_CHECK_TABLE, \
		.fr_table = ncc_log_dst_table, .fr_table_len_p = &ncc_log_dst_table_len }

#define PARSE_CTX_PROGRESS_INTERVAL &(ncc_parse_ctx_t){ .type = FR_TYPE_FLOAT64, \
	.type_check = NCC_TYPE_IGNORE_ZERO | NCC_TYPE_NOT_NEGATIVE | NCC_TYPE_FORCE_MIN, ._float.min = 0.1 }

#define PARSE_CTX_PROGRESS_DESTINATION &(ncc_parse_ctx_t){ .type = FR_TYPE_STRING, \
		.type_check = NCC_TYPE_CHECK_TABLE, \
		.fr_table = dpc_progress_stat_dst_table, .fr_table_len_p = &dpc_progress_stat_dst_table_len }

#define PARSE_CTX_REQUEST_TIMEOUT &(ncc_parse_ctx_t){ .type = FR_TYPE_FLOAT64, \
	.type_check = NCC_TYPE_IGNORE_ZERO | NCC_TYPE_NOT_NEGATIVE | NCC_TYPE_FORCE_MIN | NCC_TYPE_FORCE_MAX, \
	._float.min = 0.01, ._float.max = 3600 }

#define PARSE_CTX_BASE_XID &(ncc_parse_ctx_t){ .type = FR_TYPE_UINT64, \
		.type_check = NCC_TYPE_CHECK_MAX, .uinteger.max = 0xffffffff }

#define PARSE_CTX_SESSION_MAX_ACTIVE &(ncc_parse_ctx_t){ .type = FR_TYPE_UINT32, \
		.type_check = NCC_TYPE_CHECK_MIN, .uinteger.min = 1 }

#define PARSE_CTX_PACKET_TRACE_LEVEL &(ncc_parse_ctx_t){ .type = FR_TYPE_INT32, \
		.type_check = NCC_TYPE_CHECK_TABLE, \
		.fr_table = dpc_packet_trace_table, .fr_table_len_p = &dpc_packet_trace_table_len }

#define PARSE_CTX_SEGMENT_TYPE &(ncc_parse_ctx_t){ .type = FR_TYPE_STRING, \
		.type_check = NCC_TYPE_CHECK_TABLE, \
		.fr_table = segment_types, .fr_table_len_p = &segment_types_len }
