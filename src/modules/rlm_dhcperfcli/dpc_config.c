/**
 * @file dpc_config.c
 * @brief Handle the program configuration (reuse from FreeRADIUS main_config.c)
 */

#include "dhcperfcli.h"
#include "dpc_config.h"
#include "dpc_time_data.h"

#define MAX_ATTR_INPUT 128

static int dpc_input_list_parse_section(CONF_SECTION *section, fn_input_handle_t fn_input_handle);
static int dpc_segment_handle(TALLOC_CTX *ctx, CONF_SECTION *cs, dpc_segment_config_t *segment_config, ncc_dlist_t *segments);
static int dpc_segment_sections_parse(TALLOC_CTX *ctx, CONF_SECTION *section, ncc_dlist_t *segments);


/* Allowed values for packet trace level
 */
fr_table_num_ordered_t const dpc_packet_trace_table[] = {
	{ "auto",    -1 },
	{ "none",    0  },
	{ "digest",  1  },
	{ "pairs",   2  },
	{ "data",    3  },
};
size_t dpc_packet_trace_table_len = NUM_ELEMENTS(dpc_packet_trace_table);

/* Progress statistics destination
 */
fr_table_num_ordered_t const dpc_progress_stat_dst_table[] = {
	{ "stdout", PR_STAT_DST_STDOUT },
	{ "file",   PR_STAT_DST_FILE },
};
size_t dpc_progress_stat_dst_table_len = NUM_ELEMENTS(dpc_progress_stat_dst_table);


/* Notes:
 *
 * - Some parameters may be defined through command-line options and configuration files.
 *   For these parameters, do *not* provide a default ("dflt") to the configuration parser.
 *   A value will be set by the config parser only if the parameter is explicitly defined in configuration files.
 *   If a parameter is provided both through command-line and configuration file, the latter takes precedence.
 *
 * - Type 'uint32' is restricted to values 0-INT32_MAX (not 0-UINT32_MAX).
 *   Cf. function cf_pair_parse_value (cf_parse.c) for rationale.
 *
 * - Type 'string' with no configuration and no default ("dflt") will result in a NULL pointer,
 *   even if we had a value in target variable (pointer set to NULL by cf_section_parse_init).
 *
 * - Prefer FR_TYPE_STRING rather than FR_TYPE_FILE_INPUT (we don't want all the checks that FreeRADIUS do with it).
 *
 * Not all types are supported by FreeRADIUS parser (cf. FR_CONF_OFFSET -> FR_CONF_TYPE_CHECK in cf_parse.h)
 * The following do not work (compiler "error: void value not ignored as it ought to be"):
 * FR_TYPE_INT8, FR_TYPE_INT16, FR_TYPE_INT64, any enum type.
 *
 * To bypass the compile-time checks, use NCC_CONF_OFFSET (which is FR_CONF_OFFSET without the type checks).
 * In addition, the default parsing function cannot be used. Instead use ".func = ncc_conf_item_parse".
 */

static CONF_PARSER segment_conf_parser[] = {
	{ NCC_CONF_OFFSET("type", NCC_TYPE_ENUM, dpc_segment_config_t, type), .dflt = "fixed",
		.func = ncc_conf_item_parse, PARSE_CTX_SEGMENT_TYPE },
	{ FR_CONF_OFFSET("start", FR_TYPE_FLOAT64, dpc_segment_config_t, start), .dflt = "0", FLOAT64_NOT_NEGATIVE },
	{ FR_CONF_OFFSET("end", FR_TYPE_FLOAT64, dpc_segment_config_t, end), .dflt = "0", FLOAT64_NOT_NEGATIVE },
	{ FR_CONF_OFFSET("rate", FR_TYPE_FLOAT64, dpc_segment_config_t, rate), .dflt = "0", FLOAT64_NOT_NEGATIVE },
	{ FR_CONF_OFFSET("rate_start", FR_TYPE_FLOAT64, dpc_segment_config_t, rate_start), .dflt = "0", FLOAT64_NOT_NEGATIVE },
	{ FR_CONF_OFFSET("rate_end", FR_TYPE_FLOAT64, dpc_segment_config_t, rate_end), .dflt = "0", FLOAT64_NOT_NEGATIVE },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER log_conf_parser[] = {
	{ NCC_CONF_OFFSET("destination", NCC_TYPE_ENUM, dpc_config_t, log_dst), .dflt = "stdout",
		.func = ncc_conf_item_parse, .uctx = PARSE_CTX_LOG_DESTINATION },
	{ FR_CONF_OFFSET("file", FR_TYPE_STRING, dpc_config_t, log_file) },
	{ FR_CONF_OFFSET("debug_level", FR_TYPE_INT32, dpc_config_t, debug_level), /* No default */
		.func = ncc_conf_item_parse },
	{ FR_CONF_OFFSET("debug_dev", FR_TYPE_BOOL, dpc_config_t, debug_dev) }, /* No default */
	{ FR_CONF_OFFSET("debug_basename", FR_TYPE_BOOL, dpc_config_t, debug_basename), .dflt = "yes" },
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, dpc_config_t, log_timestamp), .dflt = "yes" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER packet_trace_conf_parser[] = {
	{ FR_CONF_OFFSET("level", FR_TYPE_INT32, dpc_config_t, packet_trace_lvl), /* No default */
		.func = ncc_conf_item_parse, PARSE_CTX_PACKET_TRACE_LEVEL },
	{ FR_CONF_OFFSET("elapsed", FR_TYPE_BOOL, dpc_config_t, packet_trace_elapsed), .dflt = "no" },
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, dpc_config_t, packet_trace_timestamp), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER progress_conf_parser[] = {
	{ FR_CONF_OFFSET("interval", FR_TYPE_FLOAT64, dpc_config_t, progress_interval), /* No default */
		.func = ncc_conf_item_parse, .uctx = PARSE_CTX_PROGRESS_INTERVAL },
	{ NCC_CONF_OFFSET("destination", NCC_TYPE_ENUM, dpc_config_t, pr_stat_dst), .dflt = "stdout",
		.func = ncc_conf_item_parse, .uctx = PARSE_CTX_PROGRESS_DESTINATION },
	{ FR_CONF_OFFSET("file", FR_TYPE_STRING, dpc_config_t, pr_stat_file) },
	{ FR_CONF_OFFSET("file_rewrite", FR_TYPE_BOOL, dpc_config_t, pr_stat_file_rewrite), .dflt = "no" },
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, dpc_config_t, pr_stat_timestamp), .dflt = "yes" },
	{ FR_CONF_OFFSET("per_input", FR_TYPE_BOOL, dpc_config_t, pr_stat_per_input), .dflt = "yes" },
	{ FR_CONF_OFFSET("per_input_digest", FR_TYPE_BOOL, dpc_config_t, pr_stat_per_input_digest), .dflt = "no" },
	{ FR_CONF_OFFSET("per_input_max", FR_TYPE_UINT32, dpc_config_t, pr_stat_per_input_max), .dflt = "0",
		.func = ncc_conf_item_parse },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER transport_conf_parser[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_FLOAT64, dpc_config_t, request_timeout), /* No default */
		.func = ncc_conf_item_parse, .uctx = PARSE_CTX_REQUEST_TIMEOUT },
	{ FR_CONF_OFFSET("retransmit", FR_TYPE_UINT32, dpc_config_t, retransmit_max), /* No default */
		.func = ncc_conf_item_parse },
	{ FR_CONF_OFFSET("interface", FR_TYPE_STRING, dpc_config_t, interface) }, /* No default */

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER load_conf_parser[] = {
	{ FR_CONF_OFFSET("rate_limit", FR_TYPE_FLOAT64, dpc_config_t, rate_limit), /* No default */
		FLOAT64_NOT_NEGATIVE },
	{ FR_CONF_OFFSET("input_rate_limit", FR_TYPE_FLOAT64, dpc_config_t, input_rate_limit), /* No default */
		FLOAT64_NOT_NEGATIVE },
	{ FR_CONF_OFFSET("duration_start_max", FR_TYPE_FLOAT64, dpc_config_t, duration_start_max), /* No default */
		FLOAT64_NOT_NEGATIVE },
	{ FR_CONF_OFFSET("input_num_use", FR_TYPE_UINT32, dpc_config_t, input_num_use), /* No default */
		.func = ncc_conf_item_parse },
	{ FR_CONF_OFFSET("session_max_num", FR_TYPE_UINT32, dpc_config_t, session_max_num), /* No default */
		.func = ncc_conf_item_parse },
	{ FR_CONF_OFFSET("session_max_active", FR_TYPE_UINT32, dpc_config_t, session_max_active), /* No default */
		.func = ncc_conf_item_parse, .uctx = PARSE_CTX_SESSION_MAX_ACTIVE },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER dhcperfcli_conf_parser[] = {
	{ FR_CONF_OFFSET("template", FR_TYPE_BOOL, dpc_config_t, template) }, /* No default */
	{ FR_CONF_OFFSET("xlat", FR_TYPE_BOOL, dpc_config_t, xlat) }, /* No default */
	{ FR_CONF_OFFSET("xlat_file", FR_TYPE_STRING | FR_TYPE_MULTI | FR_TYPE_SECRET, dpc_config_t, xlat_files) },

	{ FR_CONF_OFFSET("input_file", FR_TYPE_STRING | FR_TYPE_MULTI, dpc_config_t, input_files) },
	{ FR_CONF_OFFSET("ignore_invalid_input", FR_TYPE_BOOL, dpc_config_t, ignore_invalid_input), .dflt = "yes" },

	{ NCC_CONF_OFFSET("base_xid", FR_TYPE_INT64, dpc_config_t, base_xid), /* No default */
		.func = ncc_conf_item_parse, .uctx = PARSE_CTX_BASE_XID },
	{ FR_CONF_OFFSET("gateway", FR_TYPE_STRING | FR_TYPE_MULTI, dpc_config_t, gateways) },
	{ FR_CONF_OFFSET("listen", FR_TYPE_STRING | FR_TYPE_MULTI, dpc_config_t, listen_addrs) },
	{ FR_CONF_OFFSET("authorized_server", FR_TYPE_IPV4_ADDR | FR_TYPE_MULTI, dpc_config_t, authorized_servers) },

	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) log_conf_parser },
	{ FR_CONF_POINTER("packet_trace", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) packet_trace_conf_parser },
	{ FR_CONF_POINTER("progress", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) progress_conf_parser },
	{ FR_CONF_POINTER("transport", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) transport_conf_parser },
	{ FR_CONF_POINTER("load", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) load_conf_parser },

	CONF_PARSER_TERMINATOR
};


/**
 * Parse all "input" sections within a configuration section.
 * These may contains directly a list of vps, or "pairs" sub-section(s).
 * In which case, "input" can also contain "segment" sub-sections.
 */
static int dpc_input_list_parse_section(CONF_SECTION *section, fn_input_handle_t fn_input_handle)
{
	CONF_SECTION *cs = NULL, *subcs;
	dpc_input_t *input;
	int cs_depth_base = 1;

	/* Iterate over all the "input" sections.
	 */
	while ((cs = cf_section_find_next(section, cs, "input", CF_IDENT_ANY))) {

		MEM(input = talloc_zero(section, dpc_input_t));

		/* Look for a "pairs" sub-section. If found, get the list of vps from this sub-section.
		 * Otherwise, consider "input" as the list of vps.
		 */
		subcs = cf_section_find_next(cs, NULL, "pairs", CF_IDENT_ANY);
		if (!subcs) {
			/*
			 * "input" section contains the list of vps.
			 */
			if (ncc_pair_list_afrom_cs(input, dict_dhcpv4, &input->vps,
			                           cs, cs_depth_base, MAX_ATTR_INPUT) != 0) {
			error:
				talloc_free(input);
				return -1;
			}

		} else {
			/*
			 * Parse "pairs" sub-sections and aggregate all vps.
			 */
			ncc_cs_debug_start(cs, cs_depth_base);

			while (subcs) {
				if (ncc_pair_list_afrom_cs(input, dict_dhcpv4, &input->vps,
				                           subcs, cs_depth_base + 1, MAX_ATTR_INPUT) != 0) goto error;

				subcs = cf_section_find_next(section, subcs, "pairs", CF_IDENT_ANY);
			}

			/* If we have a "pairs" sub-section, then we may also have "segment" sub-sections.
			 * Note: segments list is allocated even if there are no segments.
			 */
			if (!CONF.template) {
				/*
				 * Input segments are not allowed in non template mode.
			 	 */
				if (cf_section_find_next(cs, NULL, "segment", CF_IDENT_ANY)) {
					cf_log_warn(cs, "Input segments are not allowed in non template mode");
				}
			} else {
				input->segments = talloc_zero(input, ncc_dlist_t);
				if (dpc_segment_sections_parse(input, cs, input->segments) != 0) goto error;
			}

			ncc_cs_debug_end(cs, cs_depth_base);
		}

		/* Copy the input name if one is defined.
	 	 */
		char const *name = cf_section_name2(cs);
		if (name) {
			input->name = talloc_strdup(input, name);
		}

		if (fn_input_handle) (*fn_input_handle)(input, &input_list);
	}

	return 0;
}

/**
 * Handle a time segment read from configuration. Add it to the provided list.
 */
static int dpc_segment_handle(TALLOC_CTX *ctx, CONF_SECTION *cs, dpc_segment_config_t *segment_config, ncc_dlist_t *segments)
{
	ncc_segment_t *segment = NULL;
	fr_time_delta_t ftd_start, ftd_end;

	ftd_start = ncc_float_to_fr_time(segment_config->start);
	ftd_end = ncc_float_to_fr_time(segment_config->end);

	segment = ncc_segment_add(ctx, segments, ftd_start, ftd_end);
	if (!segment) {
		cf_log_perr(cs, "Failed to add segment");
		return -1;
	}

	segment->type = segment_config->type;
	switch (segment->type) {
	case NCC_SEGMENT_RATE_FIXED:
		segment->rate_limit = segment_config->rate;
		break;

	case NCC_SEGMENT_RATE_LINEAR:
		/* A linear rate can only be enforced if we know when the segment will end.
	 	 */
		if (!segment->ftd_end) {
			cf_log_err(cs, "Segment of type \"%s\" must have a finite end",
			           fr_table_str_by_value(segment_types, segment->type, "???"));
			goto error;
		}
		segment->rate_limit_range.start = segment_config->rate_start;
		segment->rate_limit_range.end = segment_config->rate_end;
		break;

	default:
		break;
	}

	/* Copy the segment name if one is defined.
	 */
	if (segment_config->name) {
		segment->name = talloc_strdup(ctx, segment_config->name);
	}

	return 0;

error:
	talloc_free(segment);
	return -1;
}

/**
 * Parse all "segment" sections within a configuration section.
 * Add each segment to the provided list.
 */
static int dpc_segment_sections_parse(TALLOC_CTX *ctx, CONF_SECTION *section, ncc_dlist_t *segments)
{
	dpc_segment_config_t segment_config;
	CONF_SECTION *cs = NULL;

	while ((cs = cf_section_find_next(section, cs, "segment", CF_IDENT_ANY))) {

		/* Parse this segment sub-section.
		 */
		if (cf_section_rules_push(cs, segment_conf_parser) < 0) goto error;
		if (cf_section_parse(ctx, &segment_config, cs) < 0) goto error;

		segment_config.name = cf_section_name2(cs);

		/* Add the segment to the list.
		 */
		if (dpc_segment_handle(ctx, cs, &segment_config, segments) < 0) goto error;
	}

	return 0;

error:
	return -1;
}

/**
 * Set the program instance name.
 * Cf. FreeRADIUS function main_config_dict_dir_set (src/lib/server/main_config.c)
 */
void dpc_config_name_set_default(dpc_config_t *config, char const *name, bool overwrite_config)
{
	if (config->name) {
		talloc_const_free(config->name);
		config->name = NULL;
	}
	if (name) config->name = talloc_typed_strdup(config, name);

	config->overwrite_config_name = overwrite_config;
}

/**
 * Set the global dictionary directory.
 */
void dpc_config_dict_dir_set(dpc_config_t *config, char const *value)
{
	if (config->dict_dir) {
		talloc_const_free(config->dict_dir);
		config->dict_dir = NULL;
	}
	if (value) config->dict_dir = talloc_typed_strdup(config, value);
}

/**
 * Allocate a dpc_config_t struct, setting defaults
 */
dpc_config_t *dpc_config_alloc(TALLOC_CTX *ctx, dpc_config_t *default_config)
{
	dpc_config_t *config;

	config = talloc_zero(ctx, dpc_config_t);
	if (!config) return NULL;

	/* Set default configuration values. */
	if (default_config) *config = *default_config;

	dpc_config_dict_dir_set(config, DICTDIR);

	return config;
}

/**
 * Read the configuration file (if provided).
 * Parse the configuration (even without a file: this allows to set the default values).
 */
int dpc_config_init(dpc_config_t *config)
{
	CONF_SECTION *cs = NULL;
	char const *conf_file = config->config_file;

	cs = cf_section_alloc(NULL, NULL, "main", NULL);
	if (!cs) return -1;

	char *tmp_file = NULL;
	char template[] = "./dhcperfcli.conf.tmp_XXXXXX"; /* must end with "XXXXXX". */

	if (config->conf_inline) {
		/* Create a temporary configuration file so FreeRADIUS can read from it.
		 * It is created in current directory so that include works with relative path.
		 *
		 * Note: "If mktemp cannot find a unique file name, it makes template an empty string and returns that."
		 */
		tmp_file = mktemp(template);
		if (!tmp_file || tmp_file[0] == '\0') {
			ERROR("Failed to generate temporary file name");
			goto error;
		}
		// Note: mktemp is considered unsafe because generating the name and opening the file is not atomic.
		// Should use mkstemp, however it seems to mess with threads writing to stdout for some reason...
		// TODO.

		FILE *fp_tmp = fopen(tmp_file, "w");
		if (!fp_tmp) {
			ERROR("Failed to open temporary file \"%s\": %s", tmp_file, fr_syserror(errno));
			goto error;
		}

		/* Write inline configuration entries. */
		int i;
		for (i = 0; i < talloc_array_length(config->conf_inline); i++) {
			fprintf(fp_tmp, "%s\n", config->conf_inline[i]);
		}

		/* If a configuration file is provided, include it. */
		if (conf_file) {
			fprintf(fp_tmp, "\n$INCLUDE %s\n", conf_file);
		}
		fclose(fp_tmp);

		conf_file = tmp_file;
	}

	/* Read the configuration file (if provided) */
	if (conf_file && cf_file_read(cs, conf_file) < 0) {
		/* Note: FreeRADIUS cf_* functions directly call "ERROR", so we have nothing to pop from the error stack. */
		ERROR("Failed to read configuration file \"%s\"", conf_file);
		goto error;
	}

	/* Backup initial configuration before parsing. */
	dpc_config_t old_config = *config;

	if (cf_section_rules_push(cs, dhcperfcli_conf_parser) < 0) goto error;

	/*
	 * Parse configuration.
	 *
	 * Note: pre-existing talloc arrays (used to store multi-valued items) in target struct are not freed.
	 * They are just replaced. Thus the back-up in "old_config" remains valid, and safe to use.
	 *
	 * Pre-existing single-valued strings in target struct are not freed either.
	 * It would seem (looking at cf_pair_parse_value) that they should be.
	 * But cf_section_parse_init is called before that, which sets the pointer to NULL.
	 * Thus the back-up in "old_config" remains valid also for these.
	 */
	if (cf_section_parse(config, config, cs) < 0) goto error;

	/* Merge current and old configuration.
	 * Restore strings for which we didn't parse anything, and merge multi-valued strings.
	 */
	ncc_config_merge(dhcperfcli_conf_parser, config, &old_config);

	/* Debug level (overriden by command-line option -x). */
	if (dpc_debug_lvl == 0) dpc_debug_lvl = config->debug_level;

	ncc_log_init(stdout, dpc_debug_lvl); /* Update with file configuration. */
	ncc_default_log.timestamp = config->log_timestamp ? L_TIMESTAMP_ON : L_TIMESTAMP_OFF;
	ncc_default_log.line_number = config->debug_dev;
	ncc_default_log.basename = config->debug_basename;

	/* Log destination. */
	if (config->log_dst == LOG_DST_FILE) {
		if (!config->log_file || config->log_file[0] == '\0') {
			ERROR("No file provided for log \"file\" destination");
			goto error;
		}
		if (ncc_log_open_file(config->log_file) < 0) goto error;
	}

	/* Progress statistics destination. */
	if (config->pr_stat_dst == PR_STAT_DST_FILE) {
		if (!config->pr_stat_file || config->pr_stat_file[0] == '\0') {
			ERROR("No file provided for progress \"file\" destination");
			goto error;
		}
		config->pr_stat_fp = fopen(config->pr_stat_file, "w");
		if (!config->pr_stat_fp) {
			ERROR("Failed to open progress statistics file \"%s\": %s", config->pr_stat_file, fr_syserror(errno));
			goto error;
		}
	} else {
		config->pr_stat_fp = stdout;
	}

	config->root_cs = cs;

	fr_strerror(); /* Clear the error buffer */

	if (tmp_file && unlink(tmp_file) < 0) {
		ERROR("Failed to remove temporary file \"%s\": %s", tmp_file, fr_syserror(errno));
	}
	return 0;

error:
	talloc_free(cs);
	if (tmp_file && unlink(tmp_file) < 0) {
		ERROR("Failed to remove temporary file \"%s\": %s", tmp_file, fr_syserror(errno));
	}
	return -1;
}

/**
 * Free the configuration. Called only when exiting.
 */
void dpc_config_free(dpc_config_t **config)
{
	if (!config || !*config) return;

	TALLOC_FREE((*config)->root_cs);
	TALLOC_FREE(*config);
}

/**
 * Load configured 'input' sections.
 */
int dpc_config_load_input(dpc_config_t *config, fn_input_handle_t fn_input_handle)
{
	CONF_SECTION *cs = config->root_cs;

	DEBUG2("%s: #### Parsing 'input' sections ####", config->name);
	if (dpc_input_list_parse_section(cs, fn_input_handle) != 0) {
		ERROR("Failed to load 'input' sections from configuration file");
		return -1;
	}

	return 0;
}

/**
 * Load configured 'segment' sections.
 */
int dpc_config_load_segments(dpc_config_t *config, ncc_dlist_t *segment_list)
{
	CONF_SECTION *cs = config->root_cs;

	DEBUG2("%s: #### Parsing 'segment' sections ####", config->name);
	if (dpc_segment_sections_parse(cs, cs, segment_list) != 0) {
		ERROR("Failed to load 'segment' sections from configuration file");
		return -1;
	}

	return 0;
}

/**
 * Debug the configuration.
 */
void dpc_config_debug(dpc_config_t *config)
{
	int depth = 0;

	ncc_section_debug_start(depth, "dhcperfcli", "config");

	ncc_parser_config_debug(dhcperfcli_conf_parser, config, depth + 1, config->check_config ? "" : NULL);
	dpc_timedata_config_debug(config, depth + 1);

	ncc_section_debug_end(depth);
}
