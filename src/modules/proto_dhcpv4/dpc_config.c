/**
 * @file dpc_config.c
 * @brief Handle the program configuration (reuse from FreeRADIUS main_config.c)
 */

#include "dhcperfcli.h"
#include "dpc_config.h"

#define MAX_ATTR_INPUT 128

/* Notes:
 *
 * - Some parameters may be defined through command-line options and configuration files.
 *   For these parameters, do *not* provide a default ("dflt") to the configuration parser.
 *   A value will be set by the config parser only if the parameter is explicitly defined in configuration files.
 *
 * - Type 'uint32' is restricted to values 0-INT32_MAX (not 0-UINT32_MAX).
 *   Cf. function cf_pair_parse_value (cf_parse.c) for rationale.
 *   We need real UINT32 values, so we'll be using 'uint64'.
 *
 * - Type 'string' with no configuration and no default ("dflt") will result in a NULL pointer,
 *   even if we had a value in target variable.
 *   Probably because the value pointer dynamically allocated - so we'll have to handle this.
 */

static const CONF_PARSER _log_config[] = {
	{ FR_CONF_OFFSET("debug_level", FR_TYPE_UINT32, dpc_config_t, debug_level) }, /* No default */
	{ FR_CONF_OFFSET("debug_dev", FR_TYPE_BOOL, dpc_config_t, debug_dev) }, /* No default */
	{ FR_CONF_OFFSET("debug_basename", FR_TYPE_BOOL, dpc_config_t, debug_basename), .dflt = "yes" },
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, dpc_config_t, log_timestamp), .dflt = "yes" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER _packet_trace_config[] = {
	{ FR_CONF_OFFSET("level", FR_TYPE_INT32, dpc_config_t, packet_trace_lvl) }, /* No default */
	{ FR_CONF_OFFSET("elapsed", FR_TYPE_BOOL, dpc_config_t, packet_trace_elapsed), .dflt = "no" },
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, dpc_config_t, packet_trace_timestamp), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER _progress_config[] = {
	{ FR_CONF_OFFSET("interval", FR_TYPE_FLOAT64, dpc_config_t, progress_interval) }, /* No default */
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, dpc_config_t, pr_stat_timestamp), .dflt = "yes" },
	{ FR_CONF_OFFSET("per_input", FR_TYPE_BOOL, dpc_config_t, pr_stat_per_input), .dflt = "yes" },
	{ FR_CONF_OFFSET("per_input_digest", FR_TYPE_BOOL, dpc_config_t, pr_stat_per_input_digest), .dflt = "no" },
	{ FR_CONF_OFFSET("per_input_max", FR_TYPE_UINT32, dpc_config_t, pr_stat_per_input_max), .dflt = "0" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER _transport_config[] = {
	{ FR_CONF_OFFSET("timeout", FR_TYPE_FLOAT64, dpc_config_t, request_timeout) }, /* No default */
	{ FR_CONF_OFFSET("retransmit", FR_TYPE_UINT32, dpc_config_t, retransmit_max) }, /* No default */

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER _main_config[] = {
	{ FR_CONF_OFFSET("template", FR_TYPE_BOOL, dpc_config_t, template) }, /* No default */
	{ FR_CONF_OFFSET("xlat", FR_TYPE_BOOL, dpc_config_t, xlat) }, /* No default */
	{ FR_CONF_OFFSET("file_input", FR_TYPE_STRING, dpc_config_t, file_input) },
	// Prefer FR_TYPE_STRING rather than FR_TYPE_FILE_INPUT (we don't want all the checks that FreeRADIUS do with it).
	{ FR_CONF_OFFSET("xlat_file", FR_TYPE_STRING | FR_TYPE_MULTI, dpc_config_t, xlat_files) },
	{ FR_CONF_OFFSET("base_xid", FR_TYPE_UINT64, dpc_config_t, base_xid) }, /* No default */

	{ FR_CONF_OFFSET("gateway", FR_TYPE_STRING | FR_TYPE_MULTI, dpc_config_t, gateways) },

	{ FR_CONF_OFFSET("rate_limit", FR_TYPE_FLOAT64, dpc_config_t, rate_limit) }, /* No default */
	{ FR_CONF_OFFSET("input_rate_limit", FR_TYPE_FLOAT64, dpc_config_t, input_rate_limit), .dflt = "0" },
	{ FR_CONF_OFFSET("duration_start_max", FR_TYPE_FLOAT64, dpc_config_t, duration_start_max) }, /* No default */
	{ FR_CONF_OFFSET("input_num_use", FR_TYPE_UINT32, dpc_config_t, input_num_use) }, /* No default */
	{ FR_CONF_OFFSET("session_max_num", FR_TYPE_UINT32, dpc_config_t, session_max_num) }, /* No default */
	{ FR_CONF_OFFSET("session_max_active", FR_TYPE_UINT32, dpc_config_t, session_max_active) }, /* No default */

	{ FR_CONF_POINTER("log", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) _log_config },
	{ FR_CONF_POINTER("packet_trace", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) _packet_trace_config },
	{ FR_CONF_POINTER("progress", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) _progress_config },
	{ FR_CONF_POINTER("transport", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) _transport_config },

	CONF_PARSER_TERMINATOR
};


/*
 *	Iterates over all input definitions in the specified section, adding them to the list.
 */
int dpc_input_list_parse_section(CONF_SECTION *section, fn_input_handle_t fn_input_handle)
{
	CONF_SECTION *cs = NULL, *subcs;
	dpc_input_t *input;
	int ret;

	/*
	 *	Iterate over all the input definitions in the section, adding them to the list.
	 */
	while ((cs = cf_section_find_next(section, cs, "input", CF_IDENT_ANY))) {

		MEM(input = talloc_zero(section, dpc_input_t));

		/* Look for a "pairs" sub-section. If found, get the list of vps from this sub-section.
		 * Otherwise, consider "input" as the list of vps.
		 */
		subcs = cf_section_find_next(cs, NULL, "pairs", CF_IDENT_ANY);

		ret = ncc_pair_list_afrom_cs(input, dict_dhcpv4, &input->vps, subcs ? subcs : cs, MAX_ATTR_INPUT);
		if (ret != 0) {
			talloc_free(input);
			return -1;
		}

		if (fn_input_handle) (*fn_input_handle)(input, &input_list);
	}
	return 0;
}

/*
 *	Set the server name
 *	Cf. FreeRADIUS function main_config_dict_dir_set (src/lib/server/main_config.c)
 */
void dpc_config_name_set_default(dpc_config_t *config, char const *name, bool overwrite_config)
{
	if (config->name) {
		char *p;

		memcpy(&p, &config->name, sizeof(p));
		talloc_free(p);
		config->name = NULL;
	}
	if (name) config->name = talloc_typed_strdup(config, name);

	config->overwrite_config_name = overwrite_config;
}

/*
 *	Allocate a dpc_config_t struct, setting defaults
 */
dpc_config_t *dpc_config_alloc(TALLOC_CTX *ctx)
{
	dpc_config_t *config;

	config = talloc_zero(ctx, dpc_config_t);
	if (!config) return NULL;

	return config;
}

/*
 *	Read the configuration file (if provided).
 *	Parse the configuration (even without a file: this allows to set the default values).
 */
int dpc_config_init(dpc_config_t *config, char const *conf_file, char const *conf_inline)
{
	CONF_SECTION *cs = NULL;

	cs = cf_section_alloc(NULL, NULL, "main", NULL);
	if (!cs) return -1;

	char *tmp_file = NULL;
	if (conf_inline) {
		/* Create a temporary configuration file so FreeRADIUS can read from it.
		 * It is created in current directory so that include works with relative path.
		 *
		 * Note: "If mktemp cannot find a unique file name, it makes template an empty string and returns that."
		 */
		char template[] = "./dhcperfcli.conf.tmp_XXXXXX"; /* must end with "XXXXXX". */
		tmp_file = mktemp(template);
		if (!tmp_file || tmp_file[0] == '\0') {
			ERROR("Failed to generate temporary file name");
			goto failure;
		}

		FILE *fp_tmp = fopen(tmp_file, "w");
		if (!fp_tmp) {
			ERROR("Failed to open temporary file %s: %s", tmp_file, fr_syserror(errno));
			goto failure;
		}

		/* Write inline configuration. */
		fprintf(fp_tmp, "%s", conf_inline);

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
		ERROR("Failed to read configuration file %s", conf_file);
		goto failure;
	}

	/* Backup initial configuration before parsing. */
	dpc_config_t old_config = *config;

	if (cf_section_rules_push(cs, _main_config) < 0) goto failure;

	/* Parse main configuration. */
	if (cf_section_parse(config, config, cs) < 0) goto failure;

	/* Restore strings for which we didn't parse anything. */
	if (!config->file_input && old_config.file_input) {
		config->file_input = old_config.file_input;
	}

	/* Debug level (overriden by command-line option -x). */
	if (dpc_debug_lvl == 0) dpc_debug_lvl = config->debug_level;

	ncc_log_init(stdout, dpc_debug_lvl); /* Update with file configuration. */
	ncc_default_log.timestamp = config->log_timestamp ? L_TIMESTAMP_ON : L_TIMESTAMP_OFF;
	ncc_default_log.line_number = config->debug_dev;
	ncc_default_log.basename = config->debug_basename;

	config->root_cs = cs;

	fr_strerror(); /* Clear the error buffer */

	if (tmp_file) unlink(tmp_file);
	return 0;

failure:
	talloc_free(cs);
	if (tmp_file) unlink(tmp_file);
	return -1;
}

/*
 * Load configured 'input' sections.
 */
int dpc_config_load_input(dpc_config_t *config, fn_input_handle_t fn_input_handle)
{
	CONF_SECTION *cs = config->root_cs;

	DEBUG2("%s: #### Loading 'input' entries ####", config->name);
	if (dpc_input_list_parse_section(cs, fn_input_handle) != 0) {
		ERROR("Failed to load 'input' entries from configuration file");
		return -1;
	}

	return 0;
}

/*
 *	Check the configuration.
 */
int dpc_config_check(dpc_config_t *config)
{
	CONF_CHECK_FLOAT("progress_interval", config->progress_interval, config->progress_interval >= 0, ">= 0");
	CONF_CHECK_FLOAT("request_timeout", config->request_timeout, config->request_timeout >= 0, ">= 0");
	CONF_CHECK_UINT64("base_xid", config->base_xid, config->base_xid <= UINT32_MAX, "<= 0xffffffff");
	CONF_CHECK_FLOAT("rate_limit", config->rate_limit, config->rate_limit >= 0, ">= 0");
	CONF_CHECK_FLOAT("duration_start_max", config->duration_start_max, config->duration_start_max >= 0, ">= 0");
	CONF_CHECK_UINT("session_max_active", config->session_max_active, config->session_max_active >= 1, ">= 1");

	/*
	 *	Check and fix absurd values.
	 */
	if (CONF.progress_interval) {
		if (CONF.progress_interval < 0.1) CONF.progress_interval = 0.1;
		else if (CONF.progress_interval > 864000) CONF.progress_interval = 0;
	}

	if (CONF.request_timeout) {
		if (CONF.request_timeout < 0.01) CONF.request_timeout = 0.01;
		else if (CONF.request_timeout > 3600) CONF.request_timeout = 3600;
	}

	return 0;
}

/*
 *	Debug the configuration.
 */
void dpc_config_debug(dpc_config_t *config)
{
	#define CONF_DEBUG_FMT(_fmt, _x) \
		DEBUG("- %s = %" _fmt, STRINGIFY(_x), config->_x);

	#define CONF_DEBUG_INT(_x)\
		CONF_DEBUG_FMT("d", _x)

	#define CONF_DEBUG_UINT(_x) \
		CONF_DEBUG_FMT("u", _x)

	#define CONF_DEBUG_UINT64(_x) \
		CONF_DEBUG_FMT(PRIu64, _x)

	#define CONF_DEBUG_FLOAT(_x) \
		CONF_DEBUG_FMT("f", _x)

	#define CONF_DEBUG_STR(_x) \
		if (config->_x) CONF_DEBUG_FMT("s", _x)

	#define CONF_DEBUG_IPADDR(_x) { \
		char ipaddr_buf[FR_IPADDR_STRLEN] = ""; \
		if ((config->_x.af == AF_INET) && fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf), &config->_x)) \
			DEBUG("- %s = %s", STRINGIFY(_x), ipaddr_buf); \
	}

	#define CONF_DEBUG_BOOL(_x) \
		DEBUG("- %s = %s", STRINGIFY(_x), config->_x ? "yes" : "no");

	#define CONF_DEBUG_STR_MULTI(_x) \
	{ \
		int i; \
		for (i = 0; i < talloc_array_length(config->_x); i++) { \
			DEBUG("- %s[%u] = %s", STRINGIFY(_x), i, config->_x[i]); \
		} \
	}

	DEBUG("Configuration values:");

	CONF_DEBUG_UINT(debug_level);
	CONF_DEBUG_BOOL(debug_dev);
	CONF_DEBUG_BOOL(debug_basename);
	CONF_DEBUG_BOOL(log_timestamp);

	CONF_DEBUG_FLOAT(progress_interval);
	CONF_DEBUG_BOOL(pr_stat_timestamp);
	CONF_DEBUG_BOOL(pr_stat_per_input);
	CONF_DEBUG_UINT(pr_stat_per_input_max);

	CONF_DEBUG_BOOL(template);
	CONF_DEBUG_BOOL(xlat);
	CONF_DEBUG_STR(file_input);
	CONF_DEBUG_STR_MULTI(xlat_files);
	CONF_DEBUG_UINT64(base_xid);

	CONF_DEBUG_STR(iface);
	CONF_DEBUG_STR_MULTI(gateways);
	CONF_DEBUG_IPADDR(allowed_server);

	CONF_DEBUG_INT(packet_trace_lvl);
	CONF_DEBUG_BOOL(packet_trace_elapsed);
	CONF_DEBUG_BOOL(packet_trace_timestamp);
	CONF_DEBUG_FLOAT(request_timeout);
	CONF_DEBUG_UINT(retransmit_max);

	CONF_DEBUG_FLOAT(rate_limit);
	CONF_DEBUG_FLOAT(input_rate_limit);
	CONF_DEBUG_FLOAT(duration_start_max);
	CONF_DEBUG_UINT(input_num_use);
	CONF_DEBUG_UINT(session_max_num);
	CONF_DEBUG_UINT(session_max_active);
}
