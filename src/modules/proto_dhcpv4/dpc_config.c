/**
 * @file dpc_config.c
 * @brief Handle the program configuration (reuse from FreeRADIUS main_config.c)
 */

#include "dhcperfcli.h"
#include "dpc_config.h"

#define MAX_ATTR_INPUT 128

/* Note: Type 'float64' is not supported by FreeRADIUS in configuration files.
 * So we must use 'float32' instead.
 */

static const CONF_PARSER timing_config[] = {

	{ FR_CONF_OFFSET("timeout", FR_TYPE_FLOAT32, dpc_config_t, request_timeout) }, /* No default */
	{ FR_CONF_OFFSET("retransmit", FR_TYPE_UINT32, dpc_config_t, retransmit_max) }, /* No default */

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER packet_config[] = {

	{ FR_CONF_OFFSET("trace_elapsed", FR_TYPE_BOOL, dpc_config_t, packet_trace_elapsed), .dflt = "no" },
	{ FR_CONF_OFFSET("trace_datetime", FR_TYPE_BOOL, dpc_config_t, packet_trace_datetime), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

/*
 * Note:
 * Some parameters may be defined through command-line options and configuration files.
 * For these parameters, do *not* provide a default ("dflt") to the configuration parser.
 * A value will be set by the configuration parser only if the parameter is explicitly defined in configuration files.
 */
static const CONF_PARSER server_config[] = {

	{ FR_CONF_OFFSET("debug_level", FR_TYPE_UINT32, dpc_config_t, debug_level) }, /* No default */
	{ FR_CONF_OFFSET("debug_dev", FR_TYPE_BOOL, dpc_config_t, debug_dev) }, /* No default */
	{ FR_CONF_OFFSET("debug_basename", FR_TYPE_BOOL, dpc_config_t, debug_basename), .dflt = "yes" },
	{ FR_CONF_OFFSET("timestamp", FR_TYPE_BOOL, dpc_config_t, log_timestamp), .dflt = "yes" },

	{ FR_CONF_POINTER("packet", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) packet_config },
	{ FR_CONF_POINTER("timing", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) timing_config },

	CONF_PARSER_TERMINATOR
};


/*
 *	Iterates over all input definitions in the specified section, adding them to the list.
 */
int dpc_input_list_parse_section(CONF_SECTION *section)
{
	CONF_SECTION *cs = NULL;
	dpc_input_t *input;

	/*
	 *	Iterate over all the input definitions in the section, adding them to the list.
	 */
	while ((cs = cf_section_find_next(section, cs, "input", CF_IDENT_ANY))) {

		MEM(input = talloc_zero(section, dpc_input_t));

		int ret = ncc_pair_list_afrom_cs(input, dict_dhcpv4, &input->vps, cs, MAX_ATTR_INPUT);
		if (ret != 0) {
			return -1;
		}

		dpc_input_handle(input, &input_list);
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
 *	Read configuration file.
 */
int dpc_config_init(dpc_config_t *config, char const *conf_file)
{
	CONF_SECTION *cs = NULL;

	if (!conf_file) return 0;

	cs = cf_section_alloc(NULL, NULL, "main", NULL);
	if (!cs) return -1;

	/* Read the configuration file */
	if (cf_file_read(cs, conf_file) < 0) {
		ERROR("Failed to read configuration file %s", conf_file);
		goto failure;
	}

	if (cf_section_rules_push(cs, server_config) < 0) goto failure;

	/* Parse main configuration. */
	if (cf_section_parse(config, config, cs) < 0) goto failure;

	/* Debug level (overriden by command-line option -x). */
	if (dpc_debug_lvl == 0) dpc_debug_lvl = config->debug_level;

	ncc_log_init(stdout, dpc_debug_lvl); /* Update with file configuration. */
	ncc_default_log.timestamp = config->log_timestamp ? L_TIMESTAMP_ON : L_TIMESTAMP_OFF;
	ncc_default_log.line_number = config->debug_dev;
	ncc_default_log.basename = config->debug_basename;

	DEBUG2("%s: #### Loading 'input' entries ####", config->name);
	if (dpc_input_list_parse_section(cs) != 0) {
		ERROR("Failed to load 'input' entries from configuration file");
		goto failure;
	}

	return 0;

failure:
	talloc_free(cs);
	return -1;
}
