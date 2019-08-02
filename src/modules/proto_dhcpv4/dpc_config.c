/**
 * @file dpc_config.c
 * @brief Handle the program configuration (heavy reuse from FreeRADIUS main_config.c)
 */

#include "dhcperfcli.h"
#include "dpc_config.h"


static const CONF_PARSER server_config[] = {

	{ FR_CONF_OFFSET("debug_level", FR_TYPE_UINT32, dpc_config_t, debug_level), .dflt = "0" },
	{ FR_CONF_OFFSET("debug_dev", FR_TYPE_BOOL, dpc_config_t, debug_dev) },

	CONF_PARSER_TERMINATOR
};


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

	/*
	 *	Starting WITHOUT "-x" on the command-line: use whatever is in the config file.
	 */
	if (dpc_debug_lvl == 0) dpc_debug_lvl = config->debug_level;

	ncc_log_init(stdout, dpc_debug_lvl, config->debug_dev); /* Update with file configuration. */

	//TODO: have command line options take precedence over configuration from file?

printf("CONF dpc_debug_lvl = %u\n", dpc_debug_lvl);

	return 0;

failure:
	talloc_free(cs);
	return -1;
}
