#pragma once
/*
 * dpc_config.h
 */

typedef struct dpc_config_s dpc_config_t;

extern dpc_config_t *dpc_config; //!< Global configuration singleton.
#define CONF (*dpc_config)

/*
 *	Main configuration
 */
struct dpc_config_s {
	char const *name;            //!< Name of the daemon.
	bool overwrite_config_name;  //!< Overwrite the configured name, as this
	                             ///< was specified by the user on the command line.
	CONF_SECTION *root_cs;       //!< Root of the main config.

	int debug_level;             //!< The base debug level.
	bool debug_dev;              //!< Enable extended debug information for developper.
	bool debug_basename;         //!< Print only file base name.
	bool log_timestamp;          //!< Add timestamp to log messages.

	uint32_t retransmit_max;         //<! Max retransmissions of a request not replied to (not including first packet).
};

void dpc_config_name_set_default(dpc_config_t *config, char const *name, bool overwrite_config);
dpc_config_t *dpc_config_alloc(TALLOC_CTX *ctx);
int dpc_config_init(dpc_config_t *config, char const *conf_file);
