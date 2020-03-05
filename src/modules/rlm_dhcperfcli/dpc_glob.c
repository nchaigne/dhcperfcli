/**
 * @file dpc_glob.c
 * @brief Global elements used by several compilation units
 */
#include <freeradius-devel/server/base.h>

#include "dhcperfcli.h"
#include "dpc_config.h"

int dpc_debug_lvl;
dpc_config_t *dpc_config;
fr_time_t fte_start;

ncc_dlist_t input_list;

fr_dict_t const *dict_dhcperfcli;
