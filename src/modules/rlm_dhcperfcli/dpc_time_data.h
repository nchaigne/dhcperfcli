#pragma once
/*
 * dpc_time_data.h
 */

#include "ncc_time_data.h"


int dpc_timedata_config_load(dpc_config_t *config);

void dpc_timedata_store_packet_stat(dpc_packet_stat_field_t stat_type, uint32_t packet_type);
int dpc_timedata_send_packet_stat(ncc_timedata_stat_t *stat);
