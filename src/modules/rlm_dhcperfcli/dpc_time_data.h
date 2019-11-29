#pragma once
/*
 * dpc_time_data.h
 */

#include "ncc_time_data.h"

/*
 *	Holds sessions statistics.
 */
typedef struct dpc_session_stats {
	uint32_t num;              //!< Number of started sessions

	char const *input_name;    //!< Name of input (optional).
	uint32_t input_id;         //!< Id of input.

	char const *segment_name;  //!< Name of segment (optional).
	uint32_t segment_id;       //!< Id of segment.
} dpc_session_stats_t;

/*
 *	Statistics for dynamically discovered sessions types.
 */
typedef struct {
	dpc_session_stats_t *stats;  //<! Statistics data.
} dpc_dyn_session_stats_t;
// not strictly needed for an array, but we might want to use a better storage later.


int dpc_timedata_config_load(dpc_config_t *config);

void dpc_timedata_store_packet_stat(dpc_packet_stat_field_t stat_type, uint32_t packet_type);
int dpc_timedata_send_packet_stat(ncc_timedata_stat_t *stat);

void dpc_timedata_store_tr_stat(char const *name, fr_time_delta_t rtt);
int dpc_timedata_send_tr_stat(ncc_timedata_stat_t *stat);

void dpc_dyn_session_stats_update(TALLOC_CTX *ctx, dpc_dyn_session_stats_t *dyn_session_stats,
                                  uint32_t input_id, char const *input_name);
void dpc_timedata_store_session_stat(uint32_t input_id, char const *input_name);
int dpc_timedata_send_session_stat(ncc_timedata_stat_t *stat);
