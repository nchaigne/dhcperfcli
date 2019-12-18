#pragma once
/*
 * dpc_time_data.h
 */

#include "ncc_time_data.h"

/*
 *	Holds sessions statistics.
 */
typedef struct dpc_session_stats {
	uint32_t num;              //!< Number of started sessions.
	uint32_t target;           //<! Target number of sessions (computed from specified rate).

	char const *input_name;    //!< Name of input (optional).
	uint32_t input_id;         //!< Id of input.

	ncc_segment_t *segment;    //<! Current segment (optional).
} dpc_session_stats_t;

/*
 *	Statistics for dynamically discovered sessions types.
 */
typedef struct {
	dpc_session_stats_t *stats;  //<! Statistics data.
} dpc_dyn_session_stats_t;
// not strictly needed for an array, but we might want to use a better storage later.


int dpc_timedata_config_load(dpc_config_t *config);
void dpc_timedata_config_debug(dpc_config_t *config);

void dpc_timedata_store_packet_stat(dpc_packet_stat_field_t stat_type, uint32_t packet_type);
int dpc_timedata_send_packet_stat(ncc_timedata_stat_t *stat);

void dpc_timedata_store_tr_stat(char const *name, fr_time_delta_t rtt);
int dpc_timedata_send_tr_stat(ncc_timedata_stat_t *stat);

void dpc_dyn_session_stats_update(TALLOC_CTX *ctx, dpc_dyn_session_stats_t *dyn_session_stats,
                                  uint32_t input_id, char const *input_name, ncc_segment_t *segment,
                                  uint32_t target_add);
void dpc_timedata_store_session_stat(uint32_t input_id, char const *input_name, ncc_segment_t *segment,
                                     uint32_t target_add);
int dpc_timedata_send_session_stat(ncc_timedata_stat_t *stat);
