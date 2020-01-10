#pragma once
/*
 *	ncc_load.h
 */
#include "ncc_segment.h"

extern fr_time_t fte_load_start;
extern fr_time_t fte_load_end;
extern fr_time_t fte_load_snapshot;


/*
 * Holds statistics for a given transaction type.
 */
typedef struct ncc_transaction_stats {
	uint32_t num;              //!< Number of completed transactions.
	fr_time_t fte_start;       //!< Timestamp of first transaction.
	fr_time_t fte_end;         //!< Timestamp of latest transaction.
	fr_time_delta_t rtt_cumul; //!< Cumulated rtt (request to reply time).
	fr_time_delta_t rtt_min;   //!< Lowest rtt.
	fr_time_delta_t rtt_max;   //!< Highest rtt (timeout are not included).
} ncc_transaction_stats_t;

/*
 * Statistics for dynamically named transactions.
 */
typedef struct {
	char **names;                   //<! Array storing transaction names.
	ncc_transaction_stats_t *stats; //<! Statistics data.
} ncc_dyn_tr_stats_t;



fr_time_t ncc_load_start_time_set();
fr_time_t ncc_load_end_time_set();

double ncc_load_elapsed_time_snapshot_set();
void ncc_load_time_snapshot_clear();
fr_time_t ncc_fr_time();
fr_time_delta_t ncc_elapsed_fr_time_get(fr_time_t start, fr_time_t end);

fr_time_delta_t ncc_load_elapsed_fr_time_get();
double ncc_load_elapsed_time_get();

double ncc_segment_get_elapsed(ncc_segment_t *segment);

void ncc_tr_stats_update_values(ncc_transaction_stats_t *stats, fr_time_delta_t rtt);
void ncc_dyn_tr_stats_update(TALLOC_CTX *ctx, ncc_dyn_tr_stats_t *dyn_tr_stats, char const *name, fr_time_delta_t rtt);
size_t ncc_dyn_tr_stats_name_max_len(size_t max_len, ncc_dyn_tr_stats_t *dyn_tr_stats);
double ncc_get_tr_rate(ncc_transaction_stats_t *my_stats);
