/**
 * @file ncc_load.c
 * @brief Load framework functions.
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 */

#include "ncc_util.h"
#include "ncc_load.h"

fr_time_t fte_load_start;
fr_time_t fte_load_end;
fr_time_t fte_load_snapshot;


/**
 * Set load start time.
 */
fr_time_t ncc_load_start_time_set()
{
	fte_load_start = fr_time();
	return fte_load_start;
}

/**
 * Set load end time.
 */
fr_time_t ncc_load_end_time_set(fr_time_t fte_end)
{
	if (fte_end) fte_load_end = fte_end;
	else fte_load_end = fr_time();

	return fte_load_end;
}

/**
 * Set a snapshot of the current time.
 * Return load elapsed time (up to the snapshot).
 */
double ncc_load_elapsed_time_snapshot_set()
{
	if (fte_load_end) {
		fte_load_snapshot = fte_load_end;
	} else {
		fte_load_snapshot = fr_time();
	}

	return ncc_fr_time_to_float(fte_load_snapshot - fte_load_start);
}

/**
 * Clear the current time snapshot.
 */
void ncc_load_time_snapshot_clear()
{
	fte_load_snapshot = 0;
}

/**
 * Get either the current time snapshot if set, or real current time otherwise.
 */
fr_time_t ncc_fr_time()
{
	if (fte_load_snapshot) return fte_load_snapshot;
	else return fr_time();
}

/**
 * Get an elapsed time (difference between start and end).
 * If end is not set, use instead current time (or time snapshot if set).
 */
fr_time_delta_t ncc_elapsed_fr_time_get(fr_time_t start, fr_time_t end)
{
	if (!start) return 0; /* Start time not initialized yet. */

	if (end) {
		/* Time delta from start to end.
		 */
		return end - start;

	} else {
		/* Time delta from start to current time (or time snapshot if set).
		 */
		return ncc_fr_time() - start;
	}
}

/**
 * Obtain load elapsed time.
 */
fr_time_delta_t ncc_load_elapsed_fr_time_get()
{
	return ncc_elapsed_fr_time_get(fte_load_start, fte_load_end);
}
double ncc_load_elapsed_time_get()
{
	return ncc_fr_time_to_float(ncc_load_elapsed_fr_time_get());
}


/**
 * Update a type of transaction statistics, with one newly completed transaction:
 * number of such transactions, cumulated rtt, min/max rtt.
 */
void ncc_tr_stats_update_values(ncc_transaction_stats_t *stats, fr_time_delta_t rtt)
{
	if (!rtt) return;

	/* Update 'rtt_min'. */
	if (stats->num == 0 || rtt < stats->rtt_min) {
		stats->rtt_min = rtt;
	}

	/* Update 'rtt_max'. */
	if (stats->num == 0 || rtt > stats->rtt_max) {
		stats->rtt_max = rtt;
	}

	/* Update 'rtt_cumul' and 'num'. */
	stats->rtt_cumul += rtt;
	stats->num ++;
}

/**
 * Update statistics for a dynamically named transaction type.
 */
void ncc_dyn_tr_stats_update(TALLOC_CTX *ctx, ncc_dyn_tr_stats_t *dyn_tr_stats, char const *name, fr_time_delta_t rtt)
{
	/* Get the transaction name index. */
	int i = ncc_str_array_index(ctx, &dyn_tr_stats->names, name);

	/* Reallocate if necessary */
	size_t num_transaction_type = talloc_array_length(dyn_tr_stats->stats);
	if (i >= num_transaction_type) {
		TALLOC_REALLOC_ZERO(ctx, dyn_tr_stats->stats,
		                    ncc_transaction_stats_t, num_transaction_type, i + 1);
	}

	ncc_transaction_stats_t *my_stats = &(dyn_tr_stats->stats[i]);
	ncc_tr_stats_update_values(my_stats, rtt);
}

/**
 * Compute the effective rate (reply per second) of a given transaction type (or all).
 */
double ncc_get_tr_rate(ncc_transaction_stats_t *my_stats)
{
	double elapsed = ncc_load_elapsed_time_get();

	if (elapsed <= 0) return 0; /* Should not happen. */
	return (double)my_stats->num / elapsed;
}
