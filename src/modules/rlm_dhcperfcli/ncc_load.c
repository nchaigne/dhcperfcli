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
fr_time_t ncc_load_end_time_set()
{
	fte_load_end = fr_time();
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

	/* If end is not provided, use current time (or time snapshot if set).
	 */
	if (!end) end = ncc_fr_time();

	return end - start;
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
 * Get elapsed time from the start of a given time segment.
 */
double ncc_segment_get_elapsed(ncc_segment_t *segment)
{
	fr_time_delta_t ftd_ref;
	fr_time_delta_t ftd_elapsed = ncc_load_elapsed_fr_time_get();

	if (ftd_elapsed < segment->ftd_start) {
		return 0; /* Segment is not started yet. */
	}

	if (segment->ftd_end && ftd_elapsed >= segment->ftd_end) {
		/*
		 * Current time is beyond segment end.
		 */
		ftd_ref = segment->ftd_end - segment->ftd_start;
	} else {
		ftd_ref = ftd_elapsed - segment->ftd_start;
	}

	return ncc_fr_time_to_float(ftd_ref);
}


/**
 * Update a type of transaction statistics, with one newly completed transaction:
 * number of such transactions, cumulated rtt, min/max rtt.
 */
void ncc_tr_stats_update_values(ncc_transaction_stats_t *stats, fr_time_delta_t rtt)
{
	if (!rtt) return;

	/* Set timestamp of first transaction. */
	if (!stats->fte_start) stats->fte_start = fr_time();

	/* Update timestamp of latest. */
	stats->fte_end = fr_time();

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
 * Get the longest name of actual transactions.
 */
size_t ncc_dyn_tr_stats_name_max_len(size_t max_len, ncc_dyn_tr_stats_t *dyn_tr_stats)
{
	int i;
	size_t num_transaction_type = talloc_array_length(dyn_tr_stats->names);

	for (i = 0; i < num_transaction_type; i++) {
		size_t len = strlen(dyn_tr_stats->names[i]);
		if (len > max_len) max_len = len;
	}
	return max_len;
}

/**
 * Compute the effective rate (reply per second) of a given transaction type (or all).
 * Allow to specify a minimum elapsed time. If not attained, rate is not calculated.
 */
double ncc_get_tr_rate(ncc_transaction_stats_t *my_stats, double elapsed_min)
{
	double elapsed = ncc_fr_time_to_float(ncc_elapsed_fr_time_get(my_stats->fte_start, my_stats->fte_end));

	if (elapsed <= 0 || elapsed < elapsed_min) return 0;

	return (double)my_stats->num / elapsed;
}
