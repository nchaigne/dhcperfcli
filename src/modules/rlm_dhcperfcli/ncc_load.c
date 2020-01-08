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
