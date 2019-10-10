#pragma once
/*
 * dpc_segment.h
 */

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/time.h>

#include "ncc_util.h"


#define DPC_SEGMENT_TIME_STRLEN        (8 + 1 + 3 + 1)
/* <n>.<ddd>
 * Limit to 8 non-fractional digits, which is enough for 3 years.
 */

#define DPC_SEGMENT_INTERVAL_STRLEN    (1 + DPC_SEGMENT_TIME_STRLEN + 3 + DPC_SEGMENT_TIME_STRLEN + 1)
/* (<n1>.<ddd> - <n2>.<ddd>)
 */


/*
 *	Time segment.
 */
typedef struct dpc_segment {
	/* Generic chaining */
	fr_dlist_t dlist;           //!< Our entry into the linked list.

	uint32_t id;                //!< Id of segment.
	uint32_t num_use;           //!< How many times has this segment been used to start sessions.

	double rate_limit;          //<! Limit rate/s of sessions initialized from this segment.

	fr_time_delta_t ftd_start;  //!< Start of segment.
	fr_time_delta_t ftd_end;    //!< End of segment.

} dpc_segment_t;


dpc_segment_t *dpc_segment_from_elapsed_time(ncc_dlist_t *dlist, dpc_segment_t *segment, fr_time_delta_t ftd_elapsed);
char *dpc_segment_interval_sprint(char *out, dpc_segment_t *segment);
void dpc_segment_list_fprint(FILE *fp, ncc_dlist_t *dlist);
int dpc_segment_parse(TALLOC_CTX *ctx, ncc_dlist_t *dlist, char const *in);
dpc_segment_t *dpc_segment_add(TALLOC_CTX *ctx, ncc_dlist_t *dlist, fr_time_delta_t ftd_start, fr_time_delta_t ftd_end);
