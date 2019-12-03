#pragma once
/*
 * ncc_segment.h
 */

#include <freeradius-devel/util/dlist.h>
#include <freeradius-devel/util/time.h>

#include "ncc_util.h"


#define NCC_SEGMENT_TIME_STRLEN        (8 + 1 + 3 + 1)
/* <n>.<ddd>
 * Limit to 8 non-fractional digits, which is enough for 3 years.
 */

#define NCC_SEGMENT_INTERVAL_STRLEN    (1 + NCC_SEGMENT_TIME_STRLEN + 3 + NCC_SEGMENT_TIME_STRLEN + 1)
/* (<n1>.<ddd> - <n2>.<ddd>)
 */


extern fr_table_num_ordered_t const segment_types[];
extern size_t segment_types_len;


/*
 *	Different kinds of time segments.
 */
typedef enum {
	NCC_SEGMENT_RATE_INVALID = 0,
	NCC_SEGMENT_RATE_UNBOUNDED,
	NCC_SEGMENT_RATE_FIXED,
	NCC_SEGMENT_RATE_LINEAR,
	NCC_SEGMENT_RATE_NULL
} ncc_segment_type_t;

/*
 *	Time segment.
 */
typedef struct ncc_segment {
	/* Generic chaining */
	fr_dlist_t dlist;           //!< Our entry into the linked list.

	char const *name;           //!< Name of segment (optional).
	uint32_t id;                //!< Id of segment.
	uint32_t num_use;           //!< How many times has this segment been used to start sessions.
	uint32_t target;            //!< How many times should this segment have been used to meet target rate.

	ncc_segment_type_t type;    //!< Type of segment.

	union {
		double rate_limit;      //<! Limit rate/s of sessions initialized from this segment.

		struct {                //<! Varying limit rate/s of sessions initialized from this segment.
			double start;       //<! Start value.
			double end;         //<! End value.
		} rate_limit_range;
	};

	fr_time_delta_t ftd_start;  //!< Start of segment.
	fr_time_delta_t ftd_end;    //!< End of segment.

} ncc_segment_t;


ncc_segment_t *ncc_segment_from_elapsed_time(ncc_dlist_t *dlist, ncc_segment_t *segment, fr_time_delta_t ftd_elapsed);
char *ncc_segment_description_snprint(char *out, size_t outlen, ncc_segment_t *segment, bool with_rate);
char *ncc_segment_interval_snprint(char *out, size_t outlen, ncc_segment_t *segment);
void ncc_segment_list_fprint(FILE *fp, ncc_dlist_t *dlist);
int ncc_segment_parse(TALLOC_CTX *ctx, ncc_dlist_t *dlist, char const *in);
ncc_segment_t *ncc_segment_add(TALLOC_CTX *ctx, ncc_dlist_t *dlist, fr_time_delta_t ftd_start, fr_time_delta_t ftd_end);
int ncc_segment_list_complete(TALLOC_CTX *ctx, ncc_dlist_t *dlist, double rate);
