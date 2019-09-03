#pragma once
/*
 * dpc_segment.h
 */

#include "dhcperfcli.h"


/*
 *	Segment.
 */
typedef struct dpc_segment {
	/* Generic chaining */
	fr_dlist_t dlist;          //!< Our entry into the linked list.

	uint32_t id;                //!< Id of segment.

	fr_time_delta_t ftd_start;  //!< Start of segment.
	fr_time_delta_t ftd_end;    //!< End of segment.

} dpc_segment_t;


void dpc_segment_list_fprint(FILE *fp, ncc_dlist_t *dlist);
int dpc_segment_parse(TALLOC_CTX *ctx, ncc_dlist_t *dlist, char const *in);
dpc_segment_t *dpc_segment_add(TALLOC_CTX *ctx, ncc_dlist_t *dlist, fr_time_delta_t ftd_start, fr_time_delta_t ftd_end);
