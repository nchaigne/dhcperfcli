#include "dhcperfcli.h"
#include "dpc_segment.h"


/**
 * Print the whole list of segments.
 *
 * @param[in] fp     where to print.
 * @param[in] dlist  list of segments
 */
void dpc_segment_list_fprint(FILE *fp, ncc_dlist_t *dlist)
{
	if (!NCC_DLIST_IS_INIT(dlist)) {
		fprintf(fp, "Segment list is uninitialized\n");
	} else if (NCC_DLIST_SIZE(dlist) == 0) {
		fprintf(fp, "Segment list is empty\n");
	} else {
		fprintf(fp, "Segment list (size: %u)\n", NCC_DLIST_SIZE(dlist));

		dpc_segment_t *segment = NCC_DLIST_HEAD(dlist);
		int i = 0;

		while (segment) {
			fprintf(fp, "- Segment %u: start = %f end = %f\n",
			        i, ncc_fr_time_to_float(segment->ftd_start), ncc_fr_time_to_float(segment->ftd_end));

			i++;
			segment = NCC_DLIST_NEXT(dlist, segment);
		}
	}
}

/**
 * Attempt to add a specified time segment to a list. Segments cannot overlap.
 * After being added, start = 0 means "from the beginning", end = 0 means "until the end".
 *
 * While trying to add a new segment, start = 0 means "start as soon as possible", which can be
 * the beginning, or right after an existing segment that starts from the beginning.
 *
 * Likewise, end = 0 means "until the end" if there is no segment after the new segment added,
 * or if there is, "until the start of that next segment".
 *
 * @param[in] ctx        talloc context.
 * @param[in] dlist      list to which segment will be added.
 * @param[in] ftd_start  start of new segment.
 * @param[in] ftd_end    end of new segment.
 *
 * @return the new segment added, or NULL if failed.
 */
dpc_segment_t *dpc_segment_add(TALLOC_CTX *ctx, ncc_dlist_t *dlist, fr_time_delta_t ftd_start, fr_time_delta_t ftd_end)
{
	NCC_DLIST_INIT(dlist, dpc_segment_t);

	DEBUG2("Trying to add segment (%f - %f)", ncc_fr_time_to_float(ftd_start), ncc_fr_time_to_float(ftd_end));

	if (ftd_end && ftd_end <= ftd_start) {
		fr_strerror_printf("Invalid segment (%f - %f), end cannot predate start",
			               ncc_fr_time_to_float(ftd_start), ncc_fr_time_to_float(ftd_end));
		return NULL;
	}
	else if (!ftd_start && !ftd_end && NCC_DLIST_SIZE(dlist) > 0) {
		/* 0-0 is only allowed if list is empty (would be confusing otherwise). */
		fr_strerror_printf("Invalid segment (%f - %f), other segments exist already",
			               ncc_fr_time_to_float(ftd_start), ncc_fr_time_to_float(ftd_end));
		return NULL;
	}

	dpc_segment_t *segment_new;

	MEM(segment_new = talloc_zero(ctx, dpc_segment_t));
	segment_new->ftd_start = ftd_start;
	segment_new->ftd_end = ftd_end;

	/* If list is empty, just insert new segment. */
	if (NCC_DLIST_SIZE(dlist) == 0) {
		DEBUG2("Inserting first segment (%f - %f)",
		      ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end));

		NCC_DLIST_ENQUEUE(dlist, segment_new);
		return segment_new;
	}

	dpc_segment_t *segment = NCC_DLIST_HEAD(dlist);
	while (segment) {

		/* If existing segment starts at the beginning and last until the end, then we cannot add anything more. */
		if (!segment->ftd_start && !segment->ftd_end) {
		overlap:
			fr_strerror_printf("Invalid segment (%f - %f), would overlap existing segment (%f - %f)",
			                   ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end),
			                   ncc_fr_time_to_float(segment->ftd_start), ncc_fr_time_to_float(segment->ftd_end));
			talloc_free(segment_new);
			return NULL;
		}

		/* If new segment start is not specified, and existing segment does not start at the beginning:
		 * - If new segment end < existing segment start, insert before. (e.g. 5-8, 0-3)
		 * - Else: overlap error. (e.g. 5-8, 0-6 => reject.)
		 */
		if (!segment_new->ftd_start && segment->ftd_start) {
			if (segment_new->ftd_end >= segment->ftd_start) goto overlap;

			NCC_DLIST_INSERT_BEFORE(dlist, segment, segment_new);
			return segment_new;
		}

		/* If new segment start is not specified (check performed on initial value):
		 * - If new segment end <= existing segment end: overlap error. (e.g. 0-5, 0-3 => reject.)
		 * - Else: adjust new segment start for insert after existing segment. (e.g. 0-5, 0-8 => 5-8, 0-10 => 8-10.)
		 */
		if (!ftd_start) {
			if (segment_new->ftd_end <= segment->ftd_end) goto overlap;

			segment_new->ftd_start = segment->ftd_end;

		} else {

			/* If new segment starts before the start of existing segment, insert before. */
			if (segment_new->ftd_start < segment->ftd_start) {

				/* If new segment end is not specified: Make it end at the start of existing next segment.
				 * (e.g. 5-8, 3-0 => 3-5.)
				 */
				if (!segment_new->ftd_end) {
					segment_new->ftd_end = segment->ftd_start;

				/* Else check for overlap error. (e.g. 5-8, 3-6 => reject.) */
				} else if (segment_new->ftd_end > segment->ftd_start) goto overlap;

				/* Else: insert before existing segment. */
				DEBUG2("Inserting segment (%f - %f) before (%f - %f)",
				       ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end),
				       ncc_fr_time_to_float(segment->ftd_start), ncc_fr_time_to_float(segment->ftd_end));

				NCC_DLIST_INSERT_BEFORE(dlist, segment, segment_new);
				return segment_new;
			}

			/* New segment is not inserted before existing segment. Check for overlap. (e.g. 5-8, 7-10 => reject.) */
			if (segment_new->ftd_start < segment->ftd_end) goto overlap;
		}

		segment = NCC_DLIST_NEXT(dlist, segment);
	}

	/* Insert new segment at the tail. */
	DEBUG2("Inserting (%f - %f) at the tail",
	       ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end));

	NCC_DLIST_ENQUEUE(dlist, segment_new);
	return segment_new;
}
