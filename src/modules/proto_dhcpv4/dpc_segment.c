/**
 * @file dpc_segment.c
 * @brief Time segments handling.
 */

#include "dpc_segment.h"

static uint32_t segment_id;


/**
 * For a given elapsed time, find matching segment (if any) from the list.
 *
 * @param[in] dlist        segment list.
 * @param[in] segment      previous segment (NULL if none).
 * @param[in] ftd_elapsed  elapsed time.
 *
 * @return segment matching elapsed time (NULL if no match).
 */
dpc_segment_t *dpc_segment_from_elapsed_time(ncc_dlist_t *dlist, dpc_segment_t *segment, fr_time_delta_t ftd_elapsed)
{
	if (!NCC_DLIST_IS_INIT(dlist)) return NULL;

	/* If there was no current segment, start searching from the head. */
	if (!segment) segment = NCC_DLIST_HEAD(dlist);

	while (segment) {
		if ( (!segment->ftd_start || (segment->ftd_start && ftd_elapsed >= segment->ftd_start))
		  && (!segment->ftd_end || (segment->ftd_end && ftd_elapsed < segment->ftd_end)) ) {

			/* This segment matches current elapsed time. */
			DEBUG3("Found matching segment (id: %u) (%.3f - %.3f) for elapsed time %f", segment->id,
			       ncc_fr_time_to_float(segment->ftd_start), ncc_fr_time_to_float(segment->ftd_end),
			       ncc_fr_time_to_float(ftd_elapsed));

			return segment;
		}

		segment = NCC_DLIST_NEXT(dlist, segment);
	}

	/* No matching segment found. */
	return NULL;
}

/**
 * Print to a string buffer a segment time interval.
 *
 * @param[out] out      where to write the output string (size should be at least DPC_SEGMENT_INTERVAL_STRLEN).
 * @param[in]  segment  the time segment.
 *
 * @return pointer to the output buffer.
 */
char *dpc_segment_interval_sprint(char *out, dpc_segment_t *segment)
{
	FN_ARG_CHECK(NULL, out);

	/* First endpoint is always bounded (finite value).
	 * Second endpoint is unbounded if set to 0.
	 */
	if (segment->ftd_end) {
		sprintf(out, "(%.3f - %.3f)", ncc_fr_time_to_float(segment->ftd_start), ncc_fr_time_to_float(segment->ftd_end));
	} else {
		sprintf(out, "(%.3f - INF)", ncc_fr_time_to_float(segment->ftd_start));
	}

	return out;
}

/**
 * Print a list of segments.
 *
 * @param[in] fp     where to print.
 * @param[in] dlist  list of segments.
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
			char interval_buf[DPC_SEGMENT_INTERVAL_STRLEN];

			fprintf(fp, "  #%u: id: %u, interval: %s\n",
			        i, segment->id, dpc_segment_interval_sprint(interval_buf, segment));

			i++;
			segment = NCC_DLIST_NEXT(dlist, segment);
		}
	}
}

/**
 * Parse a segment specified from a string.
 * Input format: <start time>;<end time>[;<rate limit>]
 */
int dpc_segment_parse(TALLOC_CTX *ctx, ncc_dlist_t *dlist, char const *in)
{
	FN_ARG_CHECK(-1, in);
	FN_ARG_CHECK(-1, in[0] != '\0');

	char const *sep1, *sep2;
	double start, end;
	double rate = 0;
	fr_time_delta_t ftd_start, ftd_end;
	dpc_segment_t *segment;

	sep1 = strchr(in, ';');
	if (!sep1) {
		fr_strerror_printf("Invalid segment: [%s]", in);
		return -1;
	}

	sep2 = strchr(sep1 + 1, ';');

	if (ncc_value_from_str(&start, FR_TYPE_FLOAT64 | NCC_TYPE_NOT_NEGATIVE, in, sep1 - in) < 0
	   || ncc_value_from_str(&end, FR_TYPE_FLOAT64 | NCC_TYPE_NOT_NEGATIVE, sep1 + 1, sep2 ? sep2 - 1 - sep1 : -1) < 0
	   || (sep2 && ncc_value_from_str(&rate, FR_TYPE_FLOAT64 | NCC_TYPE_NOT_NEGATIVE, sep2 + 1, -1) < 0)) {
		fr_strerror_printf_push("Failed to parse segment [%s]", in);
		return -1;
	}

	ftd_start = ncc_float_to_fr_time(start);
	ftd_end = ncc_float_to_fr_time(end);

	segment = dpc_segment_add(ctx, dlist, ftd_start, ftd_end);
	if (!segment) {
		fr_strerror_printf_push("Failed to add segment");
		return -1;
	}
	segment->rate_limit = rate;

	return 0;
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
 * As a rule, existing segments will never be modified when trying to add a new segment.
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

	DEBUG3("Trying to add segment (%.3f - %.3f)", ncc_fr_time_to_float(ftd_start), ncc_fr_time_to_float(ftd_end));

	if (ftd_end && ftd_end <= ftd_start) {
		fr_strerror_printf("Invalid segment (%.3f - %.3f), end cannot predate start",
			               ncc_fr_time_to_float(ftd_start), ncc_fr_time_to_float(ftd_end));
		return NULL;
	}
	else if (!ftd_start && !ftd_end && NCC_DLIST_SIZE(dlist) > 0) {
		/* 0-0 is only allowed if list is empty (would be confusing otherwise). */
		fr_strerror_printf("Invalid segment (%.3f - %.3f), other segments exist already",
			               ncc_fr_time_to_float(ftd_start), ncc_fr_time_to_float(ftd_end));
		return NULL;
	}

	dpc_segment_t *segment_new;

	MEM(segment_new = talloc_zero(ctx, dpc_segment_t));
	segment_new->ftd_start = ftd_start;
	segment_new->ftd_end = ftd_end;

	/* If list is empty, just insert new segment. */
	if (NCC_DLIST_SIZE(dlist) == 0) {
		DEBUG3("Inserting first segment (%.3f - %.3f)",
		       ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end));

		NCC_DLIST_ENQUEUE(dlist, segment_new);
		goto finish;
	}

	dpc_segment_t *segment = NCC_DLIST_HEAD(dlist);
	while (segment) {

		/* If existing segment starts at the beginning and last until the end, then we cannot add anything more. */
		if (!segment->ftd_start && !segment->ftd_end) {
		overlap:
			fr_strerror_printf("Invalid segment (%.3f - %.3f), would overlap existing segment (%.3f - %.3f)",
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
			goto finish;
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
				DEBUG3("Inserting segment (%.3f - %.3f) before (%.3f - %.3f)",
				       ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end),
				       ncc_fr_time_to_float(segment->ftd_start), ncc_fr_time_to_float(segment->ftd_end));

				NCC_DLIST_INSERT_BEFORE(dlist, segment, segment_new);
				goto finish;
			}

			/* New segment is not inserted before existing segment. Check for overlap. (e.g. 5-8, 7-10 => reject.) */
			if (segment_new->ftd_start < segment->ftd_end) goto overlap;

			/* Also overlap if existing segment end is INF.
			 * (e.g. 5-0, 10-0 => reject; 5-0, 10-15 => reject.)
			 */
			if (!segment->ftd_end) goto overlap;
		}

		segment = NCC_DLIST_NEXT(dlist, segment);
	}

	/* Insert new segment at the tail. */
	DEBUG3("Inserting segment (%.3f - %.3f) at the tail",
	       ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end));

	NCC_DLIST_ENQUEUE(dlist, segment_new);
	goto finish;

finish:
	segment_new->id = segment_id++;
	return segment_new;
}
