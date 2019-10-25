/**
 * @file ncc_segment.c
 * @brief Time segments handling.
 */

#include "ncc_segment.h"

static uint32_t segment_id;


/* Map segment types to enum value.
 * Note: using "ordered" rather than "sorted" because performance is not an issue, and it's more convenient.
 */
fr_table_num_ordered_t const segment_types[] = {
	{ "fixed",     NCC_SEGMENT_RATE_FIXED },
	{ "linear",    NCC_SEGMENT_RATE_LINEAR },
	{ "null",      NCC_SEGMENT_RATE_NULL },
	{ "unbounded", NCC_SEGMENT_RATE_UNBOUNDED },
};
size_t segment_types_len = NUM_ELEMENTS(segment_types);


/**
 * For a given elapsed time, find matching segment (if any) from the list.
 *
 * @param[in] dlist        segment list.
 * @param[in] segment      previous segment (NULL if none).
 * @param[in] ftd_elapsed  elapsed time.
 *
 * @return segment matching elapsed time (NULL if no match).
 */
ncc_segment_t *ncc_segment_from_elapsed_time(ncc_dlist_t *dlist, ncc_segment_t *segment, fr_time_delta_t ftd_elapsed)
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
 * @param[out] out      where to write the output string (size should be at least NCC_SEGMENT_INTERVAL_STRLEN).
 * @param[in]  outlen   size of output buffer.
 * @param[in]  segment  the time segment.
 *
 * @return pointer to the output buffer.
 */
char *ncc_segment_interval_snprint(char *out, size_t outlen, ncc_segment_t *segment)
{
	size_t len;
	char *p = out;

	FN_ARG_CHECK(NULL, out);

	/* First endpoint is always bounded (finite value).
	 * Second endpoint is unbounded if set to 0.
	 */
	if (segment->ftd_end) {
		len = snprintf(p, outlen, "(%.3f - %.3f)", ncc_fr_time_to_float(segment->ftd_start), ncc_fr_time_to_float(segment->ftd_end));
	} else {
		len = snprintf(p, outlen, "(%.3f - INF)", ncc_fr_time_to_float(segment->ftd_start));
	}

	ERR_IF_TRUNCATED_LEN(p, outlen, len);
	return out;
}

/**
 * Print a list of segments.
 *
 * @param[in] fp     where to print.
 * @param[in] dlist  list of segments.
 */
void ncc_segment_list_fprint(FILE *fp, ncc_dlist_t *dlist)
{
	if (!NCC_DLIST_IS_INIT(dlist)) {
		fprintf(fp, "Segment list is uninitialized\n");
	} else if (NCC_DLIST_SIZE(dlist) == 0) {
		fprintf(fp, "Segment list is empty\n");
	} else {
		fprintf(fp, "Segment list (size: %u)\n", NCC_DLIST_SIZE(dlist));

		ncc_segment_t *segment = NCC_DLIST_HEAD(dlist);
		int i = 0;

		while (segment) {
			char interval_buf[NCC_SEGMENT_INTERVAL_STRLEN];

			fprintf(fp, "  #%u ", i);
			if (segment->name) {
				fprintf(fp, "%s ", segment->name);
			}

			fprintf(fp, "(id: %u): %s, interval: %s", segment->id,
			        fr_table_str_by_value(segment_types, segment->type, "???"),
			        ncc_segment_interval_snprint(interval_buf, sizeof(interval_buf), segment));

			switch (segment->type) {
			case NCC_SEGMENT_RATE_FIXED:
				fprintf(fp, ", rate: %.3f", segment->rate_limit);
				break;

			case NCC_SEGMENT_RATE_LINEAR:
				fprintf(fp, ", rate range: (%.3f - %.3f)",
				        segment->rate_limit_range.start, segment->rate_limit_range.end);
				break;

			default:
				break;
			}

			fprintf(fp, "\n");

			i++;
			segment = NCC_DLIST_NEXT(dlist, segment);
		}
	}
}

/**
 * Parse a segment specified from a string.
 * Input format: [<type>:]<start time>;<end time>[;<rate>[;<end rate]]
 */
int ncc_segment_parse(TALLOC_CTX *ctx, ncc_dlist_t *dlist, char const *in)
{
	FN_ARG_CHECK(-1, in);
	FN_ARG_CHECK(-1, in[0] != '\0');

	char const *p = in;
	char const *sep1, *sep2, *sep3, *sep4 = NULL;

	ncc_segment_t *segment = NULL;
	int segment_type = NCC_SEGMENT_RATE_FIXED;
	double start = 0, end = 0;
	double rate = 0, rate_end = 0;
	fr_time_delta_t ftd_start, ftd_end;

	sep1 = strchr(p, ':');
	if (sep1) {
		NCC_TABLE_VALUE_BY_STR(segment_type, segment_types, in, sep1 - p, NCC_SEGMENT_RATE_INVALID);
		if (segment_type == NCC_SEGMENT_RATE_INVALID) {
			fr_strerror_printf("Invalid segment (unknown type): [%s]", in);
			goto error;
		}
		p = sep1 + 1;
	}

	sep2 = strchr(p, ';');
	if (!sep2) {
		fr_strerror_printf("Invalid segment (missing separator): [%s]", in);
		goto error;
	}

	sep3 = strchr(sep2 + 1, ';');

	if (sep3) sep4 = strchr(sep3 + 1, ';');

	if (ncc_value_from_str(&start, FR_TYPE_FLOAT64 | NCC_TYPE_NOT_NEGATIVE, p, sep2 - p) < 0
	   || ncc_value_from_str(&end, FR_TYPE_FLOAT64 | NCC_TYPE_NOT_NEGATIVE, sep2 + 1, sep3 ? sep3 - 1 - sep2 : -1) < 0
	   || (sep3 && ncc_value_from_str(&rate, FR_TYPE_FLOAT64 | NCC_TYPE_NOT_NEGATIVE, sep3 + 1, sep4 ? sep4 - 1 - sep3 : -1) < 0)
	   || (sep4 && ncc_value_from_str(&rate_end, FR_TYPE_FLOAT64 | NCC_TYPE_NOT_NEGATIVE, sep4 + 1, -1) < 0)
	   ) {
		fr_strerror_printf_push("Failed to parse segment [%s]", in);
		goto error;
	}

	ftd_start = ncc_float_to_fr_time(start);
	ftd_end = ncc_float_to_fr_time(end);

	segment = ncc_segment_add(ctx, dlist, ftd_start, ftd_end);
	if (!segment) {
		fr_strerror_printf_push("Failed to add segment");
		goto error;
	}

	segment->type = segment_type;

	switch (segment->type) {
	case NCC_SEGMENT_RATE_FIXED:
		segment->rate_limit = rate;
		break;

	case NCC_SEGMENT_RATE_LINEAR:
		/* A linear rate can only be enforced if we know when the segment will end.
	 	 */
		if (!segment->ftd_end) {
			fr_strerror_printf_push("Segment of type \"%s\" must have a finite end",
			                        fr_table_str_by_value(segment_types, segment->type, "???"));
			goto error;
		}
		segment->rate_limit_range.start = rate;
		segment->rate_limit_range.end = rate_end;
		break;

	default: /* null or unbounded */
		break;
	}

	return 0;

error:
	talloc_free(segment);
	return -1;
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
ncc_segment_t *ncc_segment_add(TALLOC_CTX *ctx, ncc_dlist_t *dlist, fr_time_delta_t ftd_start, fr_time_delta_t ftd_end)
{
	NCC_DLIST_INIT(dlist, ncc_segment_t);

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

	ncc_segment_t *segment_new;

	MEM(segment_new = talloc_zero(ctx, ncc_segment_t));
	segment_new->ftd_start = ftd_start;
	segment_new->ftd_end = ftd_end;

	/* If list is empty, just insert new segment. */
	if (NCC_DLIST_SIZE(dlist) == 0) {
		DEBUG3("Inserting first segment (%.3f - %.3f)",
		       ncc_fr_time_to_float(segment_new->ftd_start), ncc_fr_time_to_float(segment_new->ftd_end));

		NCC_DLIST_ENQUEUE(dlist, segment_new);
		goto finish;
	}

	ncc_segment_t *segment = NCC_DLIST_HEAD(dlist);
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
