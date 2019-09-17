/**
 * @file ncc_util.c
 * @brief General utility functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 */

#include "ncc_util.h"


/*
 *	Peek into an event list to retrieve the timestamp of next event.
 *
 *	Note: structures fr_event_list_t and fr_event_timer_t are opaque, so we have to partially redefine them
 *	so we can access what we need.
 *	(I know, this is dangerous. We'll be fine as long as they do not change.)
 *	Ideally, this should be provided by FreeRADIUS lib. TODO: ask them ?
 */
int ncc_fr_event_timer_peek(fr_event_list_t *fr_el, fr_time_t *when)
{
	ncc_fr_event_list_t *el = (ncc_fr_event_list_t *)fr_el;
	ncc_fr_event_timer_t *ev;

	if (unlikely(!el)) return 0;

	if (fr_heap_num_elements(el->times) == 0) {
		*when = 0;
		return 0;
	}

	ev = fr_heap_peek(el->times);
	if (!ev) {
		*when = 0;
		return 0;
	}

	*when = ev->when;
	return 1;
}


/*
 *	Trace / logging.
 */
FILE *ncc_log_fp = NULL;
fr_time_t fte_ncc_start; /* Program execution start timestamp. */
int ncc_debug_lvl = 0;
fr_thread_local_setup(TALLOC_CTX *, ncc_vlog_pool)
static uint32_t location_indent = 30;
static char spaces[] = "                                                 ";

ncc_log_t ncc_default_log = {
	.timestamp = L_TIMESTAMP_AUTO,
	.basename = true
};
ncc_log_t ncc_multiline_log = {
	.timestamp = L_TIMESTAMP_AUTO,
	.multiline = true,
	.prefix_all = true
};

/**
 * Free the memory pool.
 */
static void _ncc_vlog_pool_free(void *arg)
{
	talloc_free(arg);
	ncc_vlog_pool = NULL;
}

/**
 * Initialize logging.
 */
void ncc_log_init(FILE *log_fp, int debug_lvl)
{
	if (!fte_ncc_start) {
		fte_ncc_start = fr_time();
	}
	ncc_log_fp = log_fp;
	ncc_debug_lvl = debug_lvl;
}

/**
 * Print a log message.
 */
void ncc_vlog_printf(ncc_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, va_list ap)
{
	TALLOC_CTX *pool;
	char const *fmt_location = "";
	char fmt_time[NCC_DATETIME_STRLEN];
	char const *fmt_facility = "";
	char *fmt_msg;

	fmt_time[0] = '\0';

	/*
	 * Use a memory pool to avoid constantly rellocating memory on the heap.
	 */
	pool = ncc_vlog_pool;
	if (!pool) {
		pool = talloc_pool(NULL, 4096);
		if (!pool) {
			fr_perror("Failed allocating memory pool");
			exit(EXIT_FAILURE);
		}
		fr_thread_local_set_destructor(ncc_vlog_pool, _ncc_vlog_pool_free, pool);
	}

	/* Only for Debug: allow to print file/line number. */
	if (type == L_DBG) {
		if (log->line_number) {
			char const *filename = file;
			size_t len;
			int	pad = 0;
			char *str;

			if (log->basename) {
				/* file is __FILE__ which is set at build time by gcc.
				 * e.g. src/modules/proto_dhcpv4/dhcperfcli.c
				 * Extract the file base name to have leaner traces.
				 */
				char *p = strrchr(file, FR_DIR_SEP);
				if (p) filename = p + 1;
			}

			str = talloc_asprintf(pool, " )%s:%i", filename, line);
			len = talloc_array_length(str) - 1;

			/*
			 *	Only increase the indent
			 */
			if (len > location_indent) {
				location_indent = len;
			} else {
				pad = location_indent - len;
			}

			fmt_location = talloc_asprintf_append_buffer(str, "%.*s: ", pad, spaces);
		}
	}

	/* Absolute date/time. */
	if (log->timestamp == L_TIMESTAMP_ON) {
		ncc_absolute_time_snprint(fmt_time, sizeof(fmt_time), NCC_DATETIME_FMT);
	}

	/* Facility, e.g. "Error : " for L_ERR. */
	if (type) {
		fmt_facility = fr_table_str_by_value(fr_log_levels, type, ": ");
	}

	fmt_msg = fr_vasprintf(pool, fmt, ap);

	fprintf(ncc_log_fp,
			"%s"	/* location */
			"%s"	/* time */
			"%s"	/* time sep */
			"%s"	/* facility */
			"%s"	/* message */
			"\n",
			fmt_location,
			fmt_time,
			fmt_time[0] ? " " : "",
			fmt_facility,
			fmt_msg
		);

	talloc_free(fmt_msg);
}
void ncc_log_printf(ncc_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, ...)
{
	va_list ap;

	if (!ncc_log_fp || !fmt) return;

	va_start(ap, fmt);
	ncc_vlog_printf(log, type, file, line, fmt, ap);
	va_end(ap);
}

/**
 * Print a log message and also pop all stacked FreeRADIUS error messages.
 */
int ncc_vlog_perror(ncc_log_t const *log, char const *fmt, va_list ap)
{
	char *tmp = NULL;
	char const *strerror;

	strerror = fr_strerror_pop();
	if (!strerror) {
		if (!fmt) return 0; /* No "fmt" and no error stack. */

		ncc_vlog_printf(log, 0, NULL, 0, fmt, ap);
		return 0;
	}

	/* If we have "fmt", use it as prefix. */
	if (fmt) {
		tmp = talloc_vasprintf(NULL, fmt, ap);
	}

	if (log->multiline) {
		/*
		 * Print the first error.
		 * If we have "fmt", concatenate it with the first error.
		 */
		if (fmt) {
			ncc_log_printf(log, 0, NULL, 0, "%s: %s", tmp, strerror);
		} else {
			ncc_log_printf(log, 0, NULL, 0, "%s", strerror);
		}

		/*
		 * Then print all other errors (without the "fmt" prefix) on separate lines.
		 */
		while ((strerror = fr_strerror_pop())) {
			if (fmt && log->prefix_all) {
				/* Repeat the prefix on each line - it is useful for aligned errors.
				 * (cf. fr_canonicalize_error)
				 */
				ncc_log_printf(log, 0, NULL, 0, "%s: %s", tmp, strerror);
			} else {
				ncc_log_printf(log, 0, NULL, 0, "%s", strerror);
			}
		}

	} else {
		/*
		 * Append all errors on the same line, separated with ": ".
		 */
		while (strerror) {
			tmp = talloc_asprintf_append(tmp, "%s%s", (tmp ? ": " : ""), strerror);
			strerror = fr_strerror_pop();
		}

		ncc_log_printf(log, 0, NULL, 0, "%s", tmp);
	}

	if (tmp) talloc_free(tmp);
	return 0;
}
void ncc_log_perror(ncc_log_t const *log, char const *fmt, ...)
{
	va_list ap;

	if (!ncc_log_fp) return;

	va_start(ap, fmt);
	ncc_vlog_perror(log, fmt, ap);
	va_end(ap);
}

/*
 *	Print a debug log message.
 *	Add extra information (file, line) if developper print is enabled.
 *
 *	(ref: function fr_proto_print from lib/util/proto.c)
 */
static unsigned int dev_log_indent = 30;
void ncc_log_dev_printf(ncc_log_t const *log, char const *file, int line, char const *fmt, ...)
{
	va_list ap;
	size_t len;
	char prefix[256];
	char const *filename = file;

	va_start(ap, fmt);
	if (!ncc_log_fp) {
		va_end(ap);
		return;
	}

	if (log->line_number) {
		if (log->basename) {
			/* file is __FILE__ which is set at build time by gcc.
			 * e.g. src/modules/proto_dhcpv4/dhcperfcli.c
			 * Extract the file base name to have leaner traces.
			 */
			char *p = strrchr(file, FR_DIR_SEP);
			if (p) filename = p + 1;
		}

		len = snprintf(prefix, sizeof(prefix), " )%s:%i", filename, line);
		if (len > dev_log_indent) dev_log_indent = len;

		fprintf(ncc_log_fp, "%s%.*s: ", prefix, (int)(dev_log_indent - len), spaces);

		/* Print elapsed time. */
		char time_buf[NCC_TIME_STRLEN];
		fprintf(ncc_log_fp, "t(%s) ",
		        ncc_fr_delta_time_sprint(time_buf, &fte_ncc_start, NULL, (ncc_debug_lvl >= 4) ? 6 : 3));

	} else {
		/* Print absolute date/time. */
		if (log->timestamp == L_TIMESTAMP_ON) {
			char datetime_buf[NCC_DATETIME_STRLEN];
			fprintf(ncc_log_fp, "%s ", ncc_absolute_time_snprint(datetime_buf, sizeof(datetime_buf), NCC_DATETIME_FMT));
		}
	}

	/* And then the actual log message. */
	vfprintf(ncc_log_fp, fmt, ap);
	va_end(ap);

	fprintf(ncc_log_fp, "\n");
	fflush(ncc_log_fp);
}

/*
 *	Provide our own version of "vlog_request" so we can handle FreeRADIUS "REQUEST" logs.
 */
void ncc_vlog_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
		  char const *file, int line,
		  char const *fmt, va_list ap, void *uctx)
{
	/* We want L_DBG_ERR even if debugging is not enabled. */
	if (!(type == L_DBG_ERR) && lvl > request->log.lvl) return;

	//ncc_vlog_printf(&ncc_default_log, 0, fmt, ap);

	/* Expand the log message and push it back to fr_strerror_printf. */
	if (fmt) {
		char buf[256];

		/* Using va_copy is necessary because FreeRADIUS may use the same va_list more than once
		 * (to call multiple logging functions). See function log_request (src/lib/server/log.c).
		 *
		 * This has nothing to do with Julio Merino's dubious explanation.
		 * It is perfectly safe to pass around a va_list between functions, as long as it is used only once.
		 */
		va_list aq;
		va_copy(aq, ap);
		vsnprintf(buf, sizeof(buf), fmt, ap);
		va_end(aq);

		fr_strerror_printf_push(buf);
	}
}


/*
 *	Wrapper to fr_pair_find_by_da, which just returns NULL if we don't have the dictionary attr.
 */
// now redundant with fr_pair_find_by_da: TODO: remove this.
VALUE_PAIR *ncc_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da)
{
	if (!da) return NULL;
	return fr_pair_find_by_da(head, da, TAG_ANY);
}

/*
 *	Create a value pair and add it to a list of value pairs.
 *	This is a copy of (now defunct) FreeRADIUS function radius_pair_create (from src/main/pair.c)
 */
VALUE_PAIR *ncc_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			                unsigned int attribute, unsigned int vendor)
{
	VALUE_PAIR *vp;

	MEM(vp = fr_pair_afrom_num(ctx, vendor, attribute));
	if (vps) fr_pair_add(vps, vp);

	return vp;
}

/*
 *	Create a value pair from a dictionary attribute, and add it to a list of value pairs.
 */
VALUE_PAIR *ncc_pair_create_by_da(TALLOC_CTX *ctx, VALUE_PAIR **vps, fr_dict_attr_t const *da)
{
	VALUE_PAIR *vp;

	FN_ARG_CHECK(NULL, da);

	MEM(vp = fr_pair_afrom_da(ctx, da));
	if (vps) fr_pair_add(vps, vp);

	return vp;
}

/*
 *	Copy the value from a pair to another, and the type also (e.g. VT_DATA).
 */
int ncc_pair_copy_value(VALUE_PAIR *to, VALUE_PAIR *from)
{
	to->type = from->type;
	return fr_value_box_copy(to, &to->data, &from->data);
}

/*
 *	Set value of a pair (of any data type) from a string.
 *	If the conversion is not possible, an error will be returned.
 */
int ncc_pair_value_from_str(VALUE_PAIR *vp, char const *value)
{
	fr_type_t type = vp->da->type;

	vp->type = VT_DATA;
	return fr_value_box_from_str(vp, &vp->data, &type, NULL, value, strlen(value), '\0', false);
}

/*
 *	Copy a single VP.
 *	(FreeRADIUS's fr_pair_copy, altered to work with pre-compiled xlat)
 */
VALUE_PAIR *ncc_pair_copy(TALLOC_CTX *ctx, VALUE_PAIR const *vp)
{
	VALUE_PAIR *n;

	if (!vp) return NULL;

	VP_VERIFY(vp);

	n = fr_pair_afrom_da(ctx, vp->da);
	if (!n) return NULL;

	n->op = vp->op;
	n->tag = vp->tag;
	n->next = NULL;
	n->type = vp->type;

	/*
	 *	Copy the unknown attribute hierarchy
	 */
	if (n->da->flags.is_unknown) {
		n->da = fr_dict_unknown_acopy(n, n->da);
		if (!n->da) {
			talloc_free(n);
			return NULL;
		}
	}

	/*
	 *	If it's an xlat, copy the raw string and return
	 *	early, so we don't pre-expand or otherwise mangle
	 *	the VALUE_PAIR.
	 */
	if (vp->type == VT_XLAT) {
		n->xlat = talloc_typed_strdup(n, vp->xlat);
		n->vp_ptr = vp->vp_ptr; /* This stores the compiled xlat .*/
		return n;
	}
	fr_value_box_copy(n, &n->data, &vp->data);

	return n;
}

/*
 *	Copy a list of VP.
 *	(FreeRADIUS's fr_pair_list_copy, altered to work with pre-compiled xlat)
 */
int ncc_pair_list_copy(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from)
{
	fr_cursor_t	src, dst, tmp;

	VALUE_PAIR	*head = NULL;
	VALUE_PAIR	*vp;
	int		cnt = 0;

	fr_cursor_talloc_init(&tmp, &head, VALUE_PAIR);
	for (vp = fr_cursor_talloc_init(&src, &from, VALUE_PAIR);
	     vp;
	     vp = fr_cursor_next(&src), cnt++) {
		VP_VERIFY(vp);
		vp = ncc_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&head);
			return -1;
		}
		fr_cursor_append(&tmp, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	if (!*to) {	/* Fast Path */
		*to = head;
	} else {
		fr_cursor_talloc_init(&dst, to, VALUE_PAIR);
		fr_cursor_head(&tmp);
		fr_cursor_merge(&dst, &tmp);
	}

	return cnt;
}

/*
 *	Append a list of VP. (inspired from FreeRADIUS's fr_pair_list_copy.)
 *	Note: contrary to fr_pair_list_copy, this preserves the order of the value pairs.
 */
VALUE_PAIR *ncc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from)
{
	vp_cursor_t src, dst;

	if (*to == NULL) { /* fall back to fr_pair_list_copy for a new list. */
		MEM(ncc_pair_list_copy(ctx, to, from) >= 0);
		return (*to);
	}

	VALUE_PAIR *out = *to, *vp;

	fr_pair_cursor_init(&dst, &out);
	for (vp = fr_pair_cursor_init(&src, &from);
	     vp;
	     vp = fr_pair_cursor_next(&src)) {
		VP_VERIFY(vp);
		vp = ncc_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&out);
			return NULL;
		}
		fr_pair_cursor_append(&dst, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	return *to;
}

/*
 *	Print a list of VP.
 */
void ncc_pair_list_fprint(FILE *fp, VALUE_PAIR *vps)
{
	VALUE_PAIR *vp;
	fr_cursor_t cursor;
	char buf[4096];

	/* Iterate on the value pairs of the list. */
	int i = 0;
	for (vp = fr_cursor_init(&cursor, &vps); vp; vp = fr_cursor_next(&cursor)) {
		ncc_pair_snprint(buf, sizeof(buf), vp);
		fprintf(fp, "  #%u %s\n", i, buf);
		i++;
	}
}

/*
 *	Print one attribute and value to a string.
 *	Similar to FreeRADIUS fr_pair_snprint, but prints 'x' for XLAT, '=' for DATA instead of the operator.
 *	Also, we don't handle tags here.
 */
size_t ncc_pair_snprint(char *out, size_t outlen, VALUE_PAIR const *vp)
{
	char const *token = NULL;
	size_t len, freespace = outlen;

	if (!out) return 0;

	*out = '\0';
	if (!vp || !vp->da) return 0;

	VP_VERIFY(vp);

	if (vp->type == VT_XLAT) {
		token = "x";
	} else {
		token = "=";
	}

	len = snprintf(out, freespace, "%s %s ", vp->da->name, token);
	if (is_truncated(len, freespace)) return len;

	out += len;
	freespace -= len;

	len = fr_pair_value_snprint(out, freespace, vp, '"');
	if (is_truncated(len, freespace)) return (outlen - freespace) + len;
	freespace -= len;

	return (outlen - freespace);
}


/**
 * Read a single value from a buffer, and advance the pointer.
 * (Without attribute name and operator.)
 * Inspired from FreeRADIUS function fr_pair_raw_from_str
 *
 * @param[in,out] ptr  pointer to read from and update.
 * @param[out]    raw  the struct to write the raw value to.
 *
 * @return
 * 	T_INVALID = error.
 * 	T_EOL = end of line was encountered.
 * 	the last token read otherwise (should be T_COMMA).
 */
FR_TOKEN ncc_value_raw_from_str(char const **ptr, VALUE_PAIR_RAW *raw)
{
	char const *p;
	FR_TOKEN ret = T_INVALID, next, quote;
	char buf[8];

	FN_ARG_CHECK(T_INVALID, ptr);
	FN_ARG_CHECK(T_INVALID, *ptr);
	FN_ARG_CHECK(T_INVALID, raw);

	/*
	 *	Skip leading spaces
	 */
	p = *ptr;
	while ((*p == ' ') || (*p == '\t')) p++;

	if (!*p) {
		fr_strerror_printf("No token read where we expected a value");
		return T_INVALID;
	}

	/*
	 *	Read value. Note that empty string values are allowed
	 */
	quote = gettoken(ptr, raw->r_opand, sizeof(raw->r_opand), false);
	if (quote == T_EOL) {
		fr_strerror_printf("Failed to get value");
		return T_INVALID;
	}

	/*
	 *	Peek at the next token. Must be T_EOL or T_COMMA
	 */
	p = *ptr;

	next = gettoken(&p, buf, sizeof(buf), false);
	switch (next) {
	case T_EOL:
		break;

	case T_COMMA:
		*ptr = p;
		break;

	default:
		fr_strerror_printf("Expected end of line or comma");
		return T_INVALID;
	}
	ret = next;

	switch (quote) {
	case T_DOUBLE_QUOTED_STRING:
		raw->quote = T_SINGLE_QUOTED_STRING; /* xlat expansion is not handled here, so report as single quoted. */
		break;

	case T_SINGLE_QUOTED_STRING:
	case T_BACK_QUOTED_STRING:
	case T_BARE_WORD:
		raw->quote = quote;
		break;

	default:
		fr_strerror_printf("Failed to parse string");
		return T_INVALID;
	}

	return ret;
}

/*
 *	Read one line of values into a list.
 *	The line may specify multiple values separated by commas.
 *	All VP's are created using the same (provided) dictionary attribute.
 *	Inspired from FreeRADIUS function fr_pair_list_afrom_str.
 */
FR_TOKEN ncc_value_list_afrom_str(TALLOC_CTX *ctx, fr_dict_attr_t const *da, char const *buffer, VALUE_PAIR **list)
{
	VALUE_PAIR *vp, *head, **tail;
	char const *p;
	FR_TOKEN last_token = T_INVALID;
	VALUE_PAIR_RAW raw;

	FN_ARG_CHECK(T_INVALID, buffer);

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0) {
		return T_EOL;
	}

	head = NULL;
	tail = &head;

	p = buffer;
	do {
		raw.l_opand[0] = '\0';
		raw.r_opand[0] = '\0';

		last_token = ncc_value_raw_from_str(&p, &raw);

		if (last_token == T_INVALID) break;

		//vp = fr_pair_make(ctx, dict, NULL, raw.l_opand, NULL, raw.op);
		// instead, create a vp with the fixed dictionary attribute, and value read.
		vp = ncc_pair_create_by_da(ctx, NULL, da);
		if (!vp) {
		invalid:
			last_token = T_INVALID;
			break;
		}

		/* Parse the value (and mark it as 'tainted'). */
		if (fr_pair_value_from_str(vp, raw.r_opand, -1, '"', true) < 0) {
			talloc_free(vp);
			goto invalid;
		}

		*tail = vp;
		tail = &((*tail)->next);
	} while (*p && (last_token == T_COMMA));

	if (last_token == T_INVALID) {
		fr_pair_list_free(&head);
	} else {
		fr_pair_add(list, head);
	}

	/*
	 *	And return the last token which we read.
	 */
	return last_token;
}

/*
 *	Read values from one line using the fp.
 *	Inspired from FreeRADIUS function fr_pair_list_afrom_file.
 */
int ncc_value_list_afrom_file(TALLOC_CTX *ctx, fr_dict_attr_t const *da, VALUE_PAIR **out, FILE *fp, uint32_t *line, bool *pfiledone)
{
	char buf[8192];
	FR_TOKEN last_token = T_EOL;

	fr_cursor_t cursor;

	VALUE_PAIR *vp = NULL;
	fr_cursor_init(&cursor, out);

	if (fgets(buf, sizeof(buf), fp) == NULL) {
		*pfiledone = true;
		goto done;
	}
	(*line)++;

	/*
	 * Read all of the values on the current line.
	 */
	vp = NULL;
	last_token = ncc_value_list_afrom_str(ctx, da, buf, &vp);
	if (!vp) {
		if (last_token != T_EOL) goto error;
		goto done;
	}

	VALUE_PAIR *next;
	do {
		next = vp->next;
		fr_cursor_append(&cursor, vp);
	} while (next && (vp = next));

	buf[0] = '\0';

done:
	return 0;

error:
	vp = fr_cursor_head(&cursor);
	if (vp) fr_pair_list_free(&vp);
	*out = NULL;
	return -1;
}


/**
 * Print to a string buffer the hexadecimal representation of a data buffer.
 *
 * @param[out] out           where to write the hexadecimal representation of data.
 * @param[in]  outlen        size of output buffer.
 * @param[in]  in            binary data to print.
 * @param[in]  in_len        how many octets of data we want to print.
 * @param[in]  sep           optional separator string (typically one space) printed between two octets.
 * @param[in]  prefix        optional prefix string printed at the start of the first output line.
 * @param[in]  line_max_len  start on a new output line after this many octets.
 *
 * @return pointer to the output buffer, or NULL on error.
 */
char *ncc_hex_data_snprint(char *out, size_t outlen, const uint8_t *in, int in_len, char const *sep,
                           char const *prefix, int line_max_len)
{
	int i;
	int k = 0; /* Position in the current line. */
	int prefix_len = 0, sep_len = 0;
	int num_line;
	ssize_t needed;

	FN_ARG_CHECK(NULL, out);
	FN_ARG_CHECK(NULL, outlen > 0);
	FN_ARG_CHECK(NULL, line_max_len > 0);

	*out = '\0';
	if (!in || in_len <= 0) return out; /* Nothing to print. */

	if (sep) sep_len = strlen(sep);

	if (prefix) {
		prefix_len = strlen(prefix);
		out += sprintf(out, "%s", prefix);
	}

	/* Compute needed space, ensure we have enough. */
	num_line = (in_len - 1) / line_max_len + 1;

	needed = (num_line * prefix_len) /* prefix len for each line */
		+ (num_line - 1) /* "\n" between lines */
		+ (2 * in_len) /* each printed octet */
		+ 1; /* terminating \0 */

	/* Account for separators space between each octet, except at end of each line. */
	needed += (sep_len * (in_len - 1 - (num_line - 1)));

	DEBUG_TRACE("outlen: %zu, in_len: %zu, num_line: %u, prefix_len: %u, needed: %zu\n",
	            outlen, in_len, num_line, prefix_len, needed);

	CHECK_BUFFER_SIZE(NULL, needed, outlen, "output");

	for (i = 0; i < in_len; i++) {
		if (line_max_len && (k == line_max_len)) { /* Start a new line. */
			out += sprintf(out, "\n%*s", prefix_len, "");
			k = 0;
		}
		if (k && sep) {
			out += sprintf(out, "%s", sep);
		}
		out += sprintf(out, "%02x", in[i]);
		k++;
	}
	*out = '\0';
	return out;
}

/**
 * Print to file the hexadecimal representation of a data buffer.
 *
 * @param[out] fp            where to write the hexadecimal representation of data.
 * @param[in]  in            binary data to print.
 * @param[in]  in_len        how many octets of data we want to print.
 * @param[in]  sep           optional separator string (typically one space) printed between two octets.
 * @param[in]  line_max_len  start on a new output line after this many octets.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_hex_data_fprint(FILE *fp, const uint8_t *in, int in_len, char const *sep,
                        int line_max_len)
{
	const uint8_t *p = in;
	char buf[385];
	/* Allows for lines of up to 128 octets, with one char separator.
	 * Typically we will want 16 octets printed per line so this should be more than enough.
	 */

	if (!in || in_len <= 0) return 0; /* Nothing to print. */

	while (in_len > 0) {
		int len = (in_len > line_max_len ? line_max_len : in_len);
		if (!ncc_hex_data_snprint(buf, sizeof(buf), p, len, sep, "", line_max_len)) {
			return -1;
		}

		fprintf(fp, "%04x: %s\n", (int)(p - in), buf);
		in_len -= len;
		p += len;
	}

	return 0;
}


/**
 * Print to a string buffer an endpoint: <IP>:<port>.
 *
 * @param[out] out  where to write the output string.
 * @param[in]  ep   pointer on endpoint to write.
 *
 * @return pointer to the output buffer, or NULL on error.
 */
char *ncc_endpoint_sprint(char *out, ncc_endpoint_t *ep)
{
	FN_ARG_CHECK(NULL, out);

	char ipaddr_buf[FR_IPADDR_STRLEN];
	if (!fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf), &ep->ipaddr)) return NULL;

	sprintf(out, "%s:%u", ipaddr_buf, ep->port);
	return out;
}

/**
 * Print to a string buffer an ethernet address.
 *
 * @param[out] out  where to write the output string (size must be at least NCC_ETHADDR_STRLEN).
 * @param[in]  ep   pointer on buffer which contains the 6 octets of the ethernet address.
 *
 * @return pointer to the output buffer.
 */
char *ncc_ether_addr_sprint(char *out, const uint8_t *addr)
{
	FN_ARG_CHECK(NULL, out);
	FN_ARG_CHECK(NULL, addr);

	sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
	        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return out;
}


/*
 *	Print a difference between two timestamps (pre-parsed as hour / min / sec / usec).
 */
static void _ncc_delta_time_sprint(char *out, uint8_t decimals, uint32_t hour, uint32_t min, uint32_t sec, uint32_t usec)
{
	if (hour > 0) {
		sprintf(out, "%u:%.02u:%.02u", hour, min, sec);
	} else if (min > 0) {
		sprintf(out, "%u:%.02u", min, sec);
	} else {
		sprintf(out, "%u", sec);
	}

	if (decimals) {
		char buffer[8];
		sprintf(buffer, ".%06u", usec);
		strncat(out, buffer, decimals + 1); /* (always terminated with '\0'). */
	}
}

/**
 * Print to a string buffer a difference between two timestamps (struct timeval).
 * Output format: [[<HH>:]<MI>:]<SS>[.<d{1,6}>]
 *
 * @param[out] out       where to write the output string.
 *                       (size should be at least NCC_TIME_STRLEN, which is sufficient for HH < 100 with 6 decimals)
 * @param[in]  from      pointer on oldest timestamp.
 * @param[in]  when      pointer on most recent timestamp (or NULL to use current time).
 * @param[in]  decimals  number of decimals to print in output (0-6).
 *
 * @return pointer to the output buffer.
 */
char *ncc_delta_time_sprint(char *out, struct timeval *from, struct timeval *when, uint8_t decimals)
{
	struct timeval delta, to;
	uint32_t hour, min, sec, usec;

	FN_ARG_CHECK(NULL, out);
	FN_ARG_CHECK(NULL, from);

	if (when && timercmp(when, from, <)) {
		fr_strerror_printf("Cannot have a negative time difference");
		return NULL;
	}

	/* If second timestamp is not specified, use current time. */
	if (!when) {
		gettimeofday(&to, NULL);
		when = &to;
	}

	timersub(when, from, &delta); /* delta = when - from */

	hour = (uint32_t)(delta.tv_sec / 3600);
	min = (uint32_t)(delta.tv_sec % 3600) / 60;
	sec = (uint32_t)(delta.tv_sec % 3600) % 60;
	usec = delta.tv_usec;

	_ncc_delta_time_sprint(out, decimals, hour, min, sec, usec);
	return out;
}

/**
 * Print to a string buffer a difference between two timestamps (fr_time_t).
 * Output format: [[<HH>:]<MI>:]<SS>[.<d{1,6}>]
 *
 * @param[out] out       where to write the output string.
 *                       (size should be at least NCC_TIME_STRLEN, which is sufficient for HH < 100 with 6 decimals)
 * @param[in]  from      pointer on oldest timestamp.
 * @param[in]  when      pointer on most recent timestamp (or NULL to use current time).
 * @param[in]  decimals  number of decimals to print in output (0-6).
 *
 * @return pointer to the output buffer.
 */
char *ncc_fr_delta_time_sprint(char *out, fr_time_t *from, fr_time_t *when, uint8_t decimals)
{
	fr_time_t to;
	fr_time_delta_t delta;
	uint32_t delta_sec, hour, min, sec, usec;

	FN_ARG_CHECK(NULL, out);
	FN_ARG_CHECK(NULL, from);

	if (when && *when < *from) {
		fr_strerror_printf("Cannot have a negative time difference");
		return NULL;
	}

	/* If second timestamp is not specified, use current time. */
	if (!when) {
		to = fr_time();
		when = &to;
	}

	delta = *when - *from;
	delta_sec = delta / NSEC;

	hour = delta_sec / 3600;
	min = (delta_sec % 3600) / 60;
	sec = (delta_sec % 3600) % 60;
	usec = (delta / 1000) % USEC;

	_ncc_delta_time_sprint(out, decimals, hour, min, sec, usec);
	return out;
}

/** Print to a string buffer the current absolute date/time, with specified format for strftime.
 *
 * @param[out] out       where to write the output string.
 * @param[in]  outlen    size of output buffer, which should be consistent with the specified time format.
 *                       NCC_DATETIME_STRLEN is sufficient for NCC_DATE_FMT, NCC_TIME_FMT, and NCC_DATETIME_FMT.
 * @param[in]  fmt       time format for strftime.
 *
 * @return pointer to the output buffer, or NULL on error.
 */

char *ncc_absolute_time_snprint(char *out, size_t outlen, const char *fmt)
{
	time_t date;
	struct tm tminfo;

	FN_ARG_CHECK(NULL, out);

	time(&date);
	if (localtime_r(&date, &tminfo) == NULL || strftime(out, outlen, fmt, &tminfo) == 0) {
		fr_strerror_printf("Failed to format current date and time");
		return NULL;
	}

	return out;
}


/**
 * Parse host address and port from a string: <addr>:<port>.
 * <addr> can be an IPv4 address, or a hostname to resolve.
 * Either address or port can be omitted (at least one must be provided), in which
 * case the input default is retained.
 *
 * @param[out] ep        output endpoint.
 * @param[in]  host_arg  string to parse with host adress and port.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_host_addr_resolve(ncc_endpoint_t *ep, char const *host_arg)
{
	FN_ARG_CHECK(-1, ep);
	FN_ARG_CHECK(-1, host_arg);

	unsigned long port;
	uint16_t port_fr;
	char const *p = host_arg, *q;

	/*
	 *	Allow to just have [:]<port> (no host address specified).
	 */
	if (*p == ':') p++; /* Port start */
	q = p;
	while (*q  != '\0') {
		if (!isdigit(*q)) break;
		q++;
	}
	if (q != p && *q == '\0') { /* Only digits (at least one): assume this is a port number. */
		port = strtoul(p, NULL, 10);
		if ((port > UINT16_MAX) || (port == 0)) {
			fr_strerror_printf("Port %lu outside valid port range 1-%u", port, UINT16_MAX);
			return -1;
		}
		ep->port = port;
		return 0;
	}

	/*
	 *	Otherwise delegate parsing to fr_inet_pton_port.
	 */
	if (fr_inet_pton_port(&ep->ipaddr, &port_fr, host_arg, -1, AF_INET, true, true) < 0) {
		return -1;
	}

	if (port_fr != 0) { /* If a port is specified, use it. Otherwise, keep default input value. */
		ep->port = port_fr;
	}

	return 0;
}

/**
 * Parse a uint64 value from a string.
 * Wrapper to fr_strtoull (which in turn is a wrapper to strtoull), with restrictions:
 * - Ensure the provided input is not a negative value (strtoull dubiously allows this).
 * - Check we don't have trailing garbage at the end of the input string (whitespace is allowed).
 *
 * @param[out] out    where to write the parsed value.
 * @param[in]  value  string which contains the value to parse.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_strtoull(uint64_t *out, char const *value)
{
	char *p = NULL;

	fr_skip_whitespace(value);

	if (*value == '-') { /* Don't let strtoull happily process negative values. */
	error:
		fr_strerror_printf("Invalid value \"%s\" for unsigned integer", value);
		return -1;
	}

	if (fr_strtoull(out, &p, value) < 0) return -1;
	if (*p != '\0' && !is_whitespace(p)) goto error;

	return 0;
}

/**
 * Parse a int64 value from a string.
 * Wrapper to fr_strtoll (which in turn is a wrapper to strtoll), with restrictions:
 * - Check we don't have trailing garbage at the end of the input string (whitespace is allowed).
 *
 * @param[out] out    where to write the parsed value.
 * @param[in]  value  string which contains the value to parse.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_strtoll(int64_t *out, char const *value)
{
	char *p = NULL;

	if (fr_strtoll(out, &p, value) < 0) return -1;
	if (*p != '\0' && !is_whitespace(p)) {
		fr_strerror_printf("Invalid value \"%s\" for integer", value);
		return -1;
	}
	return 0;
}

/**
 * Parse a float32 (float) value from a string.
 * Wrapper to strtof, with restrictions:
 * - Don't allow hex (confusing for floating point numbers).
 * - Check we don't have trailing garbage at the end of the input string.
 * - Don't allow "NaN" or "Infinity".
 *
 * @param[out] out    where to write the parsed value.
 * @param[in]  value  string which contains the value to parse.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_strtof(float *out, char const *value)
{
	char *p = NULL;

	fr_skip_whitespace(value);

	if ((value[0] == '0') && (value[1] == 'x' || value[1] == 'X')) {
	error:
		fr_strerror_printf("Invalid value \"%s\" for floating point number", value);
		return -1;
	}

	*out = strtof(value, &p);
	if (*p != '\0' && !is_whitespace(p)) goto error;

	/* Do not allow "NaN" or "Infinity" */
	if (!isfinite(*out)) goto error;

	return 0;
}

/**
 * Parse a float64 (double) value from a string.
 * Wrapper to strtod, with restrictions:
 * - Don't allow hex (confusing for floating point numbers).
 * - Check we don't have trailing garbage at the end of the input string.
 * - Don't allow "NaN" or "Infinity".
 *
 * @param[out] out    where to write the parsed value.
 * @param[in]  value  string which contains the value to parse.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_strtod(double *out, char const *value)
{
	char *p = NULL;

	fr_skip_whitespace(value);

	if ((value[0] == '0') && (value[1] == 'x' || value[1] == 'X')) {
	error:
		fr_strerror_printf("Invalid value \"%s\" for floating point number", value);
		return -1;
	}

	*out = strtod(value, &p);
	if (*p != '\0' && !is_whitespace(p)) goto error;

	/* Do not allow "NaN" or "Infinity" */
	if (!isfinite(*out)) goto error;

	return 0;
}

/**
 * Parse a boolean value from a string.
 * Allow yes/no, true/false, and on/off.
 *
 * @param[out] out    where to write the parsed value.
 * @param[in]  value  string which contains the value to parse.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_strtobool(bool *out, char const *value)
{
	fr_skip_whitespace(value);

	char const *end = ncc_strr_notspace(value, -1);
	if (!end) goto error;
	size_t len = end - value + 1;

	if (   (strncasecmp(value, "yes", len) == 0)
	    || (strncasecmp(value, "true", len) == 0)
	    || (strncasecmp(value, "on", len) == 0) ) {
		*(bool *)out = true;
		return 0;
	}

	if (   (strncasecmp(value, "no", len) == 0)
	    || (strncasecmp(value, "false", len) == 0)
	    || (strncasecmp(value, "off", len) == 0) ) {
		*(bool *)out = false;
		return 0;
	}

error:
	fr_strerror_printf("Invalid value \"%s\" for boolean", value);
	return -1;
}


/**
 * Parse a string value into a given FreeRADIUS data type (FR_TYPE_...).
 * Check that value is valid for the data type, and obtain converted value.
 *
 * Note: not all FreeRADIUS types are supported.
 *
 * @param[out] out    where to write the parsed value (size depends on the type).
 *                    NULL allows to discard output (validity check only).
 * @param[in]  type   type of value being parsed (base type | optional qualifiers).
 * @param[in]  value  string which contains the value to parse.
 * @param[in]  inlen  length of value, if value is \0 terminated inlen may be -1.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_value_from_str(void *out, uint32_t type, char const *value, ssize_t inlen)
{
	bool not_empty, not_negative, not_zero;
	uint64_t uinteger = 0;
	int64_t sinteger = 0;
	char buffer[4096];

	if (!value) return -1;

	/*
	 *	Copy to intermediary buffer if we were given a length
	 */
	if (inlen >= 0) {
		if (inlen >= (ssize_t)sizeof(buffer)) {
			fr_strerror_printf("Value is too long for parsing");
			return -1;
		}
		memcpy(buffer, value, inlen);
		buffer[inlen] = '\0';
		value = buffer;
	}

	fr_skip_whitespace(value);

	/* Get last non whitespace character and according value length. */
	char const *end = ncc_strr_notspace(value, -1);
	ssize_t len = end ? (end - value + 1) : 0;

	/* Optional qualifiers. */
	not_empty = (type & NCC_TYPE_NOT_EMPTY);
	not_negative = (type & NCC_TYPE_NOT_NEGATIVE);
	not_zero = (type & NCC_TYPE_NOT_ZERO);

	type = FR_BASE_TYPE(type);

	/*
	 *	Check for zero length strings
	 */
	if ((value[0] == '\0') && not_empty) {
		fr_strerror_printf("Value cannot be empty");
		return -1;
	}

#define INVALID_TYPE_VALUE \
	do { \
		fr_strerror_printf("Invalid value \"%s\" for type '%s'", value, \
			fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>")); \
		return -1; \
	} while (0)

#define IN_RANGE_UNSIGNED(_type) \
	do { \
		if (uinteger > _type ## _MAX) { \
			fr_strerror_printf("Invalid value %" PRIu64 " for type '%s' (allowed range: " \
					   "0..%" PRIu64 ")", \
					   uinteger, fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"), \
					   (uint64_t) _type ## _MAX); \
			return -1; \
		} \
	} while (0)

#define IN_RANGE_SIGNED(_type) \
	do { \
		if ((sinteger > _type ## _MAX) || (sinteger < _type ## _MIN)) { \
			fr_strerror_printf("Invalid value %" PRId64 " for type '%s' (allowed range: " \
					   "%" PRId64 "..%" PRId64 ")", \
					   sinteger, fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>"), \
					   (int64_t) _type ## _MIN, (int64_t) _type ## _MAX); \
			return -1; \
		} \
	} while (0)

#define CHECK_NOT_ZERO(_v) \
		if (not_zero && _v == 0) { \
			fr_strerror_printf("Value cannot be zero"); \
			return -1; \
		}

#define CHECK_NOT_NEGATIVE(_v) \
		if (not_negative && _v < 0) { \
			fr_strerror_printf("Value cannot be negative"); \
			return -1; \
		}

	/*
	 *	First pass for integers.
	 */
	switch (type) {
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
		/*
		 *	Function checks for overflows and trailing garbage, and calls fr_strerror_printf to set an error.
		 */
		if (ncc_strtoull(&uinteger, value) < 0) return -1;

		CHECK_NOT_ZERO(uinteger);
		break;

	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
		/*
		 *	Function checks for overflows and trailing garbage, and calls fr_strerror_printf to set an error.
		 */
		if (ncc_strtoll(&sinteger, value) < 0) return -1;

		CHECK_NOT_ZERO(sinteger);
		CHECK_NOT_NEGATIVE(sinteger);
		break;

	default:
		/* Non-integers are not handled here. */
		break;
	}

	/*
	 *	Second pass for all. Integers are already parsed and now just need assignment.
	 */
	switch (type) {
	case FR_TYPE_BOOL:
	{
		bool v;
		if (ncc_strtobool(&v, value) < 0) return -1;
		if (out) *(bool *)out = v;
	}
		break;

	case FR_TYPE_FLOAT32:
	{
		float v;
		if (ncc_strtof(&v, value) < 0) return -1;
		CHECK_NOT_ZERO(v);
		CHECK_NOT_NEGATIVE(v);
		if (out) *(float *)out = v;
	}
		break;

	case FR_TYPE_FLOAT64:
	{
		double v;
		if (ncc_strtod(&v, value) < 0) return -1;
		CHECK_NOT_ZERO(v);
		CHECK_NOT_NEGATIVE(v);
		if (out) *(double *)out = v;
	}
		break;

	case FR_TYPE_TIME_DELTA:
	{
		/* Allowed formats:
		 * "42.123" (seconds), "42.123s", "42123ms", "50us", "01:30" (min:sec)
		 */
		fr_time_delta_t v;
		if (fr_time_delta_from_str(&v, value, FR_TIME_RES_SEC) < 0) INVALID_TYPE_VALUE;
		if (out) *(fr_time_delta_t *)out = v;
	}
		break;

	case FR_TYPE_IPV4_ADDR:
	{
		fr_ipaddr_t v;
		if (fr_inet_pton4(&v, value, len, false, false, false) < 0) INVALID_TYPE_VALUE;
		if (out) *(fr_ipaddr_t *)out = v;
	}
		break;

	case FR_TYPE_ETHERNET:
	{
		fr_type_t type = FR_TYPE_ETHERNET;
		fr_value_box_t vb = { 0 };
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, value, len, '\0', false) < 0) INVALID_TYPE_VALUE;
		if (out) memcpy(out, &vb.vb_ether, 6);
	}
		break;

	case FR_TYPE_UINT8:
		IN_RANGE_UNSIGNED(UINT8);
		if (out) *(uint8_t *)out = uinteger;
		break;

	case FR_TYPE_UINT16:
		IN_RANGE_UNSIGNED(UINT16);
		if (out) *(uint16_t *)out = uinteger;
		break;

	case FR_TYPE_UINT32:
		IN_RANGE_UNSIGNED(UINT32);
		if (out) *(uint32_t *)out = uinteger;
		break;

	case FR_TYPE_UINT64:
		/* IN_RANGE_UNSIGNED doesn't work here */
		if (out) *(uint64_t *)out = uinteger;
		break;

	case FR_TYPE_INT8:
		IN_RANGE_SIGNED(INT8);
		if (out) *(int8_t *)out = sinteger;
		break;

	case FR_TYPE_INT16:
		IN_RANGE_SIGNED(INT16);
		if (out) *(int16_t *)out = sinteger;
		break;

	case FR_TYPE_INT32:
		IN_RANGE_SIGNED(INT32);
		if (out) *(int32_t *)out = sinteger;
		break;

	case FR_TYPE_INT64:
		IN_RANGE_SIGNED(INT64);
		if (out) *(int64_t *)out = sinteger;
		break;

	default:
		fr_strerror_printf("Invalid type '%s' (%i)",
		                   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type);
		return -1;
	}

	return 0;
}


/*
 *	Convert a struct timeval to float.
 */
double ncc_timeval_to_float(struct timeval *in)
{
	double value = (in->tv_sec + (double)in->tv_usec / USEC);
	return value;
}

/*
 *	Convert a float to struct timeval.
 */
int ncc_float_to_timeval(struct timeval *tv, double in)
{
	/* Boundary check. */
	if (in >= (double)LONG_MAX) {
		ERROR("Cannot convert to timeval: float value %.0f exceeds LONG_MAX (%ld)", in, LONG_MAX);
		return -1;
	}

	tv->tv_sec = (time_t)in;
	tv->tv_usec = (uint64_t)(in * USEC) - (tv->tv_sec * USEC);
	return 0;
}

/*
 *	Convert a fr_time to float.
 */
double ncc_fr_time_to_float(fr_time_delta_t in)
{
	return (double)in / NSEC;
}

/*
 *	Convert a float to fr_time.
 */
fr_time_t ncc_float_to_fr_time(double in)
{
	return (in * NSEC);
}

/*
 *	Check that a string represents a valid floating point number (e.g. 3, 2.5, .542).
 *	If so convert it to float64.
 *	"out" may be NULL, in which case this is just a format check.
 */
bool ncc_str_to_float(double *out, char const *in, bool allow_negative)
{
	double num;
	uint32_t type = FR_TYPE_FLOAT64;
	if (!allow_negative) type |= NCC_TYPE_NOT_NEGATIVE;

	if (ncc_value_from_str(&num, type, in, -1) < 0) return false;

	if (out) *out = num;
	return true;
}

/* Wrapper to ncc_str_to_float, using float32 instead of float64 */
bool ncc_str_to_float32(float *out, char const *in, bool allow_negative)
{
	double num;
	bool ret = ncc_str_to_float(&num, in, allow_negative);

	if (out && ret) *out = num;
	return ret;
}

/*
 *	Trim a string from spaces (left and right), while complying with an input length limit.
 *	Output buffer must be large enough to store the resulting string.
 *	Returns the number of characters printed, excluding the terminating '\0'.
 */
size_t ncc_str_trim(char *out, char const *in, size_t inlen)
{
	if (inlen == 0) {
		*out = '\0';
		return 0;
	}

	char const *p = in;
	char const *end = in + inlen - 1; /* Last character. */
	size_t outsize;

	/* Look for the first non-space character. */
	while (p <= end && isspace(*p)) p++;
	if (p > end || *p == '\0') { /* Only spaces. */
		*out = '\0';
		return 0;
	}

	/* And the last non-space character. */
	while (end > p && isspace(*end)) end--;

	outsize = end - p + 1;
	memcpy(out, p, outsize);
	out[outsize] = '\0';
	return outsize;
}

/**
 * Parse an input string and get:
 * - a pointer on the first non whitespace character
 * - the length of the string from the first non whitespace up to the last non whitespace
 *
 * A length limit can be provided, in which case the parsing is restricted to that many characters.
 * -1 to parse the entire input string.
 */
int ncc_str_trim_ptr(char const **out_p, ssize_t *outlen, char const *in, ssize_t inlen)
{
	char const *p = in;

	if (!in || inlen == 0) return -1;

	/* Output defaults. */
	*out_p = NULL;
	*outlen = 0;

	fr_skip_whitespace(p);

	/* If an input length is provided, check we're not already beyond that limit. */
	ssize_t len = inlen;
	if (inlen > 0) {
		len -= (p - in);
		if (len <= 0) return -1; /* Nothing left to parse. */
	}

	char const *q = ncc_strr_notspace(p, len);
	if (!q) return -1; /* Cannot happen (*p is not whitespace). */

	*out_p = p;
	*outlen = (q - p + 1);
	return 0;
}


/*
 *	Add an item entry to the tail of the list.
 */
void ncc_list_add(ncc_list_t *list, ncc_list_item_t *entry)
{
	if (!list || !entry) return;

	if (!list->head) {
		ncc_assert(list->tail == NULL);
		list->head = entry;
		entry->prev = NULL;
	} else {
		ncc_assert(list->tail != NULL);
		ncc_assert(list->tail->next == NULL);
		list->tail->next = entry;
		entry->prev = list->tail;
	}
	list->tail = entry;
	entry->next = NULL;
	entry->list = list;
	list->size ++;
}

/*
 *	Remove an item entry from its list.
 */
ncc_list_item_t *ncc_list_item_draw(ncc_list_item_t *entry)
{
	if (!entry) return NULL; // should not happen.
	if (!entry->list) return entry; // not in a list: just return the entry.

	ncc_list_item_t *prev, *next;

	prev = entry->prev;
	next = entry->next;

	ncc_list_t *list = entry->list;

	ncc_assert(list->head != NULL); // entry belongs to a list, so the list can't be empty.
	ncc_assert(list->tail != NULL); // same.

	if (prev) {
		ncc_assert(list->head != entry); // if entry has a prev, then entry can't be head.
		prev->next = next;
	}
	else {
		ncc_assert(list->head == entry); // if entry has no prev, then entry must be head.
		list->head = next;
	}

	if (next) {
		ncc_assert(list->tail != entry); // if entry has a next, then entry can't be tail.
		next->prev = prev;
	}
	else {
		ncc_assert(list->tail == entry); // if entry has no next, then entry must be tail.
		list->tail = prev;
	}

	entry->list = NULL;
	entry->prev = NULL;
	entry->next = NULL;
	list->size --;
	return entry;
}

/*
 *	Get the head item entry from a list.
 */
ncc_list_item_t *ncc_list_get_head(ncc_list_t *list)
{
	if (!list) return NULL;
	if (!list->head || list->size == 0) { // list is empty.
		return NULL;
	}
	// list is valid and has at least one element.
	return ncc_list_item_draw(list->head);
}

/*
 *	Get reference on a list item from its index (position in the list, starting at 0).
 *	Item is not removed from the list.
 */
ncc_list_item_t *ncc_list_index(ncc_list_t *list, uint32_t index)
{
	if (index >= list->size) return NULL; /* Item doesn't exist. */

	ncc_list_item_t *item = list->head;
	uint32_t i;
	for (i = 0; i < index; i++) {
		item = item->next;
	}
	return item;
}


/*
 *	Add a new endpoint to a list.
 */
ncc_endpoint_t *ncc_ep_list_add(TALLOC_CTX *ctx, ncc_endpoint_list_t *ep_list,
                                char *addr, ncc_endpoint_t *default_ep)
{
	ncc_endpoint_t this = { .ipaddr = { .af = AF_UNSPEC, .prefix = 32 } };
	ncc_endpoint_t *ep_new;

	if (default_ep) this = *default_ep;

	if (ncc_host_addr_resolve(&this, addr) != 0) return NULL; /* already have an error. */

	if (!is_endpoint_defined(this)) {
		fr_strerror_printf("IP address and port must be provided");
		return NULL;
	}

	ep_list->num ++;
	ep_list->eps = talloc_realloc(ctx, ep_list->eps, ncc_endpoint_t, ep_list->num);
	/* Note: ctx is used only on first allocation. */

	ep_new = &ep_list->eps[ep_list->num - 1];
	memcpy(ep_new, &this, sizeof(this));

	return ep_new; /* Valid only until list is expanded. */
}

/*
 *	Get next endpoint from the list (use in round robin fashion).
 */
ncc_endpoint_t *ncc_ep_list_get_next(ncc_endpoint_list_t *ep_list)
{
	if (!ep_list || !ep_list->eps) return NULL;

	ncc_endpoint_t *ep = &ep_list->eps[ep_list->next];
	ep_list->next = (ep_list->next + 1) % ep_list->num;
	return ep;
}

/*
 *	Print the endpoints in list.
 */
char *ncc_ep_list_snprint(char *out, size_t outlen, ncc_endpoint_list_t *ep_list)
{
	char ipaddr_buf[FR_IPADDR_STRLEN] = "";
	int i;
	size_t len;
	char *p = out;
	char *end = out + outlen - 1;

	if (!ep_list) {
		fr_strerror_printf("Invalid argument");
		return NULL;
	}

	for (i = 0; i < ep_list->num; i++) {
		len = snprintf(p, end - p, "%s%s:%u", (i > 0 ? ", " : ""),
		               fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf),
		               &ep_list->eps[ep_list->next].ipaddr), ep_list->eps[ep_list->next].port);

		ERR_IF_TRUNCATED(p, len, end - p);
	}

	return out;
}

/*
 *	Peek at stdin (fd 0) to see if it has input.
 */
bool ncc_stdin_peek()
{
	fd_set set;
	int max_fd = 1;
	struct timeval tv;

	FD_ZERO(&set);
	FD_SET(0, &set);
	timerclear(&tv);

	if (select(max_fd, &set, NULL, NULL, &tv) <= 0) {
		return false;
	}

	return true;
}

/*
 *	Allocate an array of strings (if not already allocated).
 */
void ncc_str_array_alloc(TALLOC_CTX *ctx, ncc_str_array_t **pt_array)
{
	if (!*pt_array) {
		MEM(*pt_array = talloc_zero(ctx, ncc_str_array_t));
	}
}

/*
 *	Add a value to an array of strings.
 */
uint32_t ncc_str_array_add(TALLOC_CTX *ctx, ncc_str_array_t **pt_array, char *value)
{
	/* Allocate the array first, if needed. */
	ncc_str_array_alloc(ctx, pt_array);

	ncc_str_array_t *array = *pt_array;
	uint32_t size_pre = array->size; /* Previous size (which is also the index of the new element). */

	TALLOC_REALLOC_ZERO(ctx, array->strings, char *, size_pre, size_pre + 1);
	array->size ++;
	array->strings[size_pre] = talloc_strdup(ctx, value);

	return array->size;
}

/*
 *	Search for a value in an array of string, add it if not found. Return its index.
 *	Note: this is unefficient, but it's meant for only a handful of elements so it doesn't matter.
 */
uint32_t ncc_str_array_index(TALLOC_CTX *ctx, ncc_str_array_t **pt_array, char *value)
{
	/* Allocate the array first, if needed. */
	ncc_str_array_alloc(ctx, pt_array);

	ncc_str_array_t *array = *pt_array;
	uint32_t size_pre = array->size; /* Previous size (which is also the index of the new element if added). */
	int i;
	for (i = 0; i < size_pre; i++) {
		if (strcmp(value, array->strings[i]) == 0) return i;
	}

	/* Value not found, add it. */
	ncc_str_array_add(ctx, pt_array, value);
	return size_pre;
}
