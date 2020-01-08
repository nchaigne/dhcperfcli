
/**
 * @file ncc_util.c
 * @brief Logging functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 */

#include "ncc_util.h"
#include "ncc_log.h"


/*
 *	Trace / logging.
 */
fr_table_num_ordered_t const ncc_log_dst_table[] = {
	{ "null",    LOG_DST_NULL },
	{ "stdout",  LOG_DST_STDOUT },
	{ "file",    LOG_DST_FILE },
};
size_t ncc_log_dst_table_len = NUM_ELEMENTS(ncc_log_dst_table);


FILE *ncc_log_fp = NULL;
fr_time_t fte_ncc_start; /* Program execution start timestamp. */
int ncc_debug_lvl = 0;
fr_thread_local_setup(TALLOC_CTX *, ncc_vlog_pool)
static uint32_t location_indent = 30;
static char const spaces_location[] = "                                                 ";
static char const spaces_marker[] = "                                                                                "; // 80

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
 * Open log file.
 */
int ncc_log_open_file(char const *file)
{
	DEBUG("Opening log file: \"%s\"", file);

	FILE *fp = fopen(file, "a");
	if (!fp) {
		ERROR("Failed to open log file \"%s\": %s", file, fr_syserror(errno));
		return -1;
	}

	/* Set stream as line buffered. */
	setlinebuf(fp);

	ncc_log_fp = fp;
	return 0;
}

/**
 * Print a log message.
 */
void ncc_vlog_printf(ncc_log_t const *log, fr_log_type_t extended_type, char const *file, int line, char const *fmt, va_list ap)
{
	TALLOC_CTX *pool;
	bool debug_location = false;
	char const *fmt_location = "";
	char fmt_time[NCC_DATETIME_STRLEN];
	char const *fmt_facility = "";
	char *fmt_msg;

	fr_log_type_t type = (extended_type & 0xff);
	bool log_location = (extended_type & NCC_LOG_LOCATION);

	if (log->basename) {
		/* file is __FILE__ which is set at build time by gcc.
		 * e.g. src/modules/proto_dhcpv4/dhcperfcli.c
		 * Extract the file base name to have leaner traces.
		 */
		FILE_BASENAME(file);
	}

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

	/* Only for Debug: print file/line number.
	 * Try to keep messages aligned, allowing to increase indentation if needed (up to a limit determined by "spaces").
	 * e.g. " )dhcperfcli.c:2556           : "
	 *      " )src/modules/proto_dhcpv4/dhcperfcli.c:2556: "
	 */
	if (type == L_DBG && log->line_number && file) debug_location = true;
	if (debug_location) {
		size_t len;
		int pad = 0;
		char *str;

		str = talloc_asprintf(pool, " )%s:%i", file, line);
		len = talloc_array_length(str) - 1;

		/*
		 * Only increase the indent
		 */
		if (len > location_indent) {
			location_indent = len;
		} else {
			pad = location_indent - len;
		}

		fmt_location = talloc_asprintf_append_buffer(str, "%.*s: ", pad, spaces_location);

		/* Print elapsed time, e.g. "t(0.001)". */
		char time_buf[NCC_TIME_STRLEN];
		snprintf(fmt_time, sizeof(fmt_time), "t(%s)",
		         ncc_fr_delta_time_snprint(time_buf, sizeof(fmt_time), fte_ncc_start, 0, (ncc_debug_lvl >= 4) ? 6 : 3));

	} else if (log_location) {
		/* With flag "log location" just print file name and line number.
		 */
		fmt_location = talloc_asprintf(pool, "%s:%i : ", file, line);
	}

	/* Absolute date/time. */
	if (!fmt_time[0] && log->timestamp == L_TIMESTAMP_ON) {
		ncc_absolute_time_snprint(fmt_time, sizeof(fmt_time), NCC_DATETIME_FMT);
	}

	/* Facility, e.g. "Error : " for L_ERR.
	 * ... except for Debug with location printed (in which case this is obvious this is debug)
	 */
	if (type && !debug_location) {
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

	talloc_free_children(pool); /* free all temporary allocations */
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
 * Write the string being parsed, and a marker showing where the parse error occurred.
 * Similar to fr_canonicalize_error / fr_canonicalize_error.
 */
int ncc_log_marker(ncc_log_t const *log, fr_log_type_t type, char const *file, int line,
                   char const *str, size_t idx, char const *fmt, ...)
{
	va_list ap;
	char *errstr;
	size_t offset, prefix_len, suffix_len;
	char const *prefix = "... ";
	char const *suffix = " ...";
	char *p;
	char const *start;
	char *value;
	size_t inlen;

	offset = idx;
	inlen = strlen(str);
	start = str;
	prefix_len = suffix_len = 0;

	TALLOC_CTX *ctx = NULL;

	if (idx >= inlen) {
		/* Marked character does not exist. */
		return -1;
	}

	va_start(ap, fmt);
	errstr = fr_vasprintf(NULL, fmt, ap);
	va_end(ap);

	/*
	 * Too many characters before the inflection point. Skip leading text.
	 */
	if (offset > 30) {
		prefix_len = strlen(prefix);

		/* Ensure the resulting string (with prefix) is actually shorter than the original. */
		size_t skip = offset - (30 - prefix_len);

		start += skip;
		inlen -= skip;
		offset -= skip;
	}

	int len_err = prefix_len + offset + 2 + strlen(errstr); /* [... ]<spaces>^ <error> */

	/*
	 * Too many characters after the inflection point. Truncate end of text.
	 * Do not truncate before the end of the error string though.
	 */
	int end_limit = offset + 40;
	if (inlen > end_limit && inlen > len_err) {
		suffix_len = strlen(suffix);

		if (end_limit >= len_err) inlen = end_limit; /* Allow truncation to extend past the error string. */
		else inlen = len_err; /* Truncate to align with the error string. */
	}

	/*
	 * Allocate an array to hold just the text we need.
	 */
	value = talloc_array(ctx, char, prefix_len + inlen + 1 + suffix_len);
	if (prefix_len) {
		memcpy(value, prefix, prefix_len);
	}
	memcpy(value + prefix_len, start, inlen);
	if (suffix_len) {
		memcpy(value + prefix_len + inlen, suffix, suffix_len);
	}
	value[prefix_len + inlen + suffix_len] = '\0';

	/*
	 * Smash tabs to spaces for the input string.
	 */
	for (p = value; *p != '\0'; p++) {
		if (*p == '\t') *p = ' ';
	}

	ncc_log_printf(log, type, file, line, "%s", value);
	ncc_log_printf(log, type, file, line, "%.*s^ %s", prefix_len + offset, spaces_marker, errstr);

	talloc_free(value);
	talloc_free(errstr);

	return 0;
}

/**
 * Print a log message and also pop all stacked FreeRADIUS error messages.
 */
int ncc_vlog_perror(ncc_log_t const *log, fr_log_type_t type, char const *fmt, va_list ap)
{
	char *tmp = NULL;
	char const *strerror;
	bool prefix = (fmt && fmt[0] != '\0');

	strerror = fr_strerror_pop();
	if (!strerror) {
		if (!prefix) return 0; /* No "fmt" prefix and no error stack. */

		ncc_vlog_printf(log, type, NULL, type, fmt, ap);
		return 0;
	}

	/* If we have "fmt", use it as prefix. */
	if (prefix) {
		tmp = talloc_vasprintf(NULL, fmt, ap);
	}

	if (log->multiline) {
		/*
		 * Print the first error.
		 * If we have a prefix, concatenate it with the first error.
		 */
		if (prefix) {
			ncc_log_printf(log, type, NULL, 0, "%s: %s", tmp, strerror);
		} else {
			ncc_log_printf(log, type, NULL, 0, "%s", strerror);
		}

		/*
		 * Then print all other errors (without the prefix) on separate lines.
		 */
		while ((strerror = fr_strerror_pop())) {
			if (prefix && log->prefix_all) {
				/* Repeat the prefix on each line - it is useful for aligned errors.
				 * (cf. fr_canonicalize_error)
				 */
				ncc_log_printf(log, type, NULL, 0, "%s: %s", tmp, strerror);
			} else {
				ncc_log_printf(log, type, NULL, 0, "%s", strerror);
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

		ncc_log_printf(log, type, NULL, 0, "%s", tmp);
	}

	if (tmp) talloc_free(tmp);
	return 0;
}
void ncc_log_perror(ncc_log_t const *log, fr_log_type_t type, char const *fmt, ...)
{
	va_list ap;

	if (!ncc_log_fp) return;

	va_start(ap, fmt);
	ncc_vlog_perror(log, type, fmt, ap);
	va_end(ap);
}

/**
 * Print a debug log message.
 * Now merely invoke ncc_vlog_printf which does the real work.
 */
void ncc_log_dev_printf(ncc_log_t const *log, char const *file, int line, char const *fmt, ...)
{
	va_list ap;

	if (!ncc_log_fp || !fmt) return;

	va_start(ap, fmt);
	ncc_vlog_printf(log, L_DBG, file, line, fmt, ap);
	va_end(ap);
}

/**
 * Provide our own version of "vlog_request" so we can handle FreeRADIUS "REQUEST" logs.
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
