#pragma once
/*
 *	ncc_log.h
 */


/*
 *	Trace / logging.
 */
typedef enum {
	LOG_DST_NULL = 0,              //!< Discard.
	LOG_DST_STDOUT,                //!< Log to stdout.
	LOG_DST_FILE,                  //!< Log to a file on disk.
} ncc_log_dst_t;

typedef struct {
	fr_log_timestamp_t timestamp;  //!< Prefix log messages with timestamps.

	bool line_number;              //!< Log source file and line number.
	bool basename;                 //<! Print only source file base name.

	bool multiline;                //<! If more than one error in the stack, print them on separate lines.
	bool prefix_all;               //<! Repeat prefix on all of the lines.

} ncc_log_t;

extern fr_table_num_ordered_t const ncc_log_dst_table[];
extern size_t ncc_log_dst_table_len;

extern ncc_log_t ncc_default_log;
extern ncc_log_t ncc_multiline_log;
extern FILE *ncc_log_fp;
extern int ncc_debug_lvl;

#define NCC_LOG_ENABLED           (ncc_log_fp)
#define NCC_DEBUG_ENABLED(_p)     (ncc_log_fp && ncc_debug_lvl >= _p)

#define NCC_DEBUG(_p, _f, ...) do { \
	if (NCC_DEBUG_ENABLED(_p)) ncc_log_dev_printf(&ncc_default_log, __FILE__, __LINE__, _f, ## __VA_ARGS__); \
} while (0)

#define NCC_LOG(_lvl, _f, ...) do { \
	if (NCC_LOG_ENABLED) ncc_log_printf(&ncc_default_log, _lvl, __FILE__, __LINE__, _f, ## __VA_ARGS__); \
} while (0)

#define NCC_LOG_FLAGS(_lvl, _flags, _f, ...) do { \
	if (NCC_LOG_ENABLED) ncc_log_printf(&ncc_default_log, (_lvl | _flags), __FILE__, __LINE__, _f, ## __VA_ARGS__); \
} while (0)

#define NCC_LOG_STACK(_lvl, _f, ...) do { \
	if (NCC_LOG_ENABLED) ncc_log_perror(&ncc_default_log, _lvl, _f, ## __VA_ARGS__); \
} while (0)

#define NCC_LOG_STACK_ML(_lvl, _f, ...) do { \
	if (NCC_LOG_ENABLED) ncc_log_perror(&ncc_multiline_log, _lvl, _f, ## __VA_ARGS__); \
} while (0)

#define NCC_LOG_MARKER(_lvl, _str, _idx, _f, ...) do { \
	if (NCC_LOG_ENABLED) ncc_log_marker(&ncc_default_log, _lvl, __FILE__, __LINE__, _str, _idx, _f, ## __VA_ARGS__); \
} while (0)


/*
	Note: FreeRADIUS logs macros are defined in src/lib/server/log.h

	Sample output (which depends on the logger configuration - here with timestamp):

	Fri Apr  5 10:00:44 2019 : Debug : Calling DEBUG
	Fri Apr  5 10:00:44 2019 : Info  : Calling INFO
	Fri Apr  5 10:00:44 2019 : Warn  : Calling WARN
	Fri Apr  5 10:00:44 2019 : Error : Calling ERROR
	Fri Apr  5 10:01:59 2019 : Error : Calling PERROR: Pushing error(2)
	Fri Apr  5 10:01:59 2019 : Error : Pushing error(1)
	Fri Apr  5 10:01:59 2019 : Error : Pushing error(0)

	We'll redefine our own, so we get exactly what we want.

	Note: The push/pop mechanism of FreeRADIUS allows to have multiple error messages
	logged in a single call of PERROR (cf. fr_strerror_printf_push / fr_log_perror).
	The most recently pushed error is displayed on the same line as the log prefix.

	So there is really no need anymore for something like: ERROR("Something: %s", fr_strerror());
	Instead do: PERROR("Something");
*/
#undef DEBUG
#define DEBUG(_f, ...)  NCC_DEBUG(1, _f, ## __VA_ARGS__)

#undef DEBUG2
#define DEBUG2(_f, ...) NCC_DEBUG(2, _f, ## __VA_ARGS__)

#undef DEBUG3
#define DEBUG3(_f, ...) NCC_DEBUG(3, _f, ## __VA_ARGS__)

#undef DEBUG4
#define DEBUG4(_f, ...) NCC_DEBUG(4, _f, ## __VA_ARGS__)

#undef INFO
#define INFO(_f, ...) NCC_LOG(L_INFO, _f, ## __VA_ARGS__)

#undef WARN
#define WARN(_f, ...) NCC_LOG(L_WARN, _f, ## __VA_ARGS__)

#undef ERROR
#define ERROR(_f, ...) NCC_LOG(L_ERR, _f, ## __VA_ARGS__)

#undef PWARN
#define PWARN(_f, ...) NCC_LOG_STACK(L_WARN, _f, ## __VA_ARGS__)

#undef PERROR
#define PERROR(_f, ...) NCC_LOG_STACK(L_ERR, _f, ## __VA_ARGS__)
#define PERROR_ML(_f, ...) NCC_LOG_STACK_ML(L_ERR, _f, ## __VA_ARGS__)

#define PERROR_CF(_cf, _fmt, ...) ncc_cf_log_perr(L_ERR, CF_TO_ITEM(_cf),  __FILE__, __LINE__, _fmt, ## __VA_ARGS__)

#define DEBUG_TRACE(_f, ...) NCC_DEBUG(3, _f, ## __VA_ARGS__)



void ncc_log_init(FILE *log_fp, int debug_lvl);
int ncc_log_open_file(char const *file);
void ncc_vlog_printf(ncc_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, va_list ap);
void ncc_log_printf(ncc_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, ...);
int ncc_log_marker(ncc_log_t const *log, fr_log_type_t type, char const *file, int line,
                   char const *str, size_t idx, char const *fmt, ...);
void ncc_log_perror(ncc_log_t const *log, fr_log_type_t type, char const *fmt, ...);
void ncc_log_dev_printf(ncc_log_t const *log, char const *file, int line, char const *fmt, ...);

void ncc_vlog_request(fr_log_type_t type, fr_log_lvl_t lvl, request_t *request,
		  char const *file, int line,
		  char const *fmt, va_list ap, void *uctx);

