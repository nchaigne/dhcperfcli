#pragma once
/*
 *	ncc_util.h
 */

#include <freeradius-devel/server/base.h>
#include <math.h>

#include "ncc_dlist.h"

#define NCC_ENDPOINT_STRLEN       (FR_IPADDR_STRLEN + 1 + 5)
#define NCC_ETHADDR_STRLEN        (17 + 1)
#define NCC_UINT32_STRLEN         (10 + 1)
#define NCC_UINT64_STRLEN         (20 + 1)
#define NCC_TIME_STRLEN           (15 + 1)
#define NCC_DATETIME_STRLEN       (19 + 1)

#define NCC_DATE_FMT              "%Y-%m-%d"
#define NCC_TIME_FMT              "%H:%M:%S"
#define NCC_DATETIME_FMT          NCC_DATE_FMT" "NCC_TIME_FMT


/*
 *	Using rad_assert defined in include/rad_assert.h
 */
#define ncc_assert rad_assert


/*
 *	Trace / logging.
 */
typedef struct {
	fr_log_timestamp_t timestamp;  //!< Prefix log messages with timestamps.

	bool line_number;              //!< Log source file and line number.
	bool basename;                 //<! Print only source file base name.

	bool multiline;                //<! If more than one error in the stack, print them on separate lines.
	bool prefix_all;               //<! Repeat prefix on all of the lines.

} ncc_log_t;

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

#define DEBUG_TRACE(_f, ...) NCC_DEBUG(3, _f, ## __VA_ARGS__)


/* Generic function argument check. Return error value if condition is not verified. */
#define FN_ARG_CHECK(_ret, _cond) { \
	if (!(_cond)) { \
		fr_strerror_printf("Failed argument check '%s'", STRINGIFY(_cond)); \
		return _ret; \
	} \
}

/* Print an error to FreeRADIUS error stack, and return error value. */
#define FN_ERROR_PRINTF(_ret, _f, ...) { \
	fr_strerror_printf(_f, ## __VA_ARGS__); \
	return _ret; \
}

/* Get a pointer on __FILE__ base name. */
#define FILE_BASENAME(_file) \
{ \
	if (_file) { \
		char *p = strrchr(_file, FR_DIR_SEP); \
		if (p) _file = p + 1; \
	} \
}

/* Push an error to FreeRADIUS error stack, with location detail (file name and line number).
 * Note: can't have a function because there isn't a non-variadic version (va_list) of fr_strerror_printf. */
#define FR_ERROR_PRINTF_LOCATION(_f, ...) \
{ \
	char *file = __FILE__; \
	FILE_BASENAME(file); \
	fr_strerror_printf("[%s:%i] " _f, file, __LINE__, ## __VA_ARGS__); \
}


/*	After a call to snprintf and similar functions, check if we have enough remaining buffer space.
 *
 *	These functions return the number of characters printed (excluding the null byte used to end output to strings).
 *	If the output was truncated due to this limit then the return value is the number of characters (excluding the
 *	terminating null byte) which would have been written to the final string if enough space had been available.
 *	Thus, a return value of size or more means that the output was truncated.
 */

/* Push error about insufficient buffer size. */
#define ERR_BUFFER_SIZE(_need, _size) \
	FR_ERROR_PRINTF_LOCATION("Insufficient buffer space (needed: %zu bytes, have: %zu)", (size_t)(_need), (size_t)(_size));

/**
 * Check buffer size, if insufficient: push error and return.
 *
 * @param[in] _ret   return with this value if size is not sufficient.
 * @param[in] _need  how many bytes are needed (must account for the terminating '\0' if relevant).
 * @param[in] _size  available space in output buffer.
 */
#define CHECK_BUFFER_SIZE(_ret, _need, _size) \
	if (_size < _need) { \
		ERR_BUFFER_SIZE(_need, _size); \
		return _ret; \
	}

/**
 * Check if we have enough remaining buffer space. If not push an error and return NULL.
 * Otherwise, update the current char pointer.
 *
 * @param[in,out] _p    current char pointer on output buffer.
 * @param[in]     _ret  number of characters (excluding the terminating null byte) necessary to print given
 *                      string in output buffer (see snprintf family).
 * @param[in]     _max  remaining available space in output buffer (including the terminating null byte).
 */
#define ERR_IF_TRUNCATED(_p, _ret, _max) do { \
	if (_ret >= _max) { \
		ERR_BUFFER_SIZE(_ret + 1, _max); \
		return NULL; \
	} \
	_p += _ret; \
} while (0)

/* Same as above, and also update remaining output buffer length.
 */
#define ERR_IF_TRUNCATED_LEN(_p, _outlen, _ret) do { \
	if (_ret >= _outlen) { \
		ERR_BUFFER_SIZE(_ret + 1, _outlen); \
		return NULL; \
	} \
	_p += _ret; \
	_outlen -= _ret; \
} while (0)


/* Custom flags that can be passed within "type" to ncc_value_from_str */
#define NCC_TYPE_NOT_EMPTY     (1 << 10)
#define NCC_TYPE_NOT_NEGATIVE  (1 << 11)
#define NCC_TYPE_NOT_ZERO      (1 << 12)

/* Custom log flags that can extend fr_log_type_t */
#define NCC_LOG_LOCATION       (1 << 10)


/* Check that endpoint is not undefined. */
#define is_ipaddr_defined(_x) (_x.af != AF_UNSPEC)
#define is_endpoint_defined(_e) (is_ipaddr_defined(_e.ipaddr) && _e.port)


/* Verify that a VP is "data" (i.e. not "xlat"). */
#define IS_VP_DATA(_vp) (_vp && _vp->type == VT_DATA)


typedef struct ncc_list_item ncc_list_item_t;

/*
 *	Chained list of data elements.
 */
typedef struct ncc_list {
	ncc_list_item_t *head;
	ncc_list_item_t *tail;
	uint32_t size;
} ncc_list_t;

/*
 *	Chained list item.
 */
struct ncc_list_item {
	ncc_list_t *list;       //!< The list to which this entry belongs (NULL for an unchained entry).
	ncc_list_item_t *prev;
	ncc_list_item_t *next;

	void *data;             //!< User-specific item data.
};

/*
 *	Dynamic array of strings, reallocated as needed.
 */
typedef struct ncc_str_array {
	char **strings;
	uint32_t size;
} ncc_str_array_t;

/*
 *	Transport endpoint (IP address, port).
 */
typedef struct ncc_endpoint {
	fr_ipaddr_t ipaddr;
	uint16_t port;
} ncc_endpoint_t;

#define NCC_EP_MAKE(_ep, _ipaddr, _port) \
	ncc_endpoint_t _ep; \
	_ep.ipaddr = _ipaddr; _ep.port = _port;

/*
 *	List of endpoints (used in round-robin fashion).
 */
typedef struct ncc_endpoint_list {
	ncc_endpoint_t *eps;   //<! List of endpoints.
	uint32_t num;          //<! Number of endpoints in the list.
	uint32_t next;         //<! Number of next endpoint to be used.
} ncc_endpoint_list_t;


/* Get visibility on fr_event_timer_t opaque struct (fr_event_timer is defined in lib/util/event.c) */
typedef struct ncc_fr_event_timer {
	fr_event_list_t		*el;			//!< because talloc_parent() is O(N) in number of objects
	fr_time_t		when;			//!< When this timer should fire.
	/* We don't need anything beyond that. */
} ncc_fr_event_timer_t;

/* Get visibility on fr_event_list_t opaque struct (fr_event_list is defined in lib/util/event.c) */
typedef struct ncc_fr_event_list {
	fr_heap_t		*times;			//!< of timer events to be executed.
	/* We don't need anything beyond that. */
} ncc_fr_event_list_t;


int ncc_fr_event_timer_peek(fr_event_list_t *fr_el, fr_time_t *when);

void ncc_log_init(FILE *log_fp, int debug_lvl);
void ncc_vlog_printf(ncc_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, va_list ap);
void ncc_log_printf(ncc_log_t const *log, fr_log_type_t type, char const *file, int line, char const *fmt, ...);
int ncc_log_marker(ncc_log_t const *log, fr_log_type_t type, char const *file, int line,
                   char const *str, size_t idx, char const *fmt, ...);
void ncc_log_perror(ncc_log_t const *log, fr_log_type_t type, char const *fmt, ...);
void ncc_log_dev_printf(ncc_log_t const *log, char const *file, int line, char const *fmt, ...);

void ncc_vlog_request(fr_log_type_t type, fr_log_lvl_t lvl, REQUEST *request,
		  char const *file, int line,
		  char const *fmt, va_list ap, void *uctx);

char const *ncc_attr_dict_name(fr_dict_attr_t const *da);
fr_dict_attr_t const *ncc_dict_attr_by_name(fr_dict_t const *dict, char const *name);
void ncc_dict_attr_info_fprint(FILE *fp, fr_dict_attr_t const *da);

VALUE_PAIR *ncc_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da);
VALUE_PAIR *ncc_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			                unsigned int attribute, unsigned int vendor);
VALUE_PAIR *ncc_pair_create_by_da(TALLOC_CTX *ctx, VALUE_PAIR **vps, fr_dict_attr_t const *da);
int ncc_pair_copy_value(VALUE_PAIR *to, VALUE_PAIR *from);
int ncc_pair_value_from_str(VALUE_PAIR *vp, char const *value);
VALUE_PAIR *ncc_pair_copy(TALLOC_CTX *ctx, VALUE_PAIR const *vp);
int ncc_pair_list_copy(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from);
VALUE_PAIR *ncc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from);
void ncc_pair_list_fprint(FILE *fp, VALUE_PAIR *vps);
size_t ncc_pair_snprint(char *out, size_t outlen, VALUE_PAIR const *vp);

FR_TOKEN ncc_value_raw_from_str(char const **ptr, VALUE_PAIR_RAW *raw);
FR_TOKEN ncc_value_list_afrom_str(TALLOC_CTX *ctx, fr_dict_attr_t const *da, char const *buffer, VALUE_PAIR **list);
int ncc_value_list_afrom_file(TALLOC_CTX *ctx, fr_dict_attr_t const *da, VALUE_PAIR **out, FILE *fp, uint32_t *line, bool *pfiledone);

VALUE_PAIR *ncc_pair_afrom_cp(TALLOC_CTX *ctx, fr_dict_t const *dict, CONF_PAIR *cp);
void ncc_cs_debug_start(CONF_SECTION *cs, int cs_depth);
void ncc_cs_debug_end(CONF_SECTION *cs, int cs_depth);
int ncc_pair_list_afrom_cs(TALLOC_CTX *ctx, fr_dict_t const *dict, VALUE_PAIR **out,
                           CONF_SECTION *cs, int cs_depth, unsigned int max);

char *ncc_hex_data_snprint(char *out, size_t outlen, const uint8_t *in, int in_len, char const *sep,
                           char const *prefix, int line_max_len);
int ncc_hex_data_fprint(FILE *fp, const uint8_t *in, int in_len, char const *sep,
                        int line_max_len);
char *ncc_endpoint_sprint(char *out, ncc_endpoint_t *ep);
char *ncc_ether_addr_snprint(char *out, size_t outlen, const uint8_t *addr);
char *ncc_delta_time_snprint(char *out, size_t outlen, struct timeval *from, struct timeval *when, uint8_t decimals);
char *ncc_fr_delta_time_snprint(char *out, size_t outlen, fr_time_t *from, fr_time_t *when, uint8_t decimals);
char *ncc_absolute_time_snprint(char *out, size_t outlen, const char *fmt);

int ncc_host_addr_resolve(ncc_endpoint_t *host_ep, char const *host_arg);

int ncc_strtoull(uint64_t *out, char const *value);
int ncc_strtoll(int64_t *out, char const *value);
int ncc_strtof(float *out, char const *value);
int ncc_strtod(double *out, char const *value);
int ncc_strtobool(bool *out, char const *value);
int ncc_value_from_str(void *out, uint32_t type, char const *value, ssize_t inlen);

double ncc_timeval_to_float(struct timeval *in);
int ncc_float_to_timeval(struct timeval *tv, double in);
double ncc_fr_time_to_float(fr_time_delta_t in);
fr_time_t ncc_float_to_fr_time(double in);
bool ncc_str_to_float(double *out, char const *in, bool allow_negative);
bool ncc_str_to_float32(float *out, char const *in, bool allow_negative);
size_t ncc_str_trim(char *out, char const *in, size_t inlen);
int ncc_str_trim_ptr(char const **out_p, ssize_t *outlen, char const *in, ssize_t inlen);

void ncc_list_add(ncc_list_t *list, ncc_list_item_t *entry);
ncc_list_item_t *ncc_list_item_draw(ncc_list_item_t *entry);
ncc_list_item_t *ncc_list_get_head(ncc_list_t *list);
ncc_list_item_t *ncc_list_index(ncc_list_t *list, uint32_t index);

#define NCC_LIST_ENQUEUE(_l, _e) ncc_list_add(_l, (ncc_list_item_t *)_e);
#define NCC_LIST_DEQUEUE(_l) (void *)ncc_list_get_head(_l);
#define NCC_LIST_INDEX(_l, _i) (void *)ncc_list_index(_l, _i);
#define NCC_LIST_DRAW(_e) (void *)ncc_list_item_draw((ncc_list_item_t *)_e);

ncc_endpoint_t *ncc_ep_list_add(TALLOC_CTX *ctx, ncc_endpoint_list_t *ep_list, char *addr, ncc_endpoint_t *default_ep);
ncc_endpoint_t *ncc_ep_list_get_next(ncc_endpoint_list_t *ep_list);
char *ncc_ep_list_snprint(char *out, size_t outlen, ncc_endpoint_list_t *ep_list);

bool ncc_stdin_peek();

void ncc_str_array_alloc(TALLOC_CTX *ctx, ncc_str_array_t **pt_array);
uint32_t ncc_str_array_add(TALLOC_CTX *ctx, ncc_str_array_t **pt_array, char *value);
uint32_t ncc_str_array_index(TALLOC_CTX *ctx, ncc_str_array_t **pt_array, char *value);


/* This is now in protocol/radius/list.h - which we might not want to depend on, so... */
#define fr_packet2myptr(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))

/* Same as is_integer, but allow to work on a given length. */
static inline bool is_integer_n(char const *value, ssize_t len)
{
	if (*value == '\0' || len == 0) return false;

	char const *p = value;
	while (*p) {
		if (!isdigit(*p)) return false;

		if (len > 0 && (p - value + 1 >= len)) break;
		p++;
	}

	return true;
}

/** Get the last non whitespace character of a string.
 *
 * @param[in] value  string to process.
 *
 * @return pointer on last non whitespace char (NULL if none found).
 */
static inline char const *ncc_strr_notspace(char const *value, ssize_t len)
{
	char const *p = value, *q = NULL;;
	while (*p) {
		if (!isspace(*p)) q = p;
		p++;

		if (len > 0 && (p >= value + len)) break;
	}
	return q;
}

/* talloc_realloc doesn't zero-initialize the new memory. */
#define TALLOC_REALLOC_ZERO(_ctx, _ptr, _type, _count_pre, _count) \
{ \
	_ptr = talloc_realloc(_ctx, _ptr, _type, _count); \
	if (_count > _count_pre) { \
		memset(&_ptr[_count_pre], 0, sizeof(_type) * (_count - _count_pre)); \
	} \
}

/**
 * Convert a string to a value using a sorted or ordered table (calls fr_table_value_by_str).
 * Allow to provide the length of string that should be considered (-1 for the entire string).
 * We don't have access to the private definitions in table.h so we'll work with a macro.
 * Note: this is *not* the same as fr_table_value_by_substr.
 */
#define NCC_TABLE_VALUE_BY_STR(_ret, _table, _name, _name_len, _def) \
{ \
	char buffer[256]; \
	char const *value = NULL; \
	_ret = _def; \
	if (_name_len < 0) value = _name; \
	else if (_name_len < (ssize_t)sizeof(buffer)) { \
		memcpy(buffer, _name, _name_len); \
		buffer[_name_len] = '\0'; \
		value = buffer; \
	} \
	if (value) _ret = fr_table_value_by_str(_table, value, _def); \
}
