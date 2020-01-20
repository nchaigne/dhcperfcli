#pragma once
/*
 *	ncc_util.h
 */

#include <freeradius-devel/server/base.h>
#include <math.h>

#include "ncc_dlist.h"
#include "ncc_log.h"

#define NCC_ENDPOINT_STRLEN       (FR_IPADDR_STRLEN + 1 + 5)
#define NCC_ETHADDR_STRLEN        (17 + 1)
#define NCC_UINT32_STRLEN         (10 + 1)
#define NCC_UINT64_STRLEN         (20 + 1)
#define NCC_TIME_STRLEN           (15 + 1)
#define NCC_DATETIME_STRLEN       (19 + 1)

#define NCC_DATE_FMT              "%Y-%m-%d"
#define NCC_TIME_FMT              "%H:%M:%S"
#define NCC_DATETIME_FMT          NCC_DATE_FMT" "NCC_TIME_FMT

#define CONF_SPACE(_depth)        ((_depth) * 2)
extern char const config_spaces[];


/*
 *	Using rad_assert (which calls fr_assert_exit) defined in lib/server/rad_assert.h
 *	Not anymore: now in non-debug build (NDEBUG) it does nothing... (??)
 *
 *	assert output:
 *	dhcperfcli: src/modules/rlm_dhcperfcli/dpc_packet_list.c:601: dpc_packet_list_recv: Assertion `pl != ((void *)0)' failed.
 *
 *	fr_assert_exit output:
 *	ASSERT FAILED src/modules/rlm_dhcperfcli/dpc_packet_list.c[601]: pl != NULL
 *	or "ASSERT WOULD FAIL" if non-debug build (NDEBUG).
 */
#define ncc_void_assert(_expr) ((void) ((_expr) ? (void) 0 : (void) fr_assert_exit(__FILE__, __LINE__, #_expr)))
#define ncc_assert(_expr) (((_expr) ? true : fr_assert_exit(__FILE__, __LINE__, #_expr)))



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


// fr_box macro that is not defined in value.h (can't have "fr_box_bool", precompiler isn't happy with that)
#define fr_box_boolean(_val) _fr_box(FR_TYPE_BOOL, .vb_bool, _val)

// a "safe" version of fr_box_strvalue that can be used with a NULL value.
#define fr_box_str(_val) _fr_box_with_len(FR_TYPE_STRING, .vb_strvalue, _val, _val ? strlen(_val) : 0)

/*
 * Custom flags that can be passed within "type_check" in ncc_parse_ctx_t.
 * Used by ncc_conf_item_parse and ncc_parse_value_from_str.
 */
#define NCC_TYPE_NOT_EMPTY     (1 << 10)
#define NCC_TYPE_NOT_NEGATIVE  (1 << 11)
#define NCC_TYPE_NOT_ZERO      (1 << 12)
#define NCC_TYPE_CHECK_MIN     (1 << 13)
#define NCC_TYPE_CHECK_MAX     (1 << 14)
#define NCC_TYPE_CHECK_TABLE   (1 << 15)
#define NCC_TYPE_FORCE_MIN     (1 << 16)
#define NCC_TYPE_FORCE_MAX     (1 << 17)
#define NCC_TYPE_IGNORE_ZERO   (1 << 18)
#define NCC_TYPE_STATIC        (1 << 19)

#define NCC_TYPE_STRING_STATIC (FR_TYPE_STRING | NCC_TYPE_STATIC)

/* Custom log flags that can extend fr_log_type_t */
#define NCC_LOG_LOCATION       (1 << 10)


/* Check that endpoint is not undefined. */
#define is_ipaddr_defined(_x) (_x.af != AF_UNSPEC)
#define is_endpoint_defined(_e) (is_ipaddr_defined(_e.ipaddr) && _e.port)


/* Verify that a VP is "data" (i.e. not "xlat"). */
#define IS_VP_DATA(_vp) (_vp && _vp->type == VT_DATA)


/*
 *	Transport endpoint (IP address, port).
 */
typedef struct ncc_endpoint {
	/* Generic chaining */
	fr_dlist_t dlist;          //!< Our entry into the linked list.

	fr_ipaddr_t ipaddr;
	uint16_t port;
} ncc_endpoint_t;

#define NCC_EP_MAKE(_ep, _ipaddr, _port) \
	ncc_endpoint_t _ep = { 0 }; \
	_ep.ipaddr = _ipaddr; _ep.port = _port;


/*
 *	Context for custom parser function ncc_conf_item_parse (called by FreeRADIUS).
 */
typedef struct ncc_parse_ctx_t {
	uint32_t type;       //<! Base fr_type_t value.
	uint32_t type_check; //<! Flags to specify the checks to perform on value.

	union {
		struct {
			double min;
			double max;
		} _float;        //<! Value bounds for float32, float64, time delta.
		struct {
			int64_t min;
			int64_t max;
		} integer;       //<! Value bounds for signed integers.
		struct {
			uint64_t min;
			uint64_t max;
		} uinteger;      //<! Value bounds for unsigned integers.
		struct {
			fr_time_delta_t min;
			fr_time_delta_t max;
		} ftd;           //<! Value bounds for time delta (not to be used directly: converted from _float).
	};

	fr_table_num_ordered_t const *fr_table; //<! Table of allowed integer values.
	size_t fr_table_len;    //<! Size of fr_table. Will be set automatically if pointer is provided.
	size_t *fr_table_len_p; //<! Pointer because NUM_ELEMENTS (sizeof) cannot work on an extern array with no specified size.

} ncc_parse_ctx_t;

#define FR_TABLE_LEN_FROM_PTR(_fr_table) \
	if (_fr_table ## _len_p) _fr_table ## _len = *(_fr_table ## _len_p);

#define PARSE_CTX_FLOAT64_NOT_NEGATIVE &(ncc_parse_ctx_t){ .type = FR_TYPE_FLOAT64, .type_check = NCC_TYPE_NOT_NEGATIVE }

#define FLOAT64_NOT_NEGATIVE .func = ncc_conf_item_parse, .uctx = PARSE_CTX_FLOAT64_NOT_NEGATIVE


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
int ncc_ev_lists_peek(fr_event_list_t **ev_lists, fr_time_t *when);
uint32_t ncc_ev_lists_service(fr_event_list_t **ev_lists, fr_time_t now);

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

char *ncc_hex_data_snprint(char *out, size_t outlen, const uint8_t *in, int in_len, char const *sep,
                           char const *prefix, int line_max_len);
int ncc_hex_data_fprint(FILE *fp, const uint8_t *in, int in_len, char const *sep,
                        int line_max_len);
char *ncc_endpoint_sprint(char *out, ncc_endpoint_t *ep);
char *ncc_ether_addr_snprint(char *out, size_t outlen, const uint8_t *addr);
char *ncc_delta_time_snprint(char *out, size_t outlen, struct timeval *from, struct timeval *when, uint8_t decimals);
char *ncc_fr_delta_time_snprint(char *out, size_t outlen, fr_time_t fte_from, fr_time_t fte_to, uint8_t decimals);
char *ncc_absolute_time_snprint(char *out, size_t outlen, const char *fmt);

int ncc_host_addr_resolve(ncc_endpoint_t *host_ep, char const *host_arg);

double ncc_timeval_to_float(struct timeval *in);
int ncc_float_to_timeval(struct timeval *tv, double in);
double ncc_fr_time_to_float(fr_time_delta_t in);
fr_time_t ncc_float_to_fr_time(double in);
bool ncc_str_to_float(double *out, char const *in, bool allow_negative);
bool ncc_str_to_float32(float *out, char const *in, bool allow_negative);
size_t ncc_str_trim(char *out, char const *in, size_t inlen);
int ncc_str_trim_ptr(char const **out_p, ssize_t *outlen, char const *in, ssize_t inlen);

int ncc_endpoint_list_parse(TALLOC_CTX *ctx, ncc_dlist_t **ep_dlist_p, char const *in,
                            ncc_endpoint_t *default_ep);
ncc_endpoint_t *ncc_endpoint_list_add(TALLOC_CTX *ctx, ncc_dlist_t *ep_dlist,
                                      char *addr, ncc_endpoint_t *default_ep);
ncc_endpoint_t *ncc_endpoint_find(ncc_dlist_t *list, ncc_endpoint_t *ep_find);
char *ncc_endpoint_list_snprint(char *out, size_t outlen, ncc_dlist_t *ep_dlist);

bool ncc_stdin_peek();

uint32_t ncc_str_array_index(TALLOC_CTX *ctx, char ***pt_array, char const *value);
int ncc_ipaddr_array_find(fr_ipaddr_t *ipaddr_array, fr_ipaddr_t *ipaddr);


/*
 * Functions from ncc_parse.c
 */
int ncc_strtoull(uint64_t *out, char const *value);
int ncc_strtoll(int64_t *out, char const *value);
int ncc_strtof(float *out, char const *value);
int ncc_strtod(double *out, char const *value);
int ncc_strtobool(bool *out, char const *value);
int ncc_value_from_str(TALLOC_CTX *ctx, void *out, uint32_t type_ext, char const *value, ssize_t inlen);
int ncc_parse_value_from_str(TALLOC_CTX *ctx, void *out, uint32_t type_ext, char const *value, ssize_t inlen, ncc_parse_ctx_t *parse_ctx);
char const *ncc_parser_config_get_table_value(void *pvalue, ncc_parse_ctx_t *parse_ctx);
int ncc_str_in_table(int32_t *out, fr_table_num_ordered_t const *table, size_t table_len, char const *str);
int ncc_value_from_str_table(void *out, uint32_t type,
                             fr_table_num_ordered_t const *table, size_t table_len, char const *str);
void ncc_section_debug_start(int depth, char const *name1, char const *name2);
void ncc_section_debug_end(int depth);
void ncc_pair_list_debug(int depth, VALUE_PAIR *vps);
void ncc_parser_config_item_debug(int type, char const *name, void *pvalue, size_t vsize, ncc_parse_ctx_t *parse_ctx,
                                  int depth, char const *prefix);
void ncc_parser_config_debug(CONF_PARSER const *rules, void *config, int depth, char const *prefix);
void ncc_config_merge(CONF_PARSER const *rules, void *config, void *config_old);
int ncc_getopt_rule(TALLOC_CTX *ctx, void *base, CONF_PARSER const *rule, char const *value);
int ncc_getopt(TALLOC_CTX *ctx, void *base, CONF_PARSER const *rules, char const *opt, int argval, char const *optarg);
int ncc_opt_default(TALLOC_CTX *ctx, void *base, CONF_PARSER const *rules);


/*
 * Functions from ncc_util_server.c
 */
void ncc_cf_log_perr(fr_log_type_t type, CONF_ITEM const *ci, char const *file, int line, char const *fmt, ...);
int ncc_conf_item_parse(TALLOC_CTX *ctx, void *out, void *parent, CONF_ITEM *ci, CONF_PARSER const *rule);
VALUE_PAIR *ncc_pair_afrom_cp(TALLOC_CTX *ctx, fr_dict_t const *dict, CONF_PAIR *cp);
void ncc_cs_debug_start(CONF_SECTION *cs, int cs_depth);
void ncc_cs_debug_end(CONF_SECTION *cs, int cs_depth);
int ncc_pair_list_afrom_cs(TALLOC_CTX *ctx, fr_dict_t const *dict, VALUE_PAIR **out,
                           CONF_SECTION *cs, int cs_depth, unsigned int max);


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

/**
 * Call talloc_realloc, and set new memory to zero.
 * Note about the memset: "_ptr" might be "*something" (hence, parenthesis are crucial).
 */
#define TALLOC_REALLOC_ZERO(_ctx, _ptr, _type, _count_pre, _count) \
{ \
	if (_count > _count_pre) { \
		_ptr = talloc_realloc(_ctx, _ptr, _type, _count); \
		memset(&(_ptr)[_count_pre], 0, sizeof(_type) * (_count - _count_pre)); \
	} \
}

/**
 * Reallocate a talloc array with one more element, and set its memory to zero.
 */
#define TALLOC_REALLOC_ONE_ZERO(_ctx, _ptr, _type) \
{ \
	size_t len = talloc_array_length(_ptr); \
	TALLOC_REALLOC_ZERO(_ctx, _ptr, _type, len, len + 1); \
}

/**
 * Reallocate a talloc array with one more element, and set it to provided value
 */
#define TALLOC_REALLOC_ONE_SET(_ctx, _ptr, _type, _v) \
{ \
	size_t len = talloc_array_length(_ptr); \
	TALLOC_REALLOC_ZERO(_ctx, _ptr, _type, len, len + 1); \
	(_ptr)[len] = _v; \
}

/**
 * Merge two talloc arrays of the same type.
 */
#define TALLOC_ARRAY_MERGE(_ctx, _arr1, _arr2, _type) \
{ \
	if (_arr2) { \
		size_t len1 = talloc_array_length(_arr1); \
		size_t len2 = talloc_array_length(_arr2); \
		if (len2) { \
			TALLOC_REALLOC_ZERO(_ctx, _arr1, _type, len1, len1 + len2); \
			memcpy(&(_arr1)[len1], &(_arr2)[0], sizeof(_type) * len2); \
		} \
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


/**
 * Check macros for configuration items or string option parsing.
 *
 * Note: float64 are printed with "%g" when using FreeRADIUS "%pV" feature.
 * This means we can get "1e-05" instead of "0.00001". Or "1e+06" instead of "1000000".
 * Using %f, the default decimal precision is 6, so it's only better for 0.000001 <= v < 0.0001
 * (and for v >= 1000000, which if storing seconds is more than 10 days)
 * With fr_time_delta_t we can get "0.000000001".
 */

#define NCC_CI_VALUE_COND_CHECK(_ci, _type, _name, _var, _cond, _new)\
do {\
	if (!(_cond)) {\
		if (_ci) cf_log_warn(_ci, "Ignoring configured \"%s = %pV\", forcing to \"%s = %pV\"", _name, fr_box_##_type(_var), _name, fr_box_##_type(_new));\
		else WARN("Ignoring configured \"%s = %pV\", forcing to \"%s = %pV\"", _name, fr_box_##_type(_var), _name, fr_box_##_type(_new));\
		_var = _new;\
	}\
} while (0)

#define NCC_CI_VALUE_BOUND_CHECK(_ci, _type, _name, _var, _op, _bound) NCC_CI_VALUE_COND_CHECK(_ci, _type, _name, _var, (_var _op _bound), _bound)

#define NCC_CI_FLOAT_COND_CHECK(_ci, _name, _var, _cond, _new)\
do {\
	if (!(_cond)) {\
		if (_ci) cf_log_warn(_ci, "Ignoring configured \"%s = %f\", forcing to \"%s = %f\"", _name, _var, _name, _new);\
		else WARN("Ignoring configured \"%s = %f\", forcing to \"%s = %f\"", _name, _var, _name, _new);\
		_var = _new;\
	}\
} while (0)

#define NCC_CI_FLOAT_BOUND_CHECK(_ci, _name, _var, _op, _bound) NCC_CI_FLOAT_COND_CHECK(_ci, _name, _var, (_var _op _bound), _bound)

#define NCC_CI_TIME_DELTA_BOUND_CHECK(_ci, _name, _var, _op, _bound) NCC_CI_VALUE_BOUND_CHECK(_ci, time_delta, _var, _op, _bound)

#define NCC_VALUE_COND_CHECK(_ret, _type, _var, _cond, _new)\
do {\
	if (!(_cond)) {\
		fr_strerror_printf("Ignoring value \"%pV\", forcing to \"%pV\"", fr_box_##_type(_var), fr_box_##_type(_new));\
		_var = _new;\
		_ret = 1;\
	}\
} while (0)

#define NCC_VALUE_BOUND_CHECK(_ret, _type, _var, _op, _bound) NCC_VALUE_COND_CHECK(_ret, _type, _var, (_var _op _bound), _bound)

#define NCC_FLOAT_COND_CHECK(_ret, _var, _cond, _new)\
do {\
	if (!(_cond)) {\
		fr_strerror_printf("Ignoring value \"%f\", forcing to \"%f\"", _var, _new);\
		_var = _new;\
		_ret = 1;\
	}\
} while (0)

#define NCC_FLOAT_BOUND_CHECK(_ret, _var, _op, _bound) NCC_FLOAT_COND_CHECK(_ret, _var, (_var _op _bound), _bound)
