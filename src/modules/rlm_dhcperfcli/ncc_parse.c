/**
 * @file ncc_parse.c
 * @brief Parsing functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 */

#include "ncc_util.h"


char const config_spaces[] = "                                                                                ";

/*
 * Tables which allow to obtain min/max bounds for each of integer types as a string.
 */
//#define UINT64_MAX_STR STRINGIFY(UINT64_MAX)
// => "(18446744073709551615UL)"... not good enough. BTW it's done that way in "inet.c": STRINGIFY(UINT16_MAX)

fr_table_num_ordered_t const fr_type_int_max_table[] = {
	{ L("255"),                  FR_TYPE_UINT8 },
	{ L("65536"),                FR_TYPE_UINT16 },
	{ L("4294967295"),           FR_TYPE_UINT32 },
	{ L("18446744073709551615"), FR_TYPE_UINT64 },

	{ L("127"),                  FR_TYPE_INT8 },
	{ L("32767"),                FR_TYPE_INT16 },
	{ L("2147483647"),           FR_TYPE_INT32 },
	{ L("9223372036854775807"),  FR_TYPE_INT64 },
};
size_t fr_type_int_max_table_len = NUM_ELEMENTS(fr_type_int_max_table);

fr_table_num_ordered_t const fr_type_int_min_table[] = {
	{ L("0"),                    FR_TYPE_UINT8 },
	{ L("0"),                    FR_TYPE_UINT16 },
	{ L("0"),                    FR_TYPE_UINT32 },
	{ L("0"),                    FR_TYPE_UINT64 },

	{ L("-128"),                 FR_TYPE_INT8 },
	{ L("-32768"),               FR_TYPE_INT16 },
	{ L("-2147483648"),          FR_TYPE_INT32 },
	{ L("-9223372036854775808"), FR_TYPE_INT64 },
};
size_t fr_type_int_min_table_len = NUM_ELEMENTS(fr_type_int_min_table);


/**
 * Parse a uint64 value from a string.
 * Wrapper to strtoull, with restrictions:
 * - Ensure the provided input is not a negative value (strtoull dubiously allows this).
 * - Check we don't have trailing garbage at the end of the input string (whitespace is allowed).
 *
 * @param[out] out    where to write the parsed value.
 * @param[in]  value  string which contains the value to parse.
 *
 * @return -2 = range error, -1 = other error, 0 = success.
 */
int ncc_strtoull(uint64_t *out, char const *value)
{
	char *p = NULL;

	fr_skip_whitespace(value);

	if (*value == '-') {
		/* Don't let strtoull happily process negative values.
		 */
		fr_strerror_printf("Invalid negative value \"%s\" for unsigned integer", value);
		return -2;
	}

	int base = 10;
	if ((value[0] == '0') && (value[1] == 'x')) base = 16;
	errno = 0;
	*out = strtoull(value, &p, base);
	if (errno == ERANGE) {
		fr_strerror_printf("Unsigned integer value \"%s\" too large, would overflow", value);
		return -2;
	}

	if (*p != '\0' && !is_whitespace(p)) {
		fr_strerror_printf("Invalid value \"%s\" for unsigned integer", value);
		return -1;
	}

	return 0;
}

/**
 * Parse a int64 value from a string.
 * Wrapper to strtoll, with restrictions:
 * - Check we don't have trailing garbage at the end of the input string (whitespace is allowed).
 *
 * @param[out] out    where to write the parsed value.
 * @param[in]  value  string which contains the value to parse.
 *
 * @return -2 = range error, -1 = other error, 0 = success.
 */
int ncc_strtoll(int64_t *out, char const *value)
{
	char *p = NULL;

	int base = 10;
	if ((value[0] == '0') && (value[1] == 'x')) base = 16;
	errno = 0;
	*out = strtoll(value, &p, base);
	if (errno == ERANGE) {
		fr_strerror_printf("Signed integer value \"%s\" too large, would overflow", value);
		return -2;
	}

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

#define STRCASECMP_LEN(_str1, _str2, _len2) (_len2 == strlen(_str1) && strncasecmp(_str2, _str1, _len2) == 0)

	if (   STRCASECMP_LEN("yes", value, len)
	    || STRCASECMP_LEN("true", value, len)
	    || STRCASECMP_LEN("on", value, len) ) {
		*(bool *)out = true;
		return 0;
	}

	if (   STRCASECMP_LEN("no", value, len)
	    || STRCASECMP_LEN("false", value, len)
	    || STRCASECMP_LEN("off", value, len) ) {
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
 * The following FreeRADIUS types are supported:
 * - FR_TYPE_UINT* (8, 16, 32, 64)
 * - FR_TYPE_INT* (8, 16, 32, 64)
 * - FR_TYPE_FLOAT* (32, 64)
 * - FR_TYPE_TIME_DELTA
 * - FR_TYPE_STRING
 * - FR_TYPE_BOOL
 * - FR_TYPE_IPV4_ADDR
 * - FR_TYPE_ETHERNET
 *
 * @param[in]  ctx    talloc context (for string allocations, can be left NULL for other data types).
 * @param[out] out    where to write the parsed value (size depends on the type).
 *                    NULL allows to discard output (validity check only).
 * @param[in]  type   type of value being parsed (base type | optional qualifiers).
 * @param[in]  value  string which contains the value to parse.
 * @param[in]  inlen  length of value, if value is \0 terminated inlen may be -1.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_value_from_str(TALLOC_CTX *ctx, void *out, uint32_t type_ext, char const *value, ssize_t inlen)
{
	int ret;
	uint64_t uinteger = 0;
	int64_t sinteger = 0;
	char buffer[4096];

	if (!value) {
		fr_strerror_printf("No value");
		return -1;
	}

	/*
	 * Copy to intermediary buffer if we were given a length
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

	uint32_t type = FR_BASE_TYPE(type_ext);

	/*
	 * Check for zero length strings
	 */
	if (value[0] == '\0') {
		fr_strerror_printf("Value cannot be empty");
		return -1;
	}

#define INVALID_TYPE_VALUE \
	do { \
		fr_strerror_printf("Invalid value \"%s\" for type '%s'", value, \
			fr_table_str_by_value(fr_value_box_type_table, type, "<INVALID>")); \
		return -1; \
	} while (0)

#define INTEGER_OUT_OF_BOUNDS(_fr_type) \
	do { \
		fr_strerror_printf("Value out of bounds for type '%s' (range: %s..%s)", \
			fr_table_str_by_value(fr_value_box_type_table, _fr_type, "<INVALID>"), \
			fr_table_str_by_value(fr_type_int_min_table, _fr_type, "<INVALID>"), \
			fr_table_str_by_value(fr_type_int_max_table, _fr_type, "<INVALID>")); \
		return -1; \
	} while (0)

#define IN_RANGE_UNSIGNED(_type) \
	do { \
		if (uinteger > _type ## _MAX) INTEGER_OUT_OF_BOUNDS(type); \
	} while (0)

#define IN_RANGE_SIGNED(_type) \
	do { \
		if ((sinteger > _type ## _MAX) || (sinteger < _type ## _MIN)) INTEGER_OUT_OF_BOUNDS(type); \
	} while (0)

	/*
	 * First pass for integers.
	 */
	switch (type) {
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
		/*
		 * Function checks for overflows and trailing garbage, and calls fr_strerror_printf to set an error.
		 * In case of ERANGE, we set our own error message (which is common to all "out of bounds" cases).
		 */
		ret = ncc_strtoull(&uinteger, value);
		if (ret < 0) {
			if (ret == -2) INTEGER_OUT_OF_BOUNDS(type);
			return -1;
		}
		break;

	case FR_TYPE_INT8:
	case FR_TYPE_INT16:
	case FR_TYPE_INT32:
	case FR_TYPE_INT64:
		/*
		 * Function checks for overflows and trailing garbage, and calls fr_strerror_printf to set an error.
		 * In case of ERANGE, we set our own error message (which is common to all "out of bounds" cases).
		 */
		ret = ncc_strtoll(&sinteger, value);
		if (ret < 0) {
			if (ret == -2) INTEGER_OUT_OF_BOUNDS(type);
			return -1;
		}
		break;

	default:
		/* Non-integers are not handled here. */
		break;
	}

	/*
	 * Second pass for all. Integers are already parsed and now just need assignment.
	 */
	switch (type) {
	case FR_TYPE_STRING:
	{
		if (out) {
			char **str = out;
			/* If "out" contains a string pointer, it is replaced.
			 * We do not attempt to free the string, as it may not have be talloc'ed.
			 * If it was, then it will be freed later along with the whole configuration.
			 */
			*str = talloc_strndup(ctx, value, len);
		}
	}
		break;

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
		if (out) *(float *)out = v;
	}
		break;

	case FR_TYPE_FLOAT64:
	{
		double v;
		if (ncc_strtod(&v, value) < 0) return -1;
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
		fr_strerror_printf("Unsupported type '%s' (%i)",
		                   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type);
		return -1;
	}

	return 0;
}

 /**
 * Parse a string value into a given FreeRADIUS data type (FR_TYPE_...).
 * Check that value is valid for the data type, and obtain converted value.
 * Perform additional checks provided in parse context.
 *
 * The following FreeRADIUS types are supported:
 * - FR_TYPE_UINT* (8, 16, 32, 64)
 * - FR_TYPE_INT* (8, 16, 32, 64)
 * - FR_TYPE_FLOAT* (32, 64)
 * - FR_TYPE_TIME_DELTA
 * - FR_TYPE_STRING
 *
 * @param[in]  ctx        talloc context (for string allocations, can be left NULL for other data types).
 * @param[out] out        where to write the parsed value (size depends on the type).
 *                        NULL allows to discard output (validity check only).
 * @param[in]  type       type of value being parsed (base type | optional qualifiers).
 * @param[in]  value      string which contains the value to parse.
 * @param[in]  inlen      length of value, if value is \0 terminated inlen may be -1.
 * @param[in]  parse_ctx  parse context which defines checks to perform on the parsed value.
 *
 * @return -1 = error, 0 = success and value is not modified, 1 = value is forced.
 */
int ncc_parse_value_from_str(TALLOC_CTX *ctx, void *out, uint32_t type_ext,
                             char const *value, ssize_t inlen, ncc_parse_ctx_t *parse_ctx)
{
	int rcode = 0; /* Set to 1 if value is forced. */
	int ret;

	uint32_t type = FR_BASE_TYPE(type_ext);

	if (!parse_ctx) {
		/*
		 * If no parse context is provided, just try to convert string value to target type.
		 */
		if (ncc_value_from_str(ctx, out, type_ext, value, inlen) < 0) return -1;

		return 0;
	}

	/* The parse context contains the base type, which should match that of "type".
	 */
	ncc_assert(type == FR_BASE_TYPE(parse_ctx->type));

	uint32_t type_check = parse_ctx->type_check;

	bool ignore_zero = (type_check & NCC_TYPE_IGNORE_ZERO);
	bool not_zero = (type_check & NCC_TYPE_NOT_ZERO);
	bool not_negative = (type_check & NCC_TYPE_NOT_NEGATIVE);
	bool force_min = (type_check & NCC_TYPE_FORCE_MIN);
	bool force_max = (type_check & NCC_TYPE_FORCE_MAX);
	bool check_min = (type_check & NCC_TYPE_CHECK_MIN);
	bool check_max = (type_check & NCC_TYPE_CHECK_MAX);
	bool check_table = (type_check & NCC_TYPE_CHECK_TABLE);

	/*
	 * First try parsing according to target type.
	 */
	ret = ncc_value_from_str(ctx, out, type_ext, value, inlen);

	if (ret < 0) {
		if (check_table && (type == FR_TYPE_INT32 || type == FR_TYPE_UINT32)) {
			/* Integer parsing failed.
			 * Look for string in provided table and obtain corresponding integer value.
		 	 */
			ret = ncc_value_from_str_table(out, type, parse_ctx->fr_table, *parse_ctx->fr_table_len_p, value);
			if (ret != 0) { /* Not found or error. */
				if (ret == -1) fr_strerror_printf_push("Invalid value \"%s\"", value);
				return -1;
			}
		}
	}

	/* Failed to parse.
	 */
	if (ret != 0) return -1;

#define CHECK_IGNORE_ZERO \
	if (ignore_zero && !v) return 0;

#define CHECK_NOT_ZERO \
	if (not_zero && !v) { \
		fr_strerror_printf("Invalid value (cannot be zero)"); \
		return -1; \
	}

#define CHECK_VALUE_TABLE(_type) { \
	if (check_table && parse_ctx->fr_table) { \
		FR_TABLE_LEN_FROM_PTR(parse_ctx->fr_table); \
		if (fr_table_str_by_value(parse_ctx->fr_table, v, NULL) == NULL) { \
			fr_strerror_printf("Invalid value \"%pV\" (unknown)", fr_box_##_type(v)); \
			return -1; \
		} \
	} \
}

#define CHECK_STR_TABLE { \
	if (check_table && parse_ctx->fr_table) { \
		FR_TABLE_LEN_FROM_PTR(parse_ctx->fr_table); \
		if (fr_table_value_by_str(parse_ctx->fr_table, v, FR_TABLE_NOT_FOUND) == FR_TABLE_NOT_FOUND) { \
			fr_strerror_printf("Invalid value \"%s\" (unknown)", v); \
			return -1; \
		} \
	} \
}

#define CHECK_VALUE(_type, _ctx_type) { \
	memcpy(&v, out, sizeof(v)); \
	CHECK_IGNORE_ZERO \
	CHECK_NOT_ZERO \
	if (not_negative && v < 0) { \
		fr_strerror_printf("Invalid value \"%pV\" (cannot be negative)", fr_box_##_type(v)); \
		return -1; \
	} \
	if (force_min) NCC_VALUE_BOUND_CHECK(rcode, _type, v, >=, parse_ctx->_ctx_type.min); \
	if (force_max) NCC_VALUE_BOUND_CHECK(rcode, _type, v, <=, parse_ctx->_ctx_type.max); \
	memcpy(out, &v, sizeof(v)); \
	if (check_min && v < parse_ctx->_ctx_type.min) { \
		fr_strerror_printf("Invalid value \"%pV\" (min: %pV)", fr_box_##_type(v), fr_box_##_type(parse_ctx->_ctx_type.min)); \
		return -1; \
	} \
	if (check_max && v > parse_ctx->_ctx_type.max) { \
		fr_strerror_printf("Invalid value \"%pV\" (max: %pV)", fr_box_##_type(v), fr_box_##_type(parse_ctx->_ctx_type.max)); \
		return -1; \
	} \
}

#define CASE_CHECK_BOX_VALUE(_fr_type, _c_type, _box_type, _ctx_type) \
	case _fr_type: \
	{ \
		_c_type v; \
		CHECK_VALUE(_box_type, _ctx_type) \
		CHECK_VALUE_TABLE(_box_type) \
	} \
	break;

	/*
	 * Extract the value, and check the type is handled.
	 * Perform specified checks.
	 */
	switch (type) {
	CASE_CHECK_BOX_VALUE(FR_TYPE_UINT8, uint8_t, uint8, uinteger)
	CASE_CHECK_BOX_VALUE(FR_TYPE_UINT16, uint16_t, uint16, uinteger)
	CASE_CHECK_BOX_VALUE(FR_TYPE_UINT32, uint32_t, uint32, uinteger)
	CASE_CHECK_BOX_VALUE(FR_TYPE_UINT64, uint64_t, uint64, uinteger)

	CASE_CHECK_BOX_VALUE(FR_TYPE_INT8, int8_t, int8, integer)
	CASE_CHECK_BOX_VALUE(FR_TYPE_INT16, int16_t, int16, integer)
	CASE_CHECK_BOX_VALUE(FR_TYPE_INT32, int32_t, int32, integer)
	CASE_CHECK_BOX_VALUE(FR_TYPE_INT64, int64_t, int64, integer)

	case FR_TYPE_FLOAT32:
	{
		float v;
		CHECK_VALUE(float32, _float)
	}
		break;

	case FR_TYPE_FLOAT64:
	{
		double v;
		CHECK_VALUE(float64, _float)
	}
		break;

	case FR_TYPE_TIME_DELTA:
	{
		fr_time_delta_t v;

		/* Convert min/max values from float to fr_time_delta_t, and put them back in the context. */
		fr_time_delta_t ftd_min = ncc_float_to_fr_time(parse_ctx->_float.min);
		fr_time_delta_t ftd_max = ncc_float_to_fr_time(parse_ctx->_float.max);
		parse_ctx->ftd.min = ftd_min;
		parse_ctx->ftd.max = ftd_max;

		CHECK_VALUE(time_delta, ftd);
	}
		break;

	case FR_TYPE_STRING:
	{
		char *v;
		memcpy(&v, out, sizeof(v));
		CHECK_STR_TABLE
	}
		break;

	default:
		fr_strerror_printf("Invalid type '%s' (%i) in parse context",
		                   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type);
		return -1;
	}

	return rcode;
}


/**
 * If parser rule has a parse context with a "check table" rule,
 * get the table string value that corresponds to the integer value.
 */
char const *ncc_parser_config_get_table_value(void *pvalue, ncc_parse_ctx_t *parse_ctx)
{
	if (!parse_ctx
	 || !(parse_ctx->type_check & NCC_TYPE_CHECK_TABLE)) return NULL;

	uint32_t type = FR_BASE_TYPE(parse_ctx->type);
	char const *table_str = NULL;

	/* Note: fr_table_str_by_value handles value as an "int".
	 * No point in trying to handle int64_t / uint64_t here.
	 */

#define CASE_GET_TABLE_VALUE(_fr_type, _c_type) \
	case _fr_type: \
	{ \
		_c_type value = *(_c_type *)pvalue; \
		if (parse_ctx->fr_table) { \
			FR_TABLE_LEN_FROM_PTR(parse_ctx->fr_table); \
			table_str = fr_table_str_by_value(parse_ctx->fr_table, value, NULL); \
		} \
	} \
	break;

	switch (type) {
	CASE_GET_TABLE_VALUE(FR_TYPE_INT8, int8_t)
	CASE_GET_TABLE_VALUE(FR_TYPE_INT16, int16_t)
	CASE_GET_TABLE_VALUE(FR_TYPE_INT32, int32_t)

	CASE_GET_TABLE_VALUE(FR_TYPE_UINT8, uint8_t)
	CASE_GET_TABLE_VALUE(FR_TYPE_UINT16, uint16_t)
	CASE_GET_TABLE_VALUE(FR_TYPE_UINT32, uint32_t)

	default:
		break;
	}

	return table_str;
}

/**
 * Check that a string can be found in the specified table, and return its integer value.
 * If not, return an error and produce a helpful log message.
 *
 * @param[out] out        where to write integer value (or NULL to just check).
 * @param[in]  table      fr_table where to look string for.
 * @param[in]  table_len  table length.
 * @param[in]  str        string to look for.
 *
 * @return -1 = error, 0 = success, 1 = value not found.
 */
int ncc_str_in_table(int32_t *out, fr_table_num_ordered_t const *table, size_t table_len, char const *str)
{
	char *list = NULL;
	int32_t value;
	size_t i;

	value = fr_table_value_by_str(table, str, FR_TABLE_NOT_FOUND);
	if (value != FR_TABLE_NOT_FOUND) {
		if (out) *out = value;
		return 0;
	}

	if (!table_len) {
		fr_strerror_printf("Table is empty");
		return -1;
	}

	/* Build a comma-separated list of allowed string values.
	 */
	for (i = 0; i < table_len; i++) {
		MEM(list = talloc_asprintf_append_buffer(list, "%s'%s'", i ? ", " : "", table[i].name.str));
	}
	fr_strerror_printf("Expected one of %s", list);

	talloc_free(list);
	return 1;
}

/**
 * Wrapper to ncc_str_in_table, with specified target type.
 *
 * @return -1 = error, 0 = success, 1 = value not found.
 */
int ncc_value_from_str_table(void *out, uint32_t type,
                             fr_table_num_ordered_t const *table, size_t table_len, char const *str)
{
	int32_t value;

	int ret = ncc_str_in_table(&value, table, table_len, str);
	if (ret != 0) return ret; /* Not found or error. */

	/* If "out" is not provided just check string is in table. */
	if (!out) return 0;

	/* No range check here, just assume values can fit in target type.
	 */
	switch (type) {
	case FR_TYPE_UINT32:
		*(uint32_t *)out = value;
		break;

	case FR_TYPE_INT32:
		*(int32_t *)out = value;
		break;

	default:
		fr_strerror_printf("Unsupported type '%s' (%i) for table string to integer",
		                   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type);
		return -1;
	}

	return 0;
}

/**
 * Debug the start of a section.
 */
void ncc_section_debug_start(int depth, char const *name1, char const *name2)
{
	if (!name2) {
		DEBUG("%.*s%s {", CONF_SPACE(depth), config_spaces, name1);
	} else {
		DEBUG("%.*s%s %s {", CONF_SPACE(depth), config_spaces, name1, name2);
	}
}

/**
 * Debug the end of a section.
 */
void ncc_section_debug_end(int depth)
{
	DEBUG("%.*s}", CONF_SPACE(depth), config_spaces);
}

/**
 * Debug a list of value pairs.
 */
void ncc_pair_list_debug(int depth, fr_pair_t *vps)
{
	fr_pair_t *vp;
	fr_cursor_t cursor;
	char buf[4096];

	/* Iterate on the value pairs of the list. */
	int i = 0;
	for (vp = fr_cursor_init(&cursor, &vps); vp; vp = fr_cursor_next(&cursor)) {
		ncc_pair_snprint(buf, sizeof(buf), vp);
		DEBUG("%.*s%s", CONF_SPACE(depth), config_spaces, buf);
		i++;
	}
}

/**
 * Debug a configuration item. If multi-valued, iterate over all values and print each of them.
 * Items are printed using the fr_box_* macro corresponding to their type.
 */
void ncc_parser_config_item_debug(int type, char const *name, void *pvalue, size_t vsize, ncc_parse_ctx_t *parse_ctx,
                                  int depth, char const *prefix)
{
	if (!pvalue) return;

	bool multi = (type & FR_TYPE_MULTI);
	int base_type = FR_BASE_TYPE(type);

	/* prefix (if not NULL) is the item section name that we want to print. */
	char const *section = "";
	char *sp_section = "";
	if (prefix && prefix[0] != '\0') {
		section = prefix;
		sp_section = ".";
	}

#define DEBUG_CONF_BOX(_type) do { \
	if (!value_str) { \
		DEBUG("%.*s%s%s%s = %pV", CONF_SPACE(depth), config_spaces, section, sp_section, name, \
		      fr_box_##_type(value)); \
	} else { \
		DEBUG("%.*s%s%s%s = %pV (%s)", CONF_SPACE(depth), config_spaces, section, sp_section, name, \
		      fr_box_##_type(value), value_str); \
	} \
} while (0)

#define CASE_CONF_BOX_VALUE(_fr_type, _c_type, _box_type) \
	case _fr_type: \
	{ \
		_c_type value = *(_c_type *)pvalue; \
		DEBUG_CONF_BOX(_box_type); \
	} \
	break;

	if (multi) {
		/*
		 * "pvalue" is a talloc array. Size of items is provided in parameter "vsize".
		 * This allows to iterate on each item without having the actual type.
		 */
		int i;
		void *value_arr = *(void **)pvalue;

		/* Cannot use talloc_array_size directly here. */
		size_t len = talloc_get_size(value_arr) / vsize;

		for (i = 0; i < len; i++) {
			ncc_parser_config_item_debug(base_type, name, (void *)(value_arr + (i * vsize)), vsize, parse_ctx, depth, prefix);
		}

	} else {
		/* Get corresponding string value if relevant. */
		char const *value_str = ncc_parser_config_get_table_value(pvalue, parse_ctx);

		switch (base_type) {
		CASE_CONF_BOX_VALUE(FR_TYPE_BOOL, bool, boolean)

		CASE_CONF_BOX_VALUE(FR_TYPE_FLOAT32, float, float32)
		CASE_CONF_BOX_VALUE(FR_TYPE_FLOAT64, double, float64)

		CASE_CONF_BOX_VALUE(FR_TYPE_UINT8, uint8_t, uint8)
		CASE_CONF_BOX_VALUE(FR_TYPE_UINT16, uint16_t, uint16)
		CASE_CONF_BOX_VALUE(FR_TYPE_UINT32, uint32_t, uint32)
		CASE_CONF_BOX_VALUE(FR_TYPE_UINT64, uint64_t, uint64)

		CASE_CONF_BOX_VALUE(FR_TYPE_INT8, int8_t, int8)
		CASE_CONF_BOX_VALUE(FR_TYPE_INT16, int16_t, int16)
		CASE_CONF_BOX_VALUE(FR_TYPE_INT32, int32_t, int32)
		CASE_CONF_BOX_VALUE(FR_TYPE_INT64, int64_t, int64)

		CASE_CONF_BOX_VALUE(FR_TYPE_TIME_DELTA, fr_time_delta_t, time_delta)

		case FR_TYPE_STRING:
		{
			char *value = *(char **)pvalue;
			if (value && value[0] != '\0') DEBUG_CONF_BOX(strvalue);
			/*
			 * Note: fr_box_strvalue must never be called with a NULL value (it uses "strlen"). */
		}
			break;

		case FR_TYPE_IPV4_ADDR:
		{
			fr_ipaddr_t value = *(fr_ipaddr_t *)pvalue;
			if (value.af == AF_INET) DEBUG_CONF_BOX(ipv4addr);
		}
			break;

		default:
			break;
		}
	}
}

/**
 * Debug configuration after it has been parsed.
 * Note: this only handles what the configuration parser knows of.
 *
 * @param[in] rules   parser rules.
 * @param[in] config  configuration structure (fields are only accessed through offset).
 * @param[in] depth   current level in configuration sections.
 * @param[in] prefix  parent section name to display before an item (NULL = don't).
 */
void ncc_parser_config_debug(CONF_PARSER const *rules, void *config, int depth, char const *prefix)
{
	CONF_PARSER const *rule_p;

#define CASE_PARSER_CONF_TYPE(_fr_type, _c_type) \
	case _fr_type: \
		ncc_parser_config_item_debug(rule_type, rule_p->name, ((uint8_t *)config + rule_p->offset), sizeof(_c_type), parse_ctx, depth, prefix); \
		break;

	/*
	 * Iterate over parser rules.
	 */
	for (rule_p = rules; rule_p->name; rule_p++) {
		int rule_type = rule_p->type;
		int type = FR_BASE_TYPE(rule_type);

		ncc_parse_ctx_t *parse_ctx = (ncc_parse_ctx_t *)rule_p->uctx;

		/* Be silent if it is marked as "secret" (unless debug level >= 3).
		 */
		if ((rule_type & FR_TYPE_SECRET) && (!NCC_DEBUG_ENABLED(3))) continue;

		switch (type) {
		CASE_PARSER_CONF_TYPE(FR_TYPE_STRING, char *);
		CASE_PARSER_CONF_TYPE(FR_TYPE_BOOL, bool);

		CASE_PARSER_CONF_TYPE(FR_TYPE_FLOAT32, float);
		CASE_PARSER_CONF_TYPE(FR_TYPE_FLOAT64, double);

		CASE_PARSER_CONF_TYPE(FR_TYPE_UINT8, uint8_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_UINT16, uint16_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_UINT32, uint32_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_UINT64, uint64_t);

		CASE_PARSER_CONF_TYPE(FR_TYPE_INT8, int8_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_INT16, int16_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_INT32, int32_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_INT64, int64_t);

		CASE_PARSER_CONF_TYPE(FR_TYPE_TIME_DELTA, fr_time_delta_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_IPV4_ADDR, fr_ipaddr_t);

		case FR_TYPE_SUBSECTION:
		{
			ncc_section_debug_start(depth, rule_p->name, NULL);

			ncc_parser_config_debug(rule_p->subcs, config, depth + 1, prefix ? rule_p->name : NULL);

			ncc_section_debug_end(depth);
		}
			break;

		default:
			WARN("Unhandled type (FIX ME) for: %s", rule_p->name);
			break;
		}
	}
}

/**
 * Merge values from two configurations (current, old).
 * - Merge multi-valued items (talloc arrays).
 * - Restore strings for which we didn't parse anything (current is NULL, old is not).
 *   The pointer is set to NULL in this case even though we did not set "dflt" (bug ?)
 *
 * @param[in]     rules       parser rules.
 * @param[in,out] config      configuration (current) structure (fields are only accessed through offset).
 * @param[in]     config_old  configuration (old) structure.
 */
void ncc_config_merge(CONF_PARSER const *rules, void *config, void *config_old)
{
	CONF_PARSER const *rule_p;

	for (rule_p = rules; rule_p->name; rule_p++) {
		int base_type = FR_BASE_TYPE(rule_p->type);

		if (base_type == FR_TYPE_SUBSECTION) {
			/*
			 * Note: we don't handle multiple sub-sections.
			 */
			ncc_config_merge(rule_p->subcs, config, config_old);

		} else if (rule_p->type & FR_TYPE_MULTI) {
			/*
			 * Multi-valued items are talloc arrays, we must merge the two arrays (old and current).
			 */
			void **p_array = (void **)((uint8_t *)config + rule_p->offset);
			void **p_array_old = (void **)((uint8_t *)config_old + rule_p->offset);

			/* Do not merge if there is no "old" array
			 * Or if it is the same array as "current" (which means we did not parse anything).
			 */
			if (!*p_array_old || *p_array_old == *p_array) continue;

			DEBUG3("Merging configuration values: %s (offset: %u)", rule_p->name, rule_p->offset);

			switch (base_type) {
			case FR_TYPE_STRING:
				TALLOC_ARRAY_MERGE(NULL, *(char ***)p_array, *(char ***)p_array_old, char *);
				break;

			case FR_TYPE_IPV4_ADDR:
				TALLOC_ARRAY_MERGE(NULL, *(fr_ipaddr_t **)p_array, *(fr_ipaddr_t **)p_array_old, fr_ipaddr_t);
				break;

			default:
				break;
			}

		} else if (base_type == FR_TYPE_STRING) {
			/*
			 * A single value string is set to NULL if we did not parse anything and no default was provided.
			 * In this case restore old value if there was one.
			 */
			char **p_value;
			char *value_old;

			p_value = (char**)((uint8_t *)config + rule_p->offset);
			value_old = *(char**)((uint8_t *)config_old + rule_p->offset);

			if (value_old && !*p_value) {
				*p_value = value_old;
			}
		}

	}
}

/**
 * Parse value to output struct, according to CONF_PARSER rule provided (reusing FreeRADIUS struct for this purpose).
 *
 * @param[in]     ctx     talloc context.
 * @param[in,out] base    base struct to write parsed values to.
 * @param[in]     rule    parser rule.
 * @param[in]     value   string to parse.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_getopt_rule(TALLOC_CTX *ctx, void *base, CONF_PARSER const *rule, char const *value)
{
	int type = rule->type;
	int base_type = FR_BASE_TYPE(type);
	bool multi = (type & FR_TYPE_MULTI);
	ncc_parse_ctx_t *parse_ctx = (ncc_parse_ctx_t *)rule->uctx;
	void *p_value;

	if (!value && rule->dflt) value = rule->dflt;

	if (!multi) {
		p_value = (uint8_t *)base + rule->offset;

	} else {
		/*
	 	 * A multi-valued item is stored within a talloc array.
	 	 * The array is reallocated each time a value is parsed. This is not the most efficient, but it's simpler.
	 	 */
		void **p_array = (void **)((uint8_t *)base + rule->offset);

#define CASE_MULTI_PARSE(_fr_type, _c_type) \
		case _fr_type: \
		{ \
			size_t len = talloc_array_length(*(_c_type **)p_array); \
			TALLOC_REALLOC_ZERO(ctx, *(_c_type **)p_array, _c_type, len, len + 1); \
			p_value = (void *)(*p_array + (len * sizeof(_c_type))); \
		} \
		break;

		switch (base_type) {
		CASE_MULTI_PARSE(FR_TYPE_STRING, char *);
		CASE_MULTI_PARSE(FR_TYPE_IPV4_ADDR, fr_ipaddr_t);

		default:
			fr_strerror_printf("Unsupported type '%s' (%i)",
		                       fr_table_str_by_value(fr_value_box_type_table, base_type, "?Unknown?"), base_type);
			return -1;
		}
	}

	return ncc_parse_value_from_str(ctx, p_value, type, value, -1, parse_ctx);
}

/**
 * Handle a short or long option value.
 * Look for matching definition in the CONF_PARSER rules provided (reusing FreeRADIUS struct for this purpose).
 * Assign member of the output struct.
 *
 * @param[in]     ctx     talloc context.
 * @param[in,out] base    base struct to write parsed values to.
 * @param[in]     rules   parser rules.
 * @param[in]     opt     option name, e.g "--my-long-opt"
 * @param[in]     argval  return value of getopt_long (option character).
 * @param[in]     optarg  option argument.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_getopt(TALLOC_CTX *ctx, void *base, CONF_PARSER const *rules, char const *opt, int argval, char const *optarg)
{
	CONF_PARSER const *rule;
	int ret;
	bool parsed = false;

	/* If it's a short option, rebuild corresponding string e.g. '-a'.
	 */
	char opt_buf[3];
	if ((!opt || opt[0] == '\0') && argval) {
		sprintf(opt_buf, "-%c", argval);
		opt = opt_buf;
	}

	/* Look for matching rule, and use if to parse the option argument.
	 */
	for (rule = rules; rule->name; rule++) {
		char *p, *name, *str;

		str = name = talloc_strdup(ctx, rule->name);

		while ((p = strsep(&str, "|")) != NULL) {
			/* Trim spaces. */
			ncc_str_trim(p, p, strlen(p));

			if (strcmp(p, opt) == 0) {
				ret = ncc_getopt_rule(ctx, base, rule, optarg);
				parsed = true;
			}
		}

		talloc_free(name);
		if (parsed) return ret;
	}

	fr_strerror_printf("Parsing rule not found");
	return -1;
}

/**
 * Set default values for options through CONF_PARSER rules provided.
 *
 * @param[in]     ctx    talloc context.
 * @param[in,out] base   base struct to write parsed values to.
 * @param[in]     rules  parser rules.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_opt_default(TALLOC_CTX *ctx, void *base, CONF_PARSER const *rules)
{
	CONF_PARSER const *rule;

	for (rule = rules; rule->name; rule++) {
		if (rule->dflt) {
			if (ncc_getopt_rule(ctx, base, rule, rule->dflt) < 0) {
				fr_strerror_printf_push("Failed handling default for option \"%s\"", rule->name);
				return -1;
			}
		}
	}

	return 0;
}


/**
 * Read one line of attribute/value pairs into a list.
 * The line may specify multiple attributes separated by commas.
 *
 * Similar to fr_pair_list_afrom_substr (pair_legacy.c)
 * But using fr_dict_attr_search_by_qualified_oid_substr with "fallback = true" instead of fr_dict_attr_by_oid_substr.
 */
extern fr_sbuff_term_t const bareword_terminals; // defined in pair_legacy.c
static ssize_t ncc_pair_list_afrom_substr(TALLOC_CTX *ctx, fr_dict_attr_t const *parent, char const *buffer,
					 fr_pair_list_t *list, fr_token_t *token, int depth)
{
	fr_pair_t	*vp, *head, **tail;
	char const	*p, *next;
	fr_token_t	last_token = T_INVALID;
	fr_pair_t_RAW	raw;
	fr_dict_attr_t const *internal = fr_dict_root(fr_dict_internal());

	if (internal == parent) internal = NULL;

	/*
	 *	We allow an empty line.
	 */
	if (buffer[0] == 0) {
		*token = T_EOL;
		return 0;
	}

	head = NULL;
	tail = &head;

	p = buffer;
	while (true) {
		ssize_t slen;
		fr_dict_attr_t const *da;
		fr_dict_attr_t *da_unknown = NULL;
		fr_skip_whitespace(p);

		/*
		 *	Stop at the end of the input, returning
		 *	whatever token was last read.
		 */
		if (!*p) break;

		if (*p == '#') {
			last_token = T_EOL;
			break;
		}

		/*
		 *	Hacky hack...
		 */
		if (strncmp(p, "raw.", 4) == 0) goto do_unknown;

		/*
		 *	Parse the name.
		 */
//		slen = fr_dict_attr_by_oid_substr(NULL, &da, parent,
//						  &FR_SBUFF_IN(p, strlen(p)), &bareword_terminals);
//		if ((slen <= 0) && internal) {
//			slen = fr_dict_attr_by_oid_substr(NULL, &da, internal,
//							  &FR_SBUFF_IN(p, strlen(p)), &bareword_terminals);
//		}
		slen = fr_dict_attr_search_by_qualified_oid_substr(NULL, &da, NULL, &FR_SBUFF_IN(p, strlen(p)), &bareword_terminals, true);

		if (slen <= 0) {
		do_unknown:
			slen = fr_dict_unknown_afrom_oid_substr(ctx, NULL, &da_unknown, parent,
								&FR_SBUFF_IN(p, strlen(p)), &bareword_terminals);
			if (slen <= 0) {
				p += -slen;

			error:
				fr_pair_list_free(&head);
				*token = T_INVALID;
				return -(p - buffer);
			}

			da = da_unknown;
		}

		next = p + slen;

		if ((size_t) (next - p) >= sizeof(raw.l_opand)) {
			fr_dict_unknown_free(&da);
			fr_strerror_printf("Attribute name too long");
			goto error;
		}

		memcpy(raw.l_opand, p, next - p);
		raw.l_opand[next - p] = '\0';
		raw.r_opand[0] = '\0';

		p = next;
		fr_skip_whitespace(p);

		/*
		 *	There must be an operator here.
		 */
		raw.op = gettoken(&p, raw.r_opand, sizeof(raw.r_opand), false);
		if ((raw.op  < T_EQSTART) || (raw.op  > T_EQEND)) {
			fr_dict_unknown_free(&da);
			fr_strerror_printf("Expecting operator");
			goto error;
		}

		fr_skip_whitespace(p);

		/*
		 *	Allow grouping attributes.
		 */
		if ((da->type == FR_TYPE_GROUP) || (da->type == FR_TYPE_TLV) || (da->type == FR_TYPE_STRUCT)) {
			if (*p != '{') {
				fr_strerror_printf("Group list for %s MUST start with '{'", da->name);
				goto error;
			}
			p++;

			vp = fr_pair_afrom_da(ctx, da);
			if (!vp) goto error;

			/*
			 *	Find the new root attribute to start encoding from.
			 */
			parent = fr_dict_attr_ref(da);
			if (!parent) parent = da;

			slen = ncc_pair_list_afrom_substr(vp, parent, p, &vp->vp_group, &last_token, depth + 1);
			if (slen <= 0) {
				talloc_free(vp);
				goto error;
			}

			if (last_token != T_RCBRACE) {
			failed_group:
				fr_strerror_printf("Failed to end group list with '}'");
				talloc_free(vp);
				goto error;
			}

			p += slen;
			fr_skip_whitespace(p);
			if (*p != '}') goto failed_group;
			p++;

		} else {
			fr_token_t quote;
			char const *q;

			/*
			 *	Get the RHS thing.
			 */
			quote = gettoken(&p, raw.r_opand, sizeof(raw.r_opand), false);
			if (quote == T_EOL) {
				fr_strerror_printf("Failed to get value");
				goto error;
			}

			switch (quote) {
				/*
				 *	Perhaps do xlat's
				 */
			case T_DOUBLE_QUOTED_STRING:
				/*
				 *	Only report as double quoted if it contained valid
				 *	a valid xlat expansion.
				 */
				q = strchr(raw.r_opand, '%');
				if (q && (q[1] == '{')) {
					raw.quote = quote;
				} else {
					raw.quote = T_SINGLE_QUOTED_STRING;
				}
				break;

			case T_SINGLE_QUOTED_STRING:
			case T_BACK_QUOTED_STRING:
			case T_BARE_WORD:
				raw.quote = quote;
				break;

			default:
				fr_strerror_printf("Failed to find expected value on right hand side in %s", da->name);
				goto error;
			}

			fr_skip_whitespace(p);

			/*
			 *	Regular expressions get sanity checked by pair_make().
			 *
			 *	@todo - note that they will also be escaped,
			 *	so we may need to fix that later.
			 */
			if ((raw.op == T_OP_REG_EQ) || (raw.op == T_OP_REG_NE)) {
				vp = fr_pair_afrom_da(ctx, da);
				if (!vp) goto error;
				vp->op = raw.op;

				fr_pair_value_bstrndup(vp, raw.r_opand, strlen(raw.r_opand), false);
			} else {
				/*
				 *	All other attributes get the name
				 *	parsed.
				 */
				vp = fr_pair_afrom_da(ctx, da);
				if (!vp) goto error;
				vp->op = raw.op;

				/*
				 *	We don't care what the value is, so
				 *	ignore it.
				 */
				if ((raw.op == T_OP_CMP_TRUE) || (raw.op == T_OP_CMP_FALSE)) goto next;

				/*
				 *	fr_pair_raw_from_str() only returns this when
				 *	the input looks like it needs to be xlat'd.
				 */
				if (raw.quote == T_DOUBLE_QUOTED_STRING) {
					if (fr_pair_mark_xlat(vp, raw.r_opand) < 0) {
						talloc_free(vp);
						goto error;
					}

					/*
					 *	Parse it ourselves.  The RHS
					 *	might NOT be tainted, but we
					 *	don't know.  So just mark it
					 *	as such to be safe.
					 */
				} else if (fr_pair_value_from_str(vp, raw.r_opand, -1, '"', true) < 0) {
					talloc_free(vp);
					goto error;
				}
			}
		}

	next:
		/*
		 *	Free the unknown attribute, we don't need it any more.
		 */
		fr_dict_unknown_free(&da);

		*tail = vp;
		tail = &((*tail)->next);

		/*
		 *	Now look for EOL, hash, etc.
		 */
		if (!*p || (*p == '#') || (*p == '\n')) {
			last_token = T_EOL;
			break;
		}

		/*
		 *	Check for nested groups.
		 */
		if ((depth > 0) && (p[0] == ' ') && (p[1] == '}')) p++;

		/*
		 *	Stop at '}', too, if we're inside of a group.
		 */
		if ((depth > 0) && (*p == '}')) {
			last_token = T_RCBRACE;
			break;
		}

		if (*p != ',') {
			fr_strerror_printf("Expected ',', got '%c' at offset %zu", *p, p - buffer);
			goto error;
		}
		p++;
		last_token = T_COMMA;
	}

	if (head) fr_pair_add(list, head);

	/*
	 *	And return the last token which we read.
	 */
	*token = last_token;
	return p - buffer;
}

/**
 * Read one line of attribute/value pairs into a list.
 * The line may specify multiple attributes separated by commas.
 *
 * Same as fr_pair_list_afrom_str (pair_legacy.c), but call ncc_pair_list_afrom_substr instead of fr_pair_list_afrom_substr.
 */
fr_token_t ncc_pair_list_afrom_str(TALLOC_CTX *ctx, fr_dict_t const *dict, char const *buffer, fr_pair_list_t *list)
{
	fr_token_t token;

	(void) ncc_pair_list_afrom_substr(ctx, fr_dict_root(dict), buffer, list, &token, 0);
	return token;
}

/**
 * Read valuepairs from the fp up to End-Of-File.
 *
 * Same as fr_pair_list_afrom_file (pair_legacy.c), but call ncc_pair_list_afrom_str instead of fr_pair_list_afrom_str.
 */
int ncc_pair_list_afrom_file(TALLOC_CTX *ctx, fr_dict_t const *dict, fr_pair_list_t *out, FILE *fp, bool *pfiledone)
{
	fr_token_t	last_token = T_EOL;
	bool		found = false;
	fr_cursor_t	cursor;
	char		buf[8192];

	fr_cursor_init(&cursor, out);

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		fr_cursor_t append;
		fr_pair_t   *vp;

		/*
		 *      If we get a '\n' by itself, we assume that's
		 *      the end of that VP list.
		 */
		if (buf[0] == '\n') {
			if (found) {
				*pfiledone = false;
				return 0;
			}
			continue;
		}

		/*
		 *	Comments get ignored
		 */
		if (buf[0] == '#') continue;

		/*
		 *	Read all of the attributes on the current line.
		 *
		 *	If we get nothing but an EOL, it's likely OK.
		 */
		vp = NULL;
		last_token = ncc_pair_list_afrom_str(ctx, dict, buf, &vp);
		if (!vp) {
			if (last_token == T_EOL) break;

			/*
			 *	Didn't read anything, but the previous
			 *	line wasn't EOL.  The input file has a
			 *	format error.
			 */
			*pfiledone = false;
			vp = fr_cursor_head(&cursor);
			if (vp) fr_pair_list_free(&vp);
			*out = NULL;
			return -1;
		}

		found = true;
		fr_cursor_init(&append, &vp);
		fr_cursor_merge(&cursor, &append);
		(void) fr_cursor_tail(&cursor);
	}

	*pfiledone = true;
	return 0;
}
