/**
 * @file ncc_parse.c
 * @brief Parsing functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 */

#include "ncc_util.h"


/*
 * Tables which allow to obtain min/max bounds for each of integer types as a string.
 */
//#define UINT64_MAX_STR STRINGIFY(UINT64_MAX)
// => "(18446744073709551615UL)"... not good enough. BTW it's done that way in "inet.c": STRINGIFY(UINT16_MAX)

fr_table_num_ordered_t const fr_type_int_max_table[] = {
	{ "255",                  FR_TYPE_UINT8 },
	{ "65536",                FR_TYPE_UINT16 },
	{ "4294967295",           FR_TYPE_UINT32 },
	{ "18446744073709551615", FR_TYPE_UINT64 },

	{ "127",                  FR_TYPE_INT8 },
	{ "32767",                FR_TYPE_INT16 },
	{ "2147483647",           FR_TYPE_INT32 },
	{ "9223372036854775807",  FR_TYPE_INT64 },
};
size_t fr_type_int_max_table_len = NUM_ELEMENTS(fr_type_int_max_table);

fr_table_num_ordered_t const fr_type_int_min_table[] = {
	{ "0",                    FR_TYPE_UINT8 },
	{ "0",                    FR_TYPE_UINT16 },
	{ "0",                    FR_TYPE_UINT32 },
	{ "0",                    FR_TYPE_UINT64 },

	{ "-128",                 FR_TYPE_INT8 },
	{ "-32768",               FR_TYPE_INT16 },
	{ "-2147483648",          FR_TYPE_INT32 },
	{ "-9223372036854775808", FR_TYPE_INT64 },
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

	if (*value == '-') { /* Don't let strtoull happily process negative values. */
	error:
		fr_strerror_printf("Invalid value \"%s\" for unsigned integer", value);
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

	if (*p != '\0' && !is_whitespace(p)) goto error;

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
	int ret;
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

	type = FR_BASE_TYPE(type);

	/*
	 *	Check for zero length strings
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
	 *	First pass for integers.
	 */
	switch (type) {
	case FR_TYPE_UINT8:
	case FR_TYPE_UINT16:
	case FR_TYPE_UINT32:
	case FR_TYPE_UINT64:
		/*
		 *	Function checks for overflows and trailing garbage, and calls fr_strerror_printf to set an error.
		 *	In case of ERANGE, we set our own error message (which is common to all "out of bounds" cases).
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
		 *	Function checks for overflows and trailing garbage, and calls fr_strerror_printf to set an error.
		 *	In case of ERANGE, we set our own error message (which is common to all "out of bounds" cases).
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
		fr_strerror_printf("Invalid type '%s' (%i)",
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
 * Note: not all FreeRADIUS types are supported.
 *
 * @param[out] out        where to write the parsed value (size depends on the type).
 *                        NULL allows to discard output (validity check only).
 * @param[in]  type       type of value being parsed (base type | optional qualifiers).
 * @param[in]  value      string which contains the value to parse.
 * @param[in]  inlen      length of value, if value is \0 terminated inlen may be -1.
 * @param[in]  parse_ctx  parse context which defines checks to perform on the parsed value.
 *
 * @return -1 = error, 0 = success and value is not modified, 1 = value is forced.
 */
int ncc_parse_value_from_str(void *out, uint32_t type, char const *value, ssize_t inlen, ncc_parse_ctx_t const *parse_ctx)
{
	int ret = 0; /* Set to 1 if value is forced. */

	if (ncc_value_from_str(out, type, value, inlen) < 0) return -1;

	if (!parse_ctx) return 0;

	type = FR_BASE_TYPE(parse_ctx->type);
	uint32_t type_check = parse_ctx->type_check;

	bool ignore_zero = (type_check & NCC_TYPE_IGNORE_ZERO);
	bool not_zero = (type_check & NCC_TYPE_NOT_ZERO);
	bool not_negative = (type_check & NCC_TYPE_NOT_NEGATIVE);
	bool force_min = (type_check & NCC_TYPE_FORCE_MIN);
	bool force_max = (type_check & NCC_TYPE_FORCE_MAX);
	bool check_min = (type_check & NCC_TYPE_CHECK_MIN);
	bool check_max = (type_check & NCC_TYPE_CHECK_MAX);

#define CHECK_IGNORE_ZERO \
	if (ignore_zero && !v) return 0;

#define CHECK_NOT_ZERO \
	if (not_zero && !v) { \
		fr_strerror_printf("Invalid value (cannot be zero)"); \
		return -1; \
	}

#define CHECK_VALUE(_type, _ctx_type) { \
	memcpy(&v, out, sizeof(v)); \
	CHECK_IGNORE_ZERO \
	CHECK_NOT_ZERO \
	if (not_negative && v < 0) { \
		fr_strerror_printf("Invalid value \"%pV\" (cannot be negative)", fr_box_##_type(v)); \
		return -1; \
	} \
	if (force_min) NCC_VALUE_BOUND_CHECK(ret, _type, v, >=, parse_ctx->_ctx_type.min); \
	if (force_max) NCC_VALUE_BOUND_CHECK(ret, _type, v, <=, parse_ctx->_ctx_type.max); \
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

	/*
	 * Extract the value, and check the type is handled.
	 * Perform specified checks.
	 */
	switch (type) {
	case FR_TYPE_UINT32:
	{
		uint32_t v;
		CHECK_VALUE(uint32, uinteger)
	}
		break;

	case FR_TYPE_UINT64:
	{
		uint64_t v;
		CHECK_VALUE(uint64, uinteger)
	}
		break;

	case FR_TYPE_INT32:
	{
		int32_t v;
		CHECK_VALUE(int32, integer)
	}
		break;

	case FR_TYPE_INT64:
	{
		int64_t v;
		CHECK_VALUE(int64, integer)
	}
		break;

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

	default:
		fr_strerror_printf("Invalid type '%s' (%i) in parse context",
		                   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type);
		return -1;
	}

	return ret;
}


/**
 * Debug a configuration item. If multi-valued, iterate over all values and print each of them.
 * Items are printed using the fr_box_* macro corresponding to their type.
 */
static char const config_spaces[] = "                                                                                ";
void ncc_parser_config_item_debug(int type, char const *name, void *pvalue, size_t vsize, int depth, char const *prefix)
{
	if (!pvalue) return;

	bool multi = (type & FR_TYPE_MULTI);
	int base_type = FR_BASE_TYPE(type);

#define CONF_SPACE(_depth) ((_depth) * 2)

#define DEBUG_CONF_BOX(_type) do { \
	if (prefix && prefix[0] != '\0') DEBUG("%.*s%s.%s = %pV", CONF_SPACE(depth), config_spaces, prefix, name, fr_box_##_type(value)); \
	else DEBUG("%.*s%s = %pV", CONF_SPACE(depth), config_spaces, name, fr_box_##_type(value)); \
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
			ncc_parser_config_item_debug(base_type, name, (void *)(value_arr + (i * vsize)), vsize, depth, prefix);
		}

	} else {
		switch (base_type) {
		CASE_CONF_BOX_VALUE(FR_TYPE_BOOL, bool, boolean);

		CASE_CONF_BOX_VALUE(FR_TYPE_FLOAT64, double, float64);
		CASE_CONF_BOX_VALUE(FR_TYPE_FLOAT32, float, float32);

		CASE_CONF_BOX_VALUE(FR_TYPE_UINT64, uint64_t, uint64);
		CASE_CONF_BOX_VALUE(FR_TYPE_UINT32, uint32_t, uint32);

		CASE_CONF_BOX_VALUE(FR_TYPE_INT64, int64_t, int64);
		CASE_CONF_BOX_VALUE(FR_TYPE_INT32, int32_t, int32);

		case FR_TYPE_STRING:
		{
			char *value = *(char **)pvalue;
			if (value) DEBUG_CONF_BOX(strvalue);
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
		ncc_parser_config_item_debug(rule_type, rule_p->name, ((uint8_t *)config + rule_p->offset), sizeof(_c_type), depth, prefix); \
		break;

	/*
	 * Iterate over parser rules.
	 */
	for (rule_p = rules; rule_p->name; rule_p++) {
		int rule_type = rule_p->type;
		int type = FR_BASE_TYPE(rule_type);

		switch (type) {
		CASE_PARSER_CONF_TYPE(FR_TYPE_STRING, char *);
		CASE_PARSER_CONF_TYPE(FR_TYPE_BOOL, bool);

		CASE_PARSER_CONF_TYPE(FR_TYPE_FLOAT64, double);
		CASE_PARSER_CONF_TYPE(FR_TYPE_FLOAT32, float);

		CASE_PARSER_CONF_TYPE(FR_TYPE_UINT64, uint64_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_UINT32, uint32_t);

		CASE_PARSER_CONF_TYPE(FR_TYPE_INT64, int64_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_INT32, int32_t);

		CASE_PARSER_CONF_TYPE(FR_TYPE_TIME_DELTA, fr_time_delta_t);
		CASE_PARSER_CONF_TYPE(FR_TYPE_IPV4_ADDR, fr_ipaddr_t);

		case FR_TYPE_SUBSECTION:
		{
			DEBUG("%.*s%s {", CONF_SPACE(depth), config_spaces, rule_p->name);

			ncc_parser_config_debug(rule_p->subcs, config, depth + 1, prefix ? rule_p->name : NULL);

			DEBUG("%.*s}", CONF_SPACE(depth), config_spaces);
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
