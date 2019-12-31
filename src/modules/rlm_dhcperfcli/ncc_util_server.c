/**
 * @file ncc_util_server.c
 * @brief Server utility functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 * - libfreeradius-server, libfreeradius-unlang
 */

#include "ncc_util.h"



static void ncc_item_parent_section(char const **section, char const **sp_section, CONF_ITEM *ci)
{
	CONF_SECTION *cs = cf_item_to_section(cf_parent(ci));

	/* The item section is not top level if it has a parent.
	 * In this case, print section name along with the item.
	 */
	if (cf_parent(cs)) {
		*section = cf_section_name1(cs);
		*sp_section = " ";
	} else {
		*section = "";
		*sp_section = "";
	}
}

/**
 * Check that a configuration item has its value in the specified table.
 * If not, return an error and produce a helpful log message.
 */
static int ncc_conf_item_in_table(int32_t *out, fr_table_num_ordered_t const *table, size_t table_len, CONF_ITEM *ci)
{
	CONF_PAIR *cp = cf_item_to_pair(ci);
	char const *item_name = cf_pair_attr(cp);
	char const *section, *sp_section;

	ncc_item_parent_section(&section, &sp_section, ci);

	if (ncc_str_in_table(out, table, table_len, cf_pair_value(cp)) < 0) {
		cf_log_perr(cp, "Invalid value \"%s\" for %s%s\"%s\"", cf_pair_value(cp), section, sp_section, item_name);
		return -1;
	}

	return 0;
}

/**
 * Custom generic parsing function which performs value checks on a conf item.
 *
 * @param[in]  ctx     talloc context.
 * @param[out] out     where to write parsed value.
 * @param[in]  parent  (unused) "base" argument passed to cf_pair_parse_value.
 * @param[in]  ci      configuration item to parse.
 * @param[in]  rule    parser rule, which must contain a ncc_parse_ctx_t in uctx.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_conf_item_parse(TALLOC_CTX *ctx, void *out, UNUSED void *parent, CONF_ITEM *ci, CONF_PARSER const *rule)
{
	ncc_parse_ctx_t *parse_ctx = (ncc_parse_ctx_t *)rule->uctx;
	/*
	 * Note: This is supposed to be const. We allow ourselves to use it for convenience.
	 */

	uint32_t type = FR_BASE_TYPE(rule->type);

	CONF_PAIR *cp = cf_item_to_pair(ci);
	char const *item_name = cf_pair_attr(cp);
	char const *section, *sp_section;

	ncc_item_parent_section(&section, &sp_section, ci);

	if (!parse_ctx) {
		/*
		 * If no parse context is provided, just try to convert string value to target type.
		 */
		if (ncc_value_from_str(out, rule->type, cf_pair_value(cp), -1) < 0) {
			cf_log_perr(cp, "Failed to parse %s%s\"%s\"", section, sp_section, item_name);
			return -1;
		}

		return 0;
	}

	/* The parse context contains the base type (because it can be used without the CONF_PARSER rule).
	 * In this function, it must be the same of that from "rule".
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

	if (type == FR_TYPE_INT32 && check_table) {
		/* Value can be provided as integer, or as a string looked up in table.
		 */
		if (ncc_value_from_str(out, type, cf_pair_value(cp), -1) < 0) {
			/* Failed to parse: this is not an integer.
			 * Try finding string value from table.
			 */
			if (ncc_conf_item_in_table(out, parse_ctx->fr_table,
			                           *parse_ctx->fr_table_len_p, ci) < 0) {
				return -1;
			}
		}

	} else {
		//if (cf_pair_parse_value(ctx, out, parent, ci, rule) < 0) {
		//	return -1;
		//}
		// Use our own parsing function (catches more errors than "cf_pair_parse_value", which needs some work).

		if (ncc_value_from_str(out, type, cf_pair_value(cp), -1) < 0) {
			cf_log_perr(cp, "Failed to parse %s%s\"%s\"", section, sp_section, item_name);
			return -1;
		}
	}

#define CHECK_IGNORE_ZERO \
	if (ignore_zero && !v) return 0;

#define CHECK_NOT_ZERO \
	if (not_zero && !v) { \
		cf_log_err(ci, "Invalid value for %s%s\"%s\" (cannot be zero)", section, sp_section, item_name); \
		return -1; \
	}

#define CHECK_NOT_NEGATIVE \
	if (not_negative && v < 0) { \
		cf_log_err(ci, "Invalid value for %s%s\"%s\" (cannot be negative)", section, sp_section, item_name); \
		return -1; \
	}

#define CHECK_VALUE_MIN(_type, _ctx_type) { \
	if (check_min && v < parse_ctx->_ctx_type.min) { \
		cf_log_err(ci, "Invalid value for %s%s\"%s\" (min: %pV)", section, sp_section, item_name, \
		           fr_box_##_type(parse_ctx->_ctx_type.min)); \
		return -1; \
	} \
}

#define CHECK_VALUE_MAX(_type, _ctx_type) { \
	if (check_max && v > parse_ctx->_ctx_type.max) { \
		cf_log_err(ci, "Invalid value for %s%s\"%s\" (max: %pV)", section, sp_section, item_name, \
		           fr_box_##_type(parse_ctx->_ctx_type.max)); \
		return -1; \
	} \
}

#define CHECK_VALUE_TABLE { \
	if (check_table && parse_ctx->fr_table) { \
		FR_TABLE_LEN_FROM_PTR(parse_ctx->fr_table); \
		if (fr_table_str_by_value(parse_ctx->fr_table, v, NULL) == NULL) { \
			cf_log_err(ci, "Invalid value for %s%s\"%s\" (unknown)", section, sp_section, item_name); \
			return -1; \
		} \
	} \
}

#define CHECK_STR_TABLE { \
	if (check_table && parse_ctx->fr_table) { \
		FR_TABLE_LEN_FROM_PTR(parse_ctx->fr_table); \
		if (fr_table_value_by_str(parse_ctx->fr_table, v, FR_TABLE_NOT_FOUND) == FR_TABLE_NOT_FOUND) { \
			cf_log_err(ci, "Invalid value for %s%s\"%s\" (unknown)", section, sp_section, item_name); \
			return -1; \
		} \
	} \
}

#define CHECK_VALUE(_type, _ctx_type) { \
	memcpy(&v, out, sizeof(v)); \
	DEBUG3("Checking configured item %s%s\"%s\": type " STRINGIFY(_type) ", value: \"%pV\"", \
	       section, sp_section, item_name, fr_box_##_type(v)); \
	CHECK_IGNORE_ZERO \
	CHECK_NOT_ZERO \
	CHECK_NOT_NEGATIVE \
	if (force_min) NCC_CI_VALUE_BOUND_CHECK(ci, _type, item_name, v, >=, parse_ctx->_ctx_type.min); \
	if (force_max) NCC_CI_VALUE_BOUND_CHECK(ci, _type, item_name, v, <=, parse_ctx->_ctx_type.max); \
	memcpy(out, &v, sizeof(v)); \
	CHECK_VALUE_MIN(_type, _ctx_type) \
	CHECK_VALUE_MAX(_type, _ctx_type) \
}

#define CASE_CHECK_BOX_VALUE(_fr_type, _c_type, _box_type, _ctx_type) \
	case _fr_type: \
	{ \
		_c_type v; \
		CHECK_VALUE(_box_type, _ctx_type) \
		CHECK_VALUE_TABLE \
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
		cf_log_err(ci, "Invalid type '%s' (%i) in parse context for \"%s\"",
		           fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type, item_name);

		return -1;
	}

	return 0;
}

/*
 *	Convert a CONF_PAIR to a VALUE_PAIR.
 */
VALUE_PAIR *ncc_pair_afrom_cp(TALLOC_CTX *ctx, fr_dict_t const *dict, CONF_PAIR *cp)
{
	char const *attr, *value;
	fr_dict_attr_t const *da = NULL;
	VALUE_PAIR *vp;

	attr = cf_pair_attr(cp); /* Note: attr cannot be NULL. */

	//da = fr_dict_attr_by_name(dict, attr);
	// can't do that: this would only look into the provided dictionary.

	da = ncc_dict_attr_by_name(dict, attr);
	if (!da) {
		cf_log_err(cp, "Not a valid attribute: \"%s\"", attr);
		return NULL;
	}

	value = cf_pair_value(cp);
	if (!value) {
		cf_log_err(cp, "No value for attribute: \"%s\"", attr);
		return NULL;
	}

	vp = fr_pair_afrom_da(ctx, da);
	if (!vp) return NULL;

	/* If value is a double-quoted string, it might be an xlat expansion.
	 * If it is, set the vp as xlat.
	 */
	if (cf_pair_value_quote(cp) == T_DOUBLE_QUOTED_STRING) {

		/* Check if it is an xlat expansion (cf. fr_pair_raw_from_str) */
		char const *p = strchr(value, '%');
		if (p && (p[1] == '{')) {
			/* Mark it as xlat. */
			if (fr_pair_mark_xlat(vp, value) < 0) {
				PERROR("Error marking pair for xlat");
				talloc_free(vp);
				return NULL;
			}
			return vp;
		}
	}

	/* Parse the value (and mark it as 'tainted'). */
	if (fr_pair_value_from_str(vp, value, -1, '\0', true) < 0) {
		cf_log_err(cp, "%s", fr_strerror());
		talloc_free(vp);
		return NULL;
	}
	return vp;
}

static char const parse_spaces[] = "                                                                                                                                                                                                                                              ";

/* Equivalent to PAIR_SPACE and SECTION_SPACE (from cf_parse.c), but with depth directly provided.
 * (Needed because CONF_SECTION is opaque and no function exposes depth)
 */
#define CF_PAIR_SPACE(_cs_depth) ((_cs_depth + 1) * 2)
#define CF_SECTION_SPACE(_cs_depth) (_cs_depth * 2)

/**
 * Debug the start of a configuration section (custom parsing, i.e. not calling cf_section_parse).
 */
void ncc_cs_debug_start(CONF_SECTION *cs, int cs_depth)
{
	char const *cs_name1, *cs_name2;

	cs_name1 = cf_section_name1(cs);
	cs_name2 = cf_section_name2(cs);

	if (!cs_name2) {
		cf_log_debug(cs, "%.*s%s {", CF_SECTION_SPACE(cs_depth), parse_spaces, cs_name1);
	} else {
		cf_log_debug(cs, "%.*s%s %s {", CF_SECTION_SPACE(cs_depth), parse_spaces, cs_name1, cs_name2);
	}
}

/**
 * Debug the end of a configuration section (custom parsing, i.e. not calling cf_section_parse).
 */
void ncc_cs_debug_end(CONF_SECTION *cs, int cs_depth)
{
	cf_log_debug(cs, "%.*s}", CF_SECTION_SPACE(cs_depth), parse_spaces);
}

/**
 * Convert a config section into an attribute list.
 * Inspired from FreeRADIUS function map_afrom_cs (src\lib\server\map.c).
 * Note: requires libfreeradius-server.
 */
int ncc_pair_list_afrom_cs(TALLOC_CTX *ctx, fr_dict_t const *dict, VALUE_PAIR **out,
                           CONF_SECTION *cs, int cs_depth, unsigned int max)
{
	CONF_PAIR *cp;
	CONF_ITEM *ci;
	char buf[4096];

	unsigned int total = 0;

	ncc_cs_debug_start(cs, cs_depth);

	ci = cf_section_to_item(cs);

	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {

		if (total++ == max) {
			cf_log_err(ci, "Too many attributes (max: %u)", max);
		error:
			fr_pair_list_free(out);
			return -1;
		}

		if (!cf_item_is_pair(ci)) {
			cf_log_err(ci, "Entry is not in \"attribute = value\" format");
			goto error;
		}

		cp = cf_item_to_pair(ci);
		rad_assert(cp != NULL);

		VALUE_PAIR *vp = ncc_pair_afrom_cp(ctx, dict, cp);
		if (!vp) goto error;

		fr_pair_add(out, vp);

		ncc_pair_snprint(buf, sizeof(buf), vp);
		cf_log_debug(cs, "%.*s%s", CF_PAIR_SPACE(cs_depth), parse_spaces, buf);
	}

	ncc_cs_debug_end(cs, cs_depth);

	return 0;
}
