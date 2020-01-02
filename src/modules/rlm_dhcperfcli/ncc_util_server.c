/**
 * @file ncc_util_server.c
 * @brief Server utility functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 * - libfreeradius-server, libfreeradius-unlang
 */

#include "ncc_util.h"



/**
 * Get a conf item parent section "name" (and a separator for printing), unless it's top level.
 */
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
	char const *name = cf_pair_attr(cp);
	char const *value = cf_pair_value(cp);
	char const *section, *sp_section;

	ncc_item_parent_section(&section, &sp_section, ci);

	DEBUG3("Parsing: %s%s\"%s\": uctx ? %s, type: '%s' (%i), value: [%s]",
	       section, sp_section, name, parse_ctx ? "yes" : "no",
		   fr_table_str_by_value(fr_value_box_type_table, type, "?Unknown?"), type,
		   value);

	if (ncc_parse_value_from_str(out, type, value, -1, parse_ctx) < 0) {
		cf_log_perr(cp, "Failed to parse %s%s\"%s\"", section, sp_section, name);
		return -1;
	}

	// Note: Using our own parsing function (catches more errors than "cf_pair_parse_value", which needs some work).

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
