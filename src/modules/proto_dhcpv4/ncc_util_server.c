/**
 * @file ncc_util_server.c
 * @brief Server utility functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 * - libfreeradius-server, libfreeradius-unlang
 */

#include "ncc_util.h"


/*
 *	Convert a CONF_PAIR to a VALUE_PAIR.
 */
VALUE_PAIR *ncc_pair_afrom_cp(TALLOC_CTX *ctx, fr_dict_t const *dict, CONF_PAIR *cp)
{
	char const *attr, *value;
	fr_dict_attr_t const *da;
	VALUE_PAIR *vp;

	attr = cf_pair_attr(cp); /* Note: attr cannot be NULL. */

	da = fr_dict_attr_by_name(dict, attr);
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

/*
 *	Convert a config section into an attribute list.
 *	Inspired from FreeRADIUS function map_afrom_cs (src\lib\server\map.c).
 *	Note: requires libfreeradius-server.
 */
int ncc_pair_list_afrom_cs(TALLOC_CTX *ctx, fr_dict_t const *dict, VALUE_PAIR **out, CONF_SECTION *cs, unsigned int max)
{
	CONF_PAIR *cp;
	CONF_ITEM *ci;
	char buf[4096];

	unsigned int total = 0;

	int cf_space = 2;
	cf_log_debug(cs, "%.*s%s {", cf_space, parse_spaces, cf_section_name(cs));

	ci = cf_section_to_item(cs);

	for (ci = cf_item_next(cs, NULL);
	     ci != NULL;
	     ci = cf_item_next(cs, ci)) {
		int cf_space = 4;

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
		cf_log_debug(cs, "%.*s%s", cf_space, parse_spaces, buf);
	}

	cf_log_debug(cs, "%.*s}", cf_space, parse_spaces);

	return 0;
}
