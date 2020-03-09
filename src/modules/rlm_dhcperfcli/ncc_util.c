/**
 * @file ncc_util.c
 * @brief General utility functions
 *
 * Requires FreeRADIUS libraries:
 * - libfreeradius-util
 */

#include "ncc_util.h"


/**
 * Peek into an event list to retrieve the timestamp of next event.
 *
 * Note: structures fr_event_list_t and fr_event_timer_t are opaque, so we have to partially redefine them
 * so we can access what we need.
 * (I know, this is dangerous. We'll be fine as long as they do not change.)
 * Ideally, this should be provided by FreeRADIUS lib. TODO: ask them ?
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

/**
 * Get next event from an array of event lists.
 */
int ncc_ev_lists_peek(fr_event_list_t **ev_lists, fr_time_t *when)
{
	int ret = 0;
	fr_time_t fte_min = 0;
	int i;
	size_t num = talloc_array_length(ev_lists);

	for (i = 0; i < num; i++) {
		fr_time_t fte_event;
		if (ncc_fr_event_timer_peek(ev_lists[i], &fte_event)) {
			if (!fte_min || fte_event < fte_min) fte_min = fte_event;
			*when = fte_min;
			ret = 1;
		}
	}

	return ret;
}

/**
 * Service all events for which the scheduled timer is reached.
 */
uint32_t ncc_ev_lists_service(fr_event_list_t **ev_lists, fr_time_t now)
{
	uint32_t num_processed = 0; /* Number of timers events triggered. */
	int i;
	size_t num = talloc_array_length(ev_lists);

	for (i = 0; i < num; i++) {
		/* If there's nothing to run right now, fr_event_timer_run sets "when" to the next event.
		 */
		fr_time_t when = now;
		while (fr_event_timer_run(ev_lists[i], &when)) {
			num_processed ++;
		}
	}

	return num_processed;
}


/**
 * Safely get the dictionary name of a dictionary attribute (or NULL).
 */
char const *ncc_attr_dict_name(fr_dict_attr_t const *da)
{
	fr_dict_t const *dict;
	fr_dict_attr_t const *da_root;

	if (!da) return NULL;

	dict = fr_dict_by_da(da);
	if (!dict) return NULL;

	da_root = fr_dict_root(dict);
	if (!da_root) return NULL;

	return da_root->name;
}

/**
 * Find a dictionary attribute by its name within a given dictionary.
 * If not found, fallback to internal and other dictionaries.
 *
 * @param[in] dict  dictionary where attribute is looked for.
 *                  If NULL the internal dictionary will be used.
 * @param[in] name  attribute to look for.
 *
 * @return the dictionary attribute (or NULL if it could not be found).
 */
fr_dict_attr_t const *ncc_dict_attr_by_name(fr_dict_t const *dict, char const *name)
{
	fr_dict_attr_t const *da = NULL;

	/* If a dictionary is specified, look into it first.
	 */
	if (dict) {
		da = fr_dict_attr_by_name(dict, name);
	}

	if (!da) {
		/*
		 * Fallback to internal and other dictionaries.
		 */
		fr_dict_attr_by_qualified_name(&da, dict, name, true);

		/* Note: fr_dict_attr_by_qualified_name allows to provide a protocol qualifier.
		 * E.g.: "dhcpv4.DHCP-Hostname" (non case sensitive).
		 * We don't need this, but it's not an issue either.
		 */
	}

	return da;
}

/**
 * Print information on a dictionary attribute (cf. function da_print_info_td from radict.c)
 *
 * <dictionary name> <OID> <attribute name> <type> <flags>
 * e.g.:
 * dhcperfcli      3004    Rate-Limit      string  internal,virtual
 */
void ncc_dict_attr_info_fprint(FILE *fp, fr_dict_attr_t const *da)
{
	char oid_str[512];
	char flags[256];

	if (!da) return;

	fr_dict_print_attr_oid(NULL, oid_str, sizeof(oid_str), NULL, da);

	fr_dict_snprint_flags(flags, sizeof(flags), fr_dict_by_da(da), da->type, &da->flags);

	fprintf(fp, "attr: [%s], OID: [%s], dict: [%s], type: [%s], flags: [%s]\n",
	        da->name, oid_str, ncc_attr_dict_name(da),
	        fr_table_str_by_value(fr_value_box_type_table, da->type, "?Unknown?"), flags);
}


/**
 * Wrapper to fr_pair_find_by_da, which just returns NULL if we don't have the dictionary attr.
 */
// now redundant with fr_pair_find_by_da: TODO: remove this.
VALUE_PAIR *ncc_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da)
{
	if (!da) return NULL;
	return fr_pair_find_by_da(head, da, TAG_ANY);
}

/**
 * Create a value pair and add it to a list of value pairs.
 * This is a copy of (now defunct) FreeRADIUS function radius_pair_create (from src/main/pair.c)
 */
VALUE_PAIR *ncc_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			                unsigned int attribute, unsigned int vendor)
{
	VALUE_PAIR *vp;

	MEM(vp = fr_pair_afrom_num(ctx, vendor, attribute));
	if (vps) fr_pair_add(vps, vp);

	return vp;
}

/**
 * Create a value pair from a dictionary attribute, and add it to a list of value pairs.
 */
VALUE_PAIR *ncc_pair_create_by_da(TALLOC_CTX *ctx, VALUE_PAIR **vps, fr_dict_attr_t const *da)
{
	VALUE_PAIR *vp;

	FN_ARG_CHECK(NULL, da);

	MEM(vp = fr_pair_afrom_da(ctx, da));
	if (vps) fr_pair_add(vps, vp);

	return vp;
}

/**
 * Copy the value from a pair to another, and the type also (e.g. VT_DATA).
 */
int ncc_pair_copy_value(VALUE_PAIR *to, VALUE_PAIR *from)
{
	to->type = from->type;
	return fr_value_box_copy(to, &to->data, &from->data);
}

/**
 * Set value of a pair (of any data type) from a string.
 * If the conversion is not possible, an error will be returned.
 *
 * Similar to FreeRADIUS's fr_pair_value_from_str, but with no de-quoting / unescaping of input string.
 * Also value is never considered as "tainted".
 *
 * @param[out] vp       where to write the output string.
 * @param[in]  value    string value to convert.
 *
 * @return -1 = error, 0 = success.
 */
int ncc_pair_value_from_str(VALUE_PAIR *vp, char const *value)
{
	fr_type_t type = vp->da->type;

	vp->type = VT_DATA;

	/* Note: if 4th parameter (dst_enumv) is NULL, string enum values won't be converted.
	 */
	if (fr_value_box_from_str(vp, &vp->data, &type, vp->da, value, strlen(value), '\0', false) < 0) return -1;

	return 0;
}

/**
 * Copy a single VP.
 * (FreeRADIUS's fr_pair_copy, altered to work with pre-compiled xlat)
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

/**
 * Copy a list of VP.
 * (FreeRADIUS's fr_pair_list_copy, altered to work with pre-compiled xlat)
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

/**
 * Append a list of VP. (inspired from FreeRADIUS's fr_pair_list_copy.)
 * Note: contrary to fr_pair_list_copy, this preserves the order of the value pairs.
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

/**
 * Print a list of VP.
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

/**
 * Print one attribute and value to a string.
 * Similar to FreeRADIUS fr_pair_snprint, but prints 'x' for XLAT, '=' for DATA instead of the operator.
 * Also, we don't handle tags here.
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

/**
 * Read one line of values into a list.
 * The line may specify multiple values separated by commas.
 * All VP's are created using the same (provided) dictionary attribute.
 * Inspired from FreeRADIUS function fr_pair_list_afrom_str.
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

/**
 * Read values from one line using the fp.
 * Inspired from FreeRADIUS function fr_pair_list_afrom_file.
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
 * Read pairs from an array of strings (must have a NULL terminator).
 * Append them to the provided list.
 * Inspired from FreeRADIUS function fr_pair_list_afrom_file.
 */
int ncc_pair_list_afrom_strings(TALLOC_CTX *ctx, fr_dict_t const *dict, VALUE_PAIR **out, char const **strings)
{
	int i = 0;
	FR_TOKEN last_token = T_EOL;
	fr_cursor_t cursor;

	VALUE_PAIR *vp = NULL;
	fr_cursor_init(&cursor, out);

	while (strings[i] != NULL) {
		VALUE_PAIR *next;

		vp = NULL;
		last_token = fr_pair_list_afrom_str(ctx, dict, strings[i], &vp);
		if (!vp) {
			if (last_token != T_EOL) goto error;
			break;
		}

		do {
			next = vp->next;
			fr_cursor_append(&cursor, vp);
		} while (next && (vp = next));

		i++;
	}

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

	DEBUG4("outlen: %zu, in_len: %zu, num_line: %u, prefix_len: %u, needed: %zu\n",
	       outlen, in_len, num_line, prefix_len, needed);

	CHECK_BUFFER_SIZE(NULL, needed, outlen);

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
 * @param[out] out     where to write the output string (size must be at least NCC_ETHADDR_STRLEN).
 * @param[in]  outlen  size of output buffer.
 * @param[in]  addr    pointer on buffer which contains the 6 octets of the ethernet address.
 *
 * @return pointer to the output buffer.
 */
char *ncc_ether_addr_snprint(char *out, size_t outlen, const uint8_t *addr)
{
	size_t len;
	char *p = out;

	FN_ARG_CHECK(NULL, out);
	FN_ARG_CHECK(NULL, addr);

	len = snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
	               addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	ERR_IF_TRUNCATED_LEN(p, outlen, len);
	return out;
}


/**
 * Print a difference between two timestamps (pre-parsed as hour / min / sec / usec).
 * Internal helper function.
 *
 * @param[out] out       where to write the output string.
 * @param[in]  outlen    size of output buffer.
 * @param[in]  decimals  number of decimals to print in output (0-6).
 * @param[in]  hour      number of hours.
 * @param[in]  min       number of minutes (0-59).
 * @param[in]  min       number of seconds (0-59).
 * @param[in]  usec      number of microseconds.
 *
 * @return pointer to the output buffer.
 */
static char *_ncc_delta_time_snprint(char *out, size_t outlen, uint8_t decimals,
                                     uint32_t hour, uint32_t min, uint32_t sec, uint32_t usec)
{
	size_t len;
	char *p = out;

	if (hour > 0) {
		len = snprintf(p, outlen, "%u:%.02u:%.02u", hour, min, sec);
	} else if (min > 0) {
		len = snprintf(p, outlen, "%u:%.02u", min, sec);
	} else {
		len = snprintf(p, outlen, "%u", sec);
	}
	ERR_IF_TRUNCATED_LEN(p, outlen, len);

	if (decimals) {
		char buffer[8];
		sprintf(buffer, ".%06u", usec);
		buffer[decimals + 1] = '\0';

		len = snprintf(p, outlen, "%s", buffer);
		ERR_IF_TRUNCATED_LEN(p, outlen, len);
	}

	return out;
}

/**
 * Print to a string buffer a difference between two timestamps (struct timeval).
 * Output format: [[<HH>:]<MI>:]<SS>[.<d{1,6}>]
 *
 * @param[out] out       where to write the output string.
 * @param[in]  outlen    size of output buffer. NCC_TIME_STRLEN is sufficient for HH < 100 with 6 decimals.
 * @param[in]  from      pointer on oldest timestamp.
 * @param[in]  when      pointer on most recent timestamp (or NULL to use current time).
 * @param[in]  decimals  number of decimals to print in output (0-6).
 *
 * @return pointer to the output buffer.
 */
char *ncc_delta_time_snprint(char *out, size_t outlen, struct timeval *from, struct timeval *when, uint8_t decimals)
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

	return _ncc_delta_time_snprint(out, outlen, decimals, hour, min, sec, usec);
}

/**
 * Print to a string buffer a difference between two timestamps (fr_time_t).
 * Output format: [[<HH>:]<MI>:]<SS>[.<d{1,6}>]
 *
 * @param[out] out       where to write the output string.
 * @param[in]  outlen    size of output buffer. NCC_TIME_STRLEN is sufficient for HH < 100 with 6 decimals.
 * @param[in]  fte_from  oldest timestamp.
 * @param[in]  fte_to    most recent timestamp (or 0 to use current time).
 * @param[in]  decimals  number of decimals to print in output (0-6).
 *
 * @return pointer to the output buffer.
 */
char *ncc_fr_delta_time_snprint(char *out, size_t outlen, fr_time_t fte_from, fr_time_t fte_to, uint8_t decimals)
{
	fr_time_delta_t delta;
	uint32_t delta_sec, hour, min, sec, usec;

	FN_ARG_CHECK(NULL, out);
	FN_ARG_CHECK(NULL, fte_from);

	if (fte_to && fte_to < fte_from) {
		fr_strerror_printf("Cannot have a negative time difference");
		return NULL;
	}

	/* If second timestamp is not specified, use current time. */
	if (!fte_to) {
		fte_to = fr_time();
	}

	delta = fte_to - fte_from;
	delta_sec = delta / NSEC;

	hour = delta_sec / 3600;
	min = (delta_sec % 3600) / 60;
	sec = (delta_sec % 3600) % 60;
	usec = (delta / 1000) % USEC;

	return _ncc_delta_time_snprint(out, outlen, decimals, hour, min, sec, usec);
}

/**
 * Print to a string buffer the current absolute date/time, with specified format for strftime.
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
 * Print retransmissions breakdown by number of retransmissions per request sent.
 * e.g. "#1: 10 (2.4%), #2: 5 (1.2%)" means that:
 * - 10 packets (2.4% of total requests) have been retransmitted at least once.
 * - 5 packets (1.2% of total requests) have been retransmitted two times (exactly, because there is no #3).
 *
 * @param[out] out       where to write the output string.
 * @param[in]  outlen    size of output buffer.
 * @param[in]  num_sent  total number of requests sent.
 * @param[in]  breakdown talloc array of retransmissions breakdown.
 *
 * @return pointer to the output buffer.
 */
char *ncc_retransmit_snprint(char *out, size_t outlen, uint32_t num_sent, uint32_t *breakdown)
{
	int i;
	char *p = out;
	size_t len = 0;
	size_t retransmit_max = talloc_array_length(breakdown);

	*p = '\0';

	if (num_sent == 0 || !breakdown) return out;

	for (i = 0; i < retransmit_max; i++) {
		/* Stop at the first 0. Everything after that is necessarily also 0.
		 * And limit printing to the 10 first entries.
		 */
		if (breakdown[i] == 0 || i >= 10) break;

		len = snprintf(p, outlen, "%s#%u: %u (%.1f%%)", (i ? ", " : ""),
		               i + 1, breakdown[i], 100 * (float)breakdown[i] / num_sent);
		ERR_IF_TRUNCATED_LEN(p, outlen, len);
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
	 * Allow to just have [:]<port> (no host address specified).
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
	 * Otherwise delegate parsing to fr_inet_pton_port.
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
 * Convert a struct timeval to float.
 */
double ncc_timeval_to_float(struct timeval *in)
{
	double value = (in->tv_sec + (double)in->tv_usec / USEC);
	return value;
}

/**
 * Convert a float to struct timeval.
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

/**
 * Convert a fr_time to float.
 */
double ncc_fr_time_to_float(fr_time_delta_t in)
{
	return (double)in / NSEC;
}

/**
 * Convert a float to fr_time.
 */
fr_time_t ncc_float_to_fr_time(double in)
{
	return (in * NSEC);
}

/**
 * Check that a string represents a valid floating point number (e.g. 3, 2.5, .542).
 * If so convert it to float64.
 * "out" may be NULL, in which case this is just a format check.
 */
bool ncc_str_to_float(double *out, char const *in, bool allow_negative)
{
	double num;
	uint32_t type = FR_TYPE_FLOAT64;
	if (!allow_negative) type |= NCC_TYPE_NOT_NEGATIVE;

	if (ncc_value_from_str(NULL, &num, type, in, -1) < 0) return false;

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

/**
 * Trim a string from spaces (left and right), while complying with an input length limit.
 * Output buffer must be large enough to store the resulting string.
 * Returns the number of characters printed, excluding the terminating '\0'.
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

/**
 * Generate a random string.
 * Similar to fr_rand_str, but accepts the array of allowed characters as argument.
 *
 * @param[out] out          where to write the output string.
 * @param[in]  len          length of output string to generate.
 * @param[in]  randstr      array to pick random characters from.
 * @param[in]  randstr_len  length of randstr (or -1 to use strlen).
 */
void ncc_rand_str(uint8_t *out, size_t len, char *randstr, ssize_t randstr_len)
{
	uint8_t *p = out, *end = p + len;
	unsigned int word, mod;
	uint8_t byte;

	if (randstr_len < 0) randstr_len = strlen(randstr);

	if (randstr_len == 0) { /* Ensure we don't crash. */
		out[0] = '\0';
		return;
	}

#define FILL(_expr) \
while (p < end) { \
	if ((mod = ((p - out) & (sizeof(word) - 1))) == 0) word = fr_rand(); \
	byte = ((uint8_t *)&word)[mod]; \
	*p++ = (_expr); \
}

	FILL(randstr[byte % randstr_len]);
	out[len] = '\0';
}

/**
 * Initialize a fr_fast_rand_t with random seed values.
 */
void ncc_rand_ctx_init(fr_fast_rand_t *rand_ctx)
{
	rand_ctx->a = fr_rand();
	rand_ctx->b = fr_rand();
}

/**
 * Generate a random string.
 * Same as ncc_rand_str but using fr_fast_rand instead of fr_rand.
 * Random context must have been initialized beforehand.
 */
void ncc_rand_str_ctx(uint8_t *out, fr_fast_rand_t *rand_ctx, size_t len, char *randstr, ssize_t randstr_len)
{
	uint8_t *p = out, *end = p + len;
	unsigned int word, mod;
	uint8_t byte;

	if (randstr_len < 0) randstr_len = strlen(randstr);

	if (randstr_len == 0) { /* Ensure we don't crash. */
		out[0] = '\0';
		return;
	}

	while (p < end) {
		if ((mod = ((p - out) & (sizeof(word) - 1))) == 0) word = fr_fast_rand(rand_ctx);
		byte = ((uint8_t *)&word)[mod];
		*p++ = (randstr[byte % randstr_len]);
	}

	out[len] = '\0';
}


/**
 * Parse a list of endpoint addresses.
 * Create and populate a list of endpoints with the results.
 */
int ncc_endpoint_list_parse(TALLOC_CTX *ctx, ncc_dlist_t **ep_dlist_p, char const *in,
                            ncc_endpoint_t *default_ep)
{
	if (!ep_dlist_p || !in) return -1;

	if (!*ep_dlist_p) {
		MEM(*ep_dlist_p = talloc_zero(ctx, ncc_dlist_t));
		NCC_DLIST_INIT(*ep_dlist_p, ncc_endpoint_t);
	}

	char *in_dup = talloc_strdup(ctx, in); /* Working copy (strsep alters the string it's dealing with). */
	char *str = in_dup;

	char *p = strsep(&str, ",");
	while (p) {
		/* First trim string of eventual spaces. */
		ncc_str_trim(p, p, strlen(p));

		/* Add this to our list of endpoints. */
		size_t size_pre = NCC_DLIST_SIZE(*ep_dlist_p);
		ncc_endpoint_t *ep = ncc_endpoint_list_add(ctx, *ep_dlist_p, p, default_ep);
		if (!ep) {
			fr_strerror_printf_push("Failed to create endpoint \"%s\"", p);
			return -1;
		}

		if (size_pre < NCC_DLIST_SIZE(*ep_dlist_p)) {
			char ep_buf[NCC_ENDPOINT_STRLEN] = "";
			DEBUG3("Added endpoint list item #%u: [%s]", size_pre, ncc_endpoint_sprint(ep_buf, ep));
		}

		p = strsep(&str, ",");
	}
	talloc_free(in_dup);

	return 0;
}

/**
 * Add a new endpoint to a list.
 */
ncc_endpoint_t *ncc_endpoint_list_add(TALLOC_CTX *ctx, ncc_dlist_t *list,
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

	/* Add new endpoint if it is not in list already. */
	ep_new = ncc_endpoint_find(list, &this);
	if (!ep_new) {
		MEM(ep_new = talloc_zero(ctx, ncc_endpoint_t));
		NCC_DLIST_ENQUEUE(list, ep_new);
		memcpy(ep_new, &this, sizeof(this));
	}

	return ep_new;
}

/**
 * Look for endpoint in list.
 */
ncc_endpoint_t *ncc_endpoint_find(ncc_dlist_t *list, ncc_endpoint_t *ep_find)
{
	ncc_endpoint_t *ep = NCC_DLIST_HEAD(list);
	while (ep) {
		if (ep->port == ep_find->port && fr_ipaddr_cmp(&ep->ipaddr, &ep_find->ipaddr) == 0) return ep;

		ep = NCC_DLIST_NEXT(list, ep);
	}

	/* Endpoint not found in list. */
	return NULL;
}

/**
 * Print the endpoints in list.
 */
char *ncc_endpoint_list_snprint(char *out, size_t outlen, ncc_dlist_t *ep_dlist)
{
	char ipaddr_buf[FR_IPADDR_STRLEN] = "";
	int i;
	size_t len;
	char *p = out;

	if (!ep_dlist) {
		fr_strerror_printf("Invalid argument");
		return NULL;
	}

	i = 0;
	ncc_endpoint_t *ep = NCC_DLIST_HEAD(ep_dlist);
	while (ep) {
		len = snprintf(p, outlen, "%s%s:%u", (i > 0 ? ", " : ""),
		               fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf),
		               &ep->ipaddr), ep->port);

		ERR_IF_TRUNCATED_LEN(p, outlen, len);

		ep = NCC_DLIST_NEXT(ep_dlist, ep);
		i++;
	}

	return out;
}

/**
 * Peek at stdin (fd 0) to see if it has input.
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

/**
 * Search for a value in an array of string, add it if not found. Return its index.
 * Note: this is unefficient, but it's meant for only a handful of elements so it doesn't matter.
 */
uint32_t ncc_str_array_index(TALLOC_CTX *ctx, char ***pt_array, char const *value)
{
	size_t size_pre = talloc_array_length(*pt_array); /* Previous size (also index of the new element if added). */
	int i;

	for (i = 0; i < size_pre; i++) {
		if (strcmp(value, (*pt_array)[i]) == 0) return i;
	}

	/* Value not found, add it. */
	TALLOC_REALLOC_ZERO(ctx, *pt_array, char *, size_pre, size_pre + 1);
	(*pt_array)[size_pre] = talloc_strdup(ctx, value);
	return size_pre;
}

/**
 * Search for an IP address in an array. If found return its index.
 *
 * @param[in] ipaddr_array  talloc array of IP addresses
 * @param[in] ipaddr        address to look for.
 *
 * @return -1 if not found, index in array if found.
 */
int ncc_ipaddr_array_find(fr_ipaddr_t *ipaddr_array, fr_ipaddr_t *ipaddr)
{
	size_t len = talloc_array_length(ipaddr_array);
	int i;

	for (i = 0; i < len; i++) {
		if (fr_ipaddr_cmp(ipaddr, &ipaddr_array[i]) == 0) return i;
	}

	return -1;
}
