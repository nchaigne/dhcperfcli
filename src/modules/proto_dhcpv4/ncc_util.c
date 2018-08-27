/*
 *	ncc_util.c
 */

#include "ncc_util.h"


/*
 *	Peek into an event list to retrieve the timestamp of next event.
 *
 *	Note: structures fr_event_list_t and fr_event_timer_t are opaque, so we have to partially redefine them
 *	so we can access what we need.
 *	(I know, this is dangerous. We'll be fine as long as they do not change.)
 *	Ideally, this should be provided by FreeRADIUS lib. TODO: ask them ?
 */
int ncc_fr_event_timer_peek(fr_event_list_t *fr_el, struct timeval *when)
{
	ncc_fr_event_list_t *el = (ncc_fr_event_list_t *)fr_el;
	ncc_fr_event_timer_t *ev;

	if (unlikely(!el)) return 0;

	if (fr_heap_num_elements(el->times) == 0) {
		when->tv_sec = 0;
		when->tv_usec = 0;
		return 0;
	}

	ev = fr_heap_peek(el->times);
	if (!ev) {
		when->tv_sec = 0;
		when->tv_usec = 0;
		return 0;
	}

	*when = ev->when;
	return 1;
}


/*
 *	Wrapper to fr_pair_find_by_da, which just returns NULL if we don't have the dictionary attr.
 */
VALUE_PAIR *ncc_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da)
{
	if (!da) return NULL;
	return fr_pair_find_by_da(head, da, TAG_ANY);
}

/*
 *	Create a value pair and add it to a list of value pairs.
 *	This is a copy of (now defunct) FreeRADIUS function radius_pair_create (from src/main/pair.c)
 */
VALUE_PAIR *ncc_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			                unsigned int attribute, unsigned int vendor)
{
	VALUE_PAIR *vp;

	MEM(vp = fr_pair_afrom_num(ctx, vendor, attribute));
	if (vps) fr_pair_add(vps, vp);

	return vp;
}

/*
 *	Create a value pair from a dictionary attribute, and add it to a list of value pairs.
 */
VALUE_PAIR *ncc_pair_create_by_da(TALLOC_CTX *ctx, VALUE_PAIR **vps, fr_dict_attr_t const *da)
{
	VALUE_PAIR *vp;

	MEM(vp = fr_pair_afrom_da(ctx, da));
	if (vps) fr_pair_add(vps, vp);

	return vp;
}

/*
 *	Copy the value from a pair to another, and the type also (e.g. VT_DATA).
 */
int ncc_pair_copy_value(VALUE_PAIR *to, VALUE_PAIR *from)
{
	to->type = from->type;
	return fr_value_box_copy(to, &to->data, &from->data);
}

/*
 *	Set value of a pair (of any data type) from a string.
 *	If the conversion is not possible, an error will be returned.
 */
int ncc_pair_value_from_str(VALUE_PAIR *vp, char const *value)
{
	fr_type_t type = vp->da->type;

	vp->type = VT_DATA;
	return fr_value_box_from_str(vp, &vp->data, &type, NULL, value, strlen(value), '\0', false);
}

/*
 *	Append a list of VP. (inspired from FreeRADIUS's fr_pair_list_copy.)
 */
VALUE_PAIR *ncc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from)
{
	vp_cursor_t src, dst;

	if (*to == NULL) { /* fall back to fr_pair_list_copy for a new list. */
		MEM(fr_pair_list_copy(ctx, to, from) >= 0);
		return (*to);
	}

	VALUE_PAIR *out = *to, *vp;

	fr_pair_cursor_init(&dst, &out);
	for (vp = fr_pair_cursor_init(&src, &from);
	     vp;
	     vp = fr_pair_cursor_next(&src)) {
		VP_VERIFY(vp);
		vp = fr_pair_copy(ctx, vp);
		if (!vp) {
			fr_pair_list_free(&out);
			return NULL;
		}
		fr_pair_cursor_append(&dst, vp); /* fr_pair_list_copy sets next pointer to NULL */
	}

	return *to;
}


/*
 *	Print endpoint: <IP>:<port>.
 */
char *ncc_endpoint_sprint(char *out, ncc_endpoint_t *ep)
{
	char ipaddr_buf[FR_IPADDR_STRLEN] = "";
	sprintf(out, "%s:%u", fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf), &ep->ipaddr), ep->port);
	return out;
}

/*
 *	Print an ethernet address in a buffer.
 */
char *ncc_ether_addr_sprint(char *out, const uint8_t *addr)
{
	sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x",
	        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	return out;
}


/*
 *	Resolve host address and port.
 */
int ncc_host_addr_resolve(ncc_endpoint_t *host_ep, char const *host_arg)
{
	if (!host_arg || !host_ep) return -1;

	unsigned long port;
	uint16_t port_fr;
	char const *p = host_arg, *q;

	/*
	 *	Allow to just have [:]<port> (i.e. no IP address specified).
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
		host_ep->port = port;
		return 0;
	}

	/*
	 *	Otherwise delegate parsing to fr_inet_pton_port.
	 */
	if (fr_inet_pton_port(&host_ep->ipaddr, &port_fr, host_arg, -1, AF_INET, true, true) < 0) {
		return -1;
	}

	if (port_fr != 0) { /* If a port is specified, use it. Otherwise, keep default. */
		host_ep->port = port_fr;
	}

	return 0;
}


/*
 *	Convert a struct timeval to float.
 */
float ncc_timeval_to_float(struct timeval *in)
{
	float value = (in->tv_sec + (float)in->tv_usec / USEC);
	return value;
}

/*
 *	Convert a float to struct timeval.
 */
int ncc_float_to_timeval(struct timeval *tv, float in)
{
	/* Boundary check. */
	if (in >= (float)LONG_MAX) {
		ERROR("Cannot convert to timeval: float value %.0f exceeds LONG_MAX (%ld)", in, LONG_MAX);
		return -1;
	}

	tv->tv_sec = (time_t)in;
	tv->tv_usec = (uint64_t)(in * USEC) - (tv->tv_sec * USEC);
	return 0;
}

/*
 *	Check that a string represents a valid floating point number (e.g. 3, 2.5, .542).
 *	If so convert it to float.
 *	Note: not using strtof because we want to be more restrictive.
 */
bool ncc_str_to_float(float *out, char const *in, bool allow_negative)
{
	if (!in || in[0] == '\0') return false;

	char const *p = in;

	if (*p == '-') {
		if (!allow_negative) return false; /* Negative numbers not allowed. */
		p++;
	}

	while (*p != '\0') {
		if (isdigit(*p)) {
			p++;
			continue;
		}
		if (*p == '.') {
			p++;
			if (*p == '\0') return false; /* Do not allow a dot without any following digit. */
			break;
		}
		return false; /* Not a digit or dot. */
	}

	while (*p != '\0') { /* Everything after the dot must be a digit. */
		if (!isdigit(*p)) return false;
		p++;
	}

	/* Format is correct. */
	if (out) {
		*out = atof(in);
	}
	return true;
}

/*
 *	Check that a string represents either an integer or a valid hex string.
 *	If so convert it to uint32.
 */
bool ncc_str_to_uint32(uint32_t *out, char const *in)
{
	uint64_t uinteger = 0;
	char *p = NULL;

	if (!in || in[0] == '\0') return false;

	uinteger = fr_strtoull(in, &p); /* Allows integer or hex string. */
	if (*p != '\0' || uinteger > UINT32_MAX) return false;

	*out = (uint32_t) uinteger;
	return true;
}

/*
 *	Trim a string from spaces (left and right), while complying with an input length limit.
 *	Output buffer must be large enough to store the resulting string.
 *	Returns the number of characters printed, excluding the terminating '\0'.
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


/*
 *	Add an item entry to the tail of the list.
 */
void ncc_list_add(ncc_list_t *list, ncc_list_item_t *entry)
{
	if (!list || !entry) return;

	if (!list->head) {
		ncc_assert(list->tail == NULL);
		list->head = entry;
		entry->prev = NULL;
	} else {
		ncc_assert(list->tail != NULL);
		ncc_assert(list->tail->next == NULL);
		list->tail->next = entry;
		entry->prev = list->tail;
	}
	list->tail = entry;
	entry->next = NULL;
	entry->list = list;
	list->size ++;
}

/*
 *	Remove an input entry from its list.
 */
ncc_list_item_t *ncc_list_item_draw(ncc_list_item_t *entry)
{
	if (!entry) return NULL; // should not happen.
	if (!entry->list) return entry; // not in a list: just return the entry.

	ncc_list_item_t *prev, *next;

	prev = entry->prev;
	next = entry->next;

	ncc_list_t *list = entry->list;

	ncc_assert(list->head != NULL); // entry belongs to a list, so the list can't be empty.
	ncc_assert(list->tail != NULL); // same.

	if (prev) {
		ncc_assert(list->head != entry); // if entry has a prev, then entry can't be head.
		prev->next = next;
	}
	else {
		ncc_assert(list->head == entry); // if entry has no prev, then entry must be head.
		list->head = next;
	}

	if (next) {
		ncc_assert(list->tail != entry); // if entry has a next, then entry can't be tail.
		next->prev = prev;
	}
	else {
		ncc_assert(list->tail == entry); // if entry has no next, then entry must be tail.
		list->tail = prev;
	}

	entry->list = NULL;
	entry->prev = NULL;
	entry->next = NULL;
	list->size --;
	return entry;
}

/*
 *	Get the head input entry from a list.
 */
ncc_list_item_t *ncc_list_get_head(ncc_list_t *list)
{
	if (!list) return NULL;
	if (!list->head || list->size == 0) { // list is empty.
		return NULL;
	}
	// list is valid and has at least one element.
	return ncc_list_item_draw(list->head);
}

/*
 *	Get reference on a list item from its index (position in the list, starting at 0).
 *	Item is not removed from the list.
 */
ncc_list_item_t *ncc_list_index(ncc_list_t *list, uint32_t index)
{
	if (index >= list->size) return NULL; /* Item doesn't exist. */

	ncc_list_item_t *item = list->head;
	uint32_t i;
	for (i = 0; i < index; i++) {
		item = item->next;
	}
	return item;
}
