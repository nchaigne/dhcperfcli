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
 *	Trace / logging.
 */
FILE *ncc_log_fp = NULL;
struct timeval tve_ncc_start; /* Program execution start timestamp. */
int ncc_debug_lvl = 0;
int ncc_debug_dev = 0; /* 0 = basic debug, 1 = developper. */
int ncc_debug_basename = 1;
int ncc_debug_datetime = 1; /* Absolute date/time. */
// TODO: make this configurable.

/*
 *	Initialize debug logging.
 */
void ncc_log_init(FILE *log_fp, int debug_lvl, int debug_dev)
{
	gettimeofday(&tve_ncc_start, NULL);
	ncc_log_fp = log_fp;
	ncc_debug_lvl = debug_lvl;
	ncc_debug_dev = debug_dev;
}

/*
 *	Print a log message.
 */
void ncc_printf_log(char const *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (!ncc_log_fp) {
		va_end(ap);
		return;
	}

	/* Print absolute date/time. */
	if (ncc_debug_datetime) {
		char datetime_buf[NCC_DATETIME_STRLEN];
		fprintf(ncc_log_fp, "%s ", ncc_absolute_time_sprint(datetime_buf, true));
	}

	vfprintf(ncc_log_fp, fmt, ap);
	va_end(ap);

	return;
}

/*
 *	Print a debug log message.
 *	Add extra information (file, line) if developper print is enabled.
 *
 *	(ref: function fr_proto_print from lib/util/proto.c)
 */
static unsigned int dev_log_indent = 30;
static char spaces[] = "                                                 ";
void ncc_log_dev_printf(char const *file, int line, char const *fmt, ...)
{
	va_list ap;
	size_t len;
	char prefix[256];
	char const *filename = file;

	va_start(ap, fmt);
	if (!ncc_log_fp) {
		va_end(ap);
		return;
	}

	if (ncc_debug_dev) {
		if (ncc_debug_basename) {
			/* file is __FILE__ which is set at build time by gcc.
			 * e.g. src/modules/proto_dhcpv4/dhcperfcli.c
			 * Extract the file base name to have leaner traces.
			 */
			char *p = strrchr(file, FR_DIR_SEP);
			if (p) filename = p + 1;
		}

		len = snprintf(prefix, sizeof(prefix), " )%s:%i", filename, line);
		if (len > dev_log_indent) dev_log_indent = len;

		fprintf(ncc_log_fp, "%s%.*s: ", prefix, (int)(dev_log_indent - len), spaces);

		/* Print elapsed time. */
		char time_buf[NCC_TIME_STRLEN];
		fprintf(ncc_log_fp, "t(%s) ",
		        ncc_delta_time_sprint(time_buf, &tve_ncc_start, NULL, (ncc_debug_lvl >= 4) ? 6 : 3));

	} else {
		/* Print absolute date/time. */
		if (ncc_debug_datetime) {
			char datetime_buf[NCC_DATETIME_STRLEN];
			fprintf(ncc_log_fp, "%s ", ncc_absolute_time_sprint(datetime_buf, true));
		}
	}

	/* And then the actual log message. */
	vfprintf(ncc_log_fp, fmt, ap);
	va_end(ap);

	fprintf(ncc_log_fp, "\n");
	fflush(ncc_log_fp);
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
	sprintf(out, "%s:%u",
	        fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf), &ep->ipaddr) ? ipaddr_buf : "(undef)", ep->port);
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
 *	Print a time difference, in format: [[<HH>:]<MI>:]<SS>[.<d{1,6}>]
 *	Hour and minute printed only if relevant, decimals optional.
 *	If when is NULL, now is used instead.
 */
char *ncc_delta_time_sprint(char *out, struct timeval *from, struct timeval *when, uint8_t decimals)
{
	struct timeval delta, to;
	uint32_t sec, min, hour;

	if (!when) {
		gettimeofday(&to, NULL);
		when = &to;
	}

	timersub(when, from, &delta); /* delta = when - from */

	hour = (uint32_t)(delta.tv_sec / 3600);
	min = (uint32_t)(delta.tv_sec % 3600) / 60;
	sec = (uint32_t)(delta.tv_sec % 3600) % 60;

	if (hour > 0) {
		sprintf(out, "%d:%.02d:%.02d", hour, min, sec);
	} else if (min > 0) {
		sprintf(out, "%d:%.02d", min, sec);
	} else {
		sprintf(out, "%d", sec);
	}

	if (decimals) {
		char buffer[32] = "";
		sprintf(buffer, ".%06ld", delta.tv_usec);
		strncat(out, buffer, decimals + 1); /* (always terminated with '\0'). */
	}

	return out;
}

/*
 *	Print absolute date/time, in format: [YYYY-MM-DD ]HH:MI:SS
 */
char *ncc_absolute_time_sprint(char *out, bool with_date)
{
	time_t t;
	struct tm s_tm;

	time(&t);
	strftime(out, NCC_DATETIME_STRLEN, (with_date ? NCC_DATETIME_FMT : NCC_TIME_FMT),
	         localtime_r(&t, &s_tm));

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

	/* Allows integer or hex string. */
	if (fr_strtoull(&uinteger, &p, in) < 0) return false;
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


/*
 *	Add a new endpoint to a list.
 */
ncc_endpoint_t *ncc_ep_list_add(TALLOC_CTX *ctx, ncc_endpoint_list_t *ep_list,
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

	ep_list->num ++;
	ep_list->eps = talloc_realloc(ctx, ep_list->eps, ncc_endpoint_t, ep_list->num);
	/* Note: ctx is used only on first allocation. */

	ep_new = &ep_list->eps[ep_list->num - 1];
	memcpy(ep_new, &this, sizeof(this));

	return ep_new; /* Valid only until list is expanded. */
}

/*
 *	Get next endpoint from the list (use in round robin fashion).
 */
ncc_endpoint_t *ncc_ep_list_get_next(ncc_endpoint_list_t *ep_list)
{
	if (!ep_list || !ep_list->eps) return NULL;

	ncc_endpoint_t *ep = &ep_list->eps[ep_list->next];
	ep_list->next = (ep_list->next + 1) % ep_list->num;
	return ep;
}

/*
 *	Print the endpoints in list.
 */
char *ncc_ep_list_snprint(char *out, size_t outlen, ncc_endpoint_list_t *ep_list)
{
	char ipaddr_buf[FR_IPADDR_STRLEN] = "";
	int i;
	size_t len;
	char *p = out;
	char *end = out + outlen - 1;

	if (!ep_list) {
		fr_strerror_printf("Invalid argument");
		return NULL;
	}

	for (i = 0; i < ep_list->num; i++) {
		len = snprintf(p, end - p, "%s%s:%u", (i > 0 ? ", " : ""),
		               fr_inet_ntop(ipaddr_buf, sizeof(ipaddr_buf),
		               &ep_list->eps[ep_list->next].ipaddr), ep_list->eps[ep_list->next].port);

		ERR_IF_TRUNCATED(p, len, end - p);
	}

	return out;
}

/*
 *	Peek at stdin (fd 0) to see if it has input.
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
