/*
 * ncc_util.c
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
 *	Resolve host address and port.
 */
int ncc_host_addr_resolve(char *host_arg, ncc_endpoint_t *host_ep)
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
