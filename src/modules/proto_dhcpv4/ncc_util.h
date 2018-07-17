#pragma once
/*
 * ncc_util.h
 */

#include <freeradius-devel/server/base.h>

/* Transport endpoint (IP address, port). */
typedef struct ncc_endpoint {
	fr_ipaddr_t ipaddr;
	uint16_t port;
} ncc_endpoint_t;

VALUE_PAIR *ncc_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da);
VALUE_PAIR *ncc_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			                unsigned int attribute, unsigned int vendor);
VALUE_PAIR *ncc_pair_create_by_da(TALLOC_CTX *ctx, VALUE_PAIR **vps, fr_dict_attr_t const *da);

int ncc_host_addr_resolve(char *host_arg, ncc_endpoint_t *host_ep);
