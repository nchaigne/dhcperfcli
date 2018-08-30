#pragma once
/*
 *	ncc_util.h
 */

#include <freeradius-devel/server/base.h>


#define NCC_ENDPOINT_STRLEN       (FR_IPADDR_STRLEN + 5)
#define NCC_ETHADDR_STRLEN        (17 + 1)
#define NCC_UINT32_STRLEN         (10 + 1)
#define NCC_UINT64_STRLEN         (20 + 1)


/*
 *	Using rad_assert defined in include/rad_assert.h
 */
#define ncc_assert rad_assert


typedef struct ncc_list_item ncc_list_item_t;

/*
 *	Chained list of data elements.
 */
typedef struct ncc_list {
	ncc_list_item_t *head;
	ncc_list_item_t *tail;
	uint32_t size;
} ncc_list_t;

/*
 *	Chained list item.
 */
struct ncc_list_item {
	ncc_list_t *list;       //!< The list to which this entry belongs (NULL for an unchained entry).
	ncc_list_item_t *prev;
	ncc_list_item_t *next;

	void *data;             //!< User-specific item data.
};

/*
 *	Transport endpoint (IP address, port).
 */
typedef struct ncc_endpoint {
	fr_ipaddr_t ipaddr;
	uint16_t port;
} ncc_endpoint_t;


/* Get visibility on fr_event_timer_t opaque struct (fr_event_timer is defined in lib/util/event.c) */
typedef struct ncc_fr_event_timer {
	fr_event_list_t		*el;			//!< because talloc_parent() is O(N) in number of objects
	struct timeval		when;			//!< When this timer should fire.
	/* We don't need anything beyond that. */
} ncc_fr_event_timer_t;

/* Get visibility on fr_event_list_t opaque struct (fr_event_list is defined in lib/util/event.c) */
typedef struct ncc_fr_event_list {
	fr_heap_t		*times;			//!< of timer events to be executed.
	/* We don't need anything beyond that. */
} ncc_fr_event_list_t;


int ncc_fr_event_timer_peek(fr_event_list_t *fr_el, struct timeval *when);

VALUE_PAIR *ncc_pair_find_by_da(VALUE_PAIR *head, fr_dict_attr_t const *da);
VALUE_PAIR *ncc_pair_create(TALLOC_CTX *ctx, VALUE_PAIR **vps,
			                unsigned int attribute, unsigned int vendor);
VALUE_PAIR *ncc_pair_create_by_da(TALLOC_CTX *ctx, VALUE_PAIR **vps, fr_dict_attr_t const *da);
int ncc_pair_copy_value(VALUE_PAIR *to, VALUE_PAIR *from);
int ncc_pair_value_from_str(VALUE_PAIR *vp, char const *value);
VALUE_PAIR *ncc_pair_list_append(TALLOC_CTX *ctx, VALUE_PAIR **to, VALUE_PAIR *from);

char *ncc_endpoint_sprint(char *out, ncc_endpoint_t *ep);
char *ncc_ether_addr_sprint(char *out, const uint8_t *addr);

int ncc_host_addr_resolve(ncc_endpoint_t *host_ep, char const *host_arg);

float ncc_timeval_to_float(struct timeval *in);
int ncc_float_to_timeval(struct timeval *out, float in);
bool ncc_str_to_float(float *out, char const *in, bool allow_negative);
bool ncc_str_to_uint32(uint32_t *out, char const *in);
size_t ncc_str_trim(char *out, char const *in, size_t inlen);

void ncc_list_add(ncc_list_t *list, ncc_list_item_t *entry);
ncc_list_item_t *ncc_list_item_draw(ncc_list_item_t *entry);
ncc_list_item_t *ncc_list_get_head(ncc_list_t *list);
ncc_list_item_t *ncc_list_index(ncc_list_t *list, uint32_t index);

#define NCC_LIST_ENQUEUE(_l, _e) ncc_list_add(_l, (ncc_list_item_t *)_e);
#define NCC_LIST_DEQUEUE(_l) (void *)ncc_list_get_head(_l);
#define NCC_LIST_INDEX(_l, _i) (void *)ncc_list_index(_l, _i);

/* This is now in protocol/radius/list.h - which we might not want to depend on, so... */
# define fr_packet2myptr(TYPE, MEMBER, PTR) (TYPE *) (((char *)PTR) - offsetof(TYPE, MEMBER))
