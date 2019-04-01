/**
 * @file ncc_xlat_func.c
 * @brief Xlat functions
 */

/*
 *	Reuse from FreeRADIUS, see:
 *	src/lib/server/xlat_func.c
 */

#include "ncc_util.h"
#include "ncc_xlat.h"

#include <freeradius-devel/server/xlat_priv.h>


/*
 *	Xlat names.
 */
#define NCC_XLAT_ETHADDR_RANGE "ethaddr.range"
#define NCC_XLAT_ETHADDR_RAND  "ethaddr.rand"


/*
 *	Different kinds of xlat contexts.
 */
typedef enum {
	NCC_CTX_TYPE_NUM_RANGE = 1,
	NCC_CTX_TYPE_IPADDR_RANGE,
	NCC_CTX_TYPE_ETHADDR_RANGE,
} ncc_xlat_ctx_type_t;

typedef struct sic_xlat_ctx {
	/* Generic chaining */
	ncc_list_t *list;       //!< The list to which this entry belongs (NULL for an unchained entry).
	ncc_list_item_t *prev;
	ncc_list_item_t *next;

	/* Specific item data */
	uint32_t num;
	ncc_xlat_ctx_type_t type;

	union {
		struct {
			uint64_t min;
			uint64_t max;
			uint64_t next;
		} num_range;
		struct {
			uint32_t min;
			uint32_t max;
			uint32_t next;
		} ipaddr_range;
		struct {
			uint8_t min[6];
			uint8_t max[6];
			uint8_t next[6];
		} ethaddr_range;
	};

} ncc_xlat_ctx_t;

static ncc_list_t *ncc_xlat_ctx_list = NULL; /* This is an array of lists. */
static uint32_t num_xlat_ctx_list = 0;


/*
 *	To use FreeRADIUS xlat engine, we need a REQUEST (which is a "typedef struct rad_request").
 *	This is defined in src/lib/server/base.h
 */
REQUEST *FX_request = NULL;

/* WARNING:
 * FreeRADIUS xlat functions can used this as Talloc context for allocating memory.
 * This happens when we have a simple attribute expansion, e.g. Attr1 = "%{Attr2}".
 * Cf. xlat_process function (src/lib/server/xlat_eval.c):
 * "Hack for speed. If it's one expansion, just allocate that and return, instead of allocating an intermediary array."
 *
 * So we must account for this so we don't have a huge memory leak.
 * Our fake request has to be freed, but we don't have to do this every time we do a xlat. Once in a while is good enough.
 */
static uint32_t request_num_use = 0;
static uint32_t request_max_use = 10000;

/*
 *	Build a unique fake request for xlat.
 */
void ncc_xlat_init_request(VALUE_PAIR *vps)
{
	if (FX_request && request_num_use >= request_max_use) {
		TALLOC_FREE(FX_request);
		request_num_use = 0;
	}
	request_num_use++;

	if (!FX_request) {
		FX_request = request_alloc(NULL);
		FX_request->packet = fr_radius_alloc(FX_request, false);
	}

	FX_request->control = vps; /* Allow to use %{control:Attr} */
	FX_request->packet->vps = vps; /* Allow to use %{packet:Attr} or directly %{Attr} */
}

/*
 *	Initialize xlat context in our fake request for processing a list of input vps.
 */
void ncc_xlat_set_num(uint64_t num)
{
	ncc_xlat_init_request(NULL);
	FX_request->number = num; /* Our input id. */
	FX_request->child_number = 0; /* The index of the xlat context for this input. */
}


/*
 *	Retrieve a specific xlat context, using information from our fake request.
 */
static ncc_xlat_ctx_t *ncc_xlat_get_ctx(TALLOC_CTX *ctx)
{
	ncc_xlat_ctx_t *xlat_ctx;

	uint32_t id_list = FX_request->number;
	uint32_t id_item = FX_request->child_number;

	/* Get the list for this input item. If it doesn't exist yet, allocate a new one. */
	ncc_list_t *list;
	if (id_list >= num_xlat_ctx_list) {
		uint32_t num_xlat_ctx_list_pre = num_xlat_ctx_list;
		num_xlat_ctx_list = id_list + 1;

		/* Allocate lists to all input items, even if they don't need xlat'ing. This is simpler. */
		ncc_xlat_ctx_list = talloc_realloc(ctx, ncc_xlat_ctx_list, ncc_list_t, num_xlat_ctx_list);

		/* talloc_realloc doesn't zero out the new elements. */
		memset(&ncc_xlat_ctx_list[num_xlat_ctx_list_pre], 0,
		       sizeof(ncc_list_t) * (num_xlat_ctx_list - num_xlat_ctx_list_pre));
	}
	list = &ncc_xlat_ctx_list[id_list];

	/* Now get the xlat context. If it doesn't exist yet, allocate a new one and add it to the list. */
	xlat_ctx = NCC_LIST_INDEX(list, id_item);
	if (!xlat_ctx) {
		/* We don't have a context element yet, need to add a new one. */
		MEM(xlat_ctx = talloc_zero(ctx, ncc_xlat_ctx_t));

		xlat_ctx->num = id_item;

		NCC_LIST_ENQUEUE(list, xlat_ctx);
	}

	FX_request->child_number ++; /* Prepare next xlat context. */

	return xlat_ctx;
}


/*
 *	Parse an Ethernet address range "<Ether1>-<Ether2>" and extract <Ether1> / <Ether2> as uint8_t[6].
 */
static int ncc_parse_ethaddr_range(uint8_t ethaddr1[6], uint8_t ethaddr2[6], char const *in)
{
	fr_type_t type = FR_TYPE_ETHERNET;
	fr_value_box_t vb = { 0 };

	char const *p = strchr(in, '-');
	if (!p) { /* Mandatory range delimiter. */
		fr_strerror_printf("No range delimiter, in: [%s]", in);
		return -1;
	}

	/* Convert the first Ethernet address. */
	if (fr_value_box_from_str(NULL, &vb, &type, NULL, in, (p - in), '\0', false) < 0) {
		fr_strerror_printf("Invalid first ethaddr, in: [%s]", in);
		return -1;
	}
	memcpy(ethaddr1, &vb.vb_ether, 6);

	/* Convert the second Ethernet address. */
	if (fr_value_box_from_str(NULL, &vb, &type, NULL, (p + 1), -1, '\0', false) < 0) {
		fr_strerror_printf("Invalid second ethaddr, in: [%s]", in);
		return -1;
	}
	memcpy(ethaddr2, &vb.vb_ether, 6);

	// TODO: check: ! e2 > e1

	return 0;
}

/** Generate increasing Ethernet addr values from a range.
 *
 *  %{ethaddr.range:01:02:03:04:05:06-01:02:03:04:05:ff} -> 01:02:03:04:05:06, 01:02:03:04:05:07, etc.
 */
static ssize_t _ncc_xlat_ethaddr_range(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	*out = NULL;

	/* Do *not* use the TALLOC context we get from FreeRADIUS. We don't want our contexts to be freed. */
	ncc_xlat_ctx_t *xlat_ctx = ncc_xlat_get_ctx(NULL);
	if (!xlat_ctx) return -1; /* Cannot happen. */

	if (!xlat_ctx->type) {
		/* Not yet parsed. */
		uint8_t ethaddr1[6], ethaddr2[6];
		if (ncc_parse_ethaddr_range(ethaddr1, ethaddr2, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat ethaddr range: %s", fr_strerror());
			return -1;
		}

		xlat_ctx->type = NCC_CTX_TYPE_ETHADDR_RANGE;
		memcpy(xlat_ctx->ethaddr_range.min, ethaddr1, 6);
		memcpy(xlat_ctx->ethaddr_range.max, ethaddr2, 6);
		memcpy(xlat_ctx->ethaddr_range.next, ethaddr1, 6);
	}

	char ethaddr_buf[NCC_ETHADDR_STRLEN] = "";
	ncc_ether_addr_sprint(ethaddr_buf, xlat_ctx->ethaddr_range.next);

	*out = talloc_typed_asprintf(ctx, "%s", ethaddr_buf);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	if (memcmp(xlat_ctx->ethaddr_range.next, xlat_ctx->ethaddr_range.max, 6) == 0) {
		memcpy(xlat_ctx->ethaddr_range.next, xlat_ctx->ethaddr_range.min, 6);
	} else {
		/* Store the 6 octets of Ethernet addr in a uint64_t to perform an integer increment.
		 */
		uint64_t ethaddr = 0;
		memcpy(&ethaddr, xlat_ctx->ethaddr_range.next, 6);

		ethaddr = (ntohll(ethaddr) >> 16) + 1;
		ethaddr = htonll(ethaddr << 16);
		memcpy(xlat_ctx->ethaddr_range.next, &ethaddr, 6);
	}

	return strlen(*out);
}

ssize_t ncc_xlat_ethaddr_range(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt)
{
	return _ncc_xlat_ethaddr_range(ctx, out, outlen, NULL, NULL, NULL, fmt);
}

/** Generate random Ethernet addr values from a range.
 *
 *  %{ethaddr.rand:01:02:03:04:05:06-01:02:03:04:05:ff} -> 01:02:03:04:05:32, ...
 *
 *  %{ethaddr.rand}
 */
static ssize_t _ncc_xlat_ethaddr_rand(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	uint64_t num1 = 0, num2 = 0, delta;
	uint64_t value;
	uint8_t ethaddr[6];

	*out = NULL;

	//TODO: parse once, save as context?

	if (fmt) {
		uint8_t ethaddr1[6], ethaddr2[6];
		if (ncc_parse_ethaddr_range(ethaddr1, ethaddr2, fmt) < 0) return -1;

		/* fr_value_box_from_str behaves strangely if we feed it partial ethaddr:
		"01" (or anything with only digits) => "00:00:00:00:00:00" but no complaining.
		"01:02", "0a" => these are ok.
		Probably a bug... TODO: check it.
		*/
		char buf_ethaddr[NCC_ETHADDR_STRLEN] = "";
		ncc_ether_addr_sprint(buf_ethaddr, ethaddr1);
		printf("parsed ethaddr1: %s\n", ncc_ether_addr_sprint(buf_ethaddr, ethaddr1));
		ncc_ether_addr_sprint(buf_ethaddr, ethaddr2);
		printf("parsed ethaddr2: %s\n", ncc_ether_addr_sprint(buf_ethaddr, ethaddr2));
		// temporary trace. TODO: remove this.

		memcpy(&num1, ethaddr1, 6);
		num1 = (ntohll(num1) >> 16);

		memcpy(&num2, ethaddr2, 6);
		num2 = (ntohll(num2) >> 16);

	} else {
		/* Get a random value from 00:00:00:00:00:01 to ff:ff:ff:ff:ff:ff:fe. (excluding zero and broadcast) */
		num1 = 1;
		num2 = 0xffffffffffff - 1;
	}

	double rnd = (double)fr_rand() / UINT32_MAX; /* Random value between 0..1 */

	delta = num2 - num1 + 1;
	value = (uint64_t)(rnd * delta) + num1;

	value = htonll(value << 16);
	memcpy(ethaddr, &value, 6);

	char ethaddr_buf[NCC_ETHADDR_STRLEN] = "";
	ncc_ether_addr_sprint(ethaddr_buf, ethaddr);

	*out = talloc_typed_asprintf(ctx, "%s", ethaddr_buf);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	return strlen(*out);
}

ssize_t ncc_xlat_ethaddr_rand(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt)
{
	return _ncc_xlat_ethaddr_rand(ctx, out, outlen, NULL, NULL, NULL, fmt);
}


/*
 *	Register our own xlat functions (and implicitly initialize the xlat framework).
 */
void ncc_xlat_register(void)
{
	ncc_xlat_core_register(NULL, NCC_XLAT_ETHADDR_RANGE, _ncc_xlat_ethaddr_range, NULL, NULL, 0, 0, true);
	ncc_xlat_core_register(NULL, NCC_XLAT_ETHADDR_RAND, _ncc_xlat_ethaddr_rand, NULL, NULL, 0, 0, true);
}
