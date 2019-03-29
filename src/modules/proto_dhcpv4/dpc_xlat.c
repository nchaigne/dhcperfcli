/**
 * @file dpc_xlat.c
 * @brief Xlat wrapper functions.
 */

#include "dhcperfcli.h"

#include <freeradius-devel/server/xlat_priv.h>

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
static void dpc_xlat_init_request(VALUE_PAIR *vps)
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
void dpc_xlat_set_num(uint64_t num)
{
	dpc_xlat_init_request(NULL);
	FX_request->number = num; /* Our input id. */
	FX_request->child_number = 0; /* The index of the xlat context for this input. */
}

/*
 *	Wrapper to FreeRADIUS xlat_eval with a fake REQUEST provided.
 */
ssize_t dpc_xlat_eval(char *out, size_t outlen, char const *fmt, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;
	dpc_xlat_init_request(vps);

	size_t len = xlat_eval(out, outlen, FX_request, fmt, NULL, NULL);
	CHECK_BUFFER_SIZE(-1, len + 1, outlen, "xlat"); /* push error and return -1. */
	return len;
}

ssize_t dpc_xlat_eval_compiled(char *out, size_t outlen, xlat_exp_t const *xlat, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;
	dpc_xlat_init_request(vps);

	size_t len = xlat_eval_compiled(out, outlen, FX_request, xlat, NULL, NULL);
	CHECK_BUFFER_SIZE(-1, len + 1, outlen, "xlat"); /* push error and return -1. */
	return len;
}
