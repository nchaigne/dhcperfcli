/**
 * @file dpc_xlat.c
 * @brief Xlat wrapper functions.
 */

#include "dhcperfcli.h"
#include "ncc_xlat.h"

#include <freeradius-devel/server/xlat_priv.h>


/*
 *	Wrapper to FreeRADIUS xlat_eval with a fake REQUEST provided.
 */
ssize_t dpc_xlat_eval(char *out, size_t outlen, char const *fmt, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;
	ncc_xlat_init_request(vps);

	size_t len = xlat_eval(out, outlen, FX_request, fmt, NULL, NULL);
	CHECK_BUFFER_SIZE(-1, len + 1, outlen, "xlat"); /* push error and return -1. */

	/* Check if our xlat functions returned an error. */
	if (ncc_xlat_get_rcode() != 0) return -1;

	return len;
}

ssize_t dpc_xlat_eval_compiled(char *out, size_t outlen, xlat_exp_t const *xlat, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;
	ncc_xlat_init_request(vps);

	size_t len = xlat_eval_compiled(out, outlen, FX_request, xlat, NULL, NULL);
	CHECK_BUFFER_SIZE(-1, len + 1, outlen, "xlat"); /* push error and return -1. */

	/* Check if our xlat functions returned an error. */
	if (ncc_xlat_get_rcode() != 0) return -1;

	return len;
}
