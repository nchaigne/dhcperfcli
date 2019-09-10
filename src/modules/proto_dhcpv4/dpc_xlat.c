/**
 * @file dpc_xlat.c
 * @brief Xlat wrapper functions.
 */

#include "dhcperfcli.h"
#include "ncc_xlat.h"


/*
 *	Wrapper to FreeRADIUS xlat_eval with a fake REQUEST provided.
 */
ssize_t dpc_xlat_eval(char *out, size_t outlen, char const *fmt, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;

	return ncc_xlat_eval(out, outlen, fmt, vps);
}

ssize_t dpc_xlat_eval_compiled(char *out, size_t outlen, xlat_exp_t const *xlat, DHCP_PACKET *packet)
{
	VALUE_PAIR *vps = NULL;
	if (packet) vps = packet->vps;

	return ncc_xlat_eval_compiled(out, outlen, xlat, vps);
}
