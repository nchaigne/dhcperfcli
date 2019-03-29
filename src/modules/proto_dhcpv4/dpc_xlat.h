
#pragma once
/*
 * dpc_xlat.h
 */

#define DPC_XLAT_MAX_LEN 4096

ssize_t dpc_xlat_eval(char *out, size_t outlen, char const *fmt, DHCP_PACKET *packet);
ssize_t dpc_xlat_eval_compiled(char *out, size_t outlen, xlat_exp_t const *xlat, DHCP_PACKET *packet);
