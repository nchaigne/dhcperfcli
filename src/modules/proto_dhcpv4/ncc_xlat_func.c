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
#define NCC_XLAT_ETHADDR_RAND  "ethaddr.rand"


/*
 *	Parse an Ethernet address range "<Ether1>-<Ether2>" and extract <Ether1> / <Ether2> as uint8_t[6].
 */
int ncc_parse_ethaddr_range(uint8_t ethaddr1[6], uint8_t ethaddr2[6], char const *in)
{
	fr_type_t type = FR_TYPE_ETHERNET;
	fr_value_box_t vb;

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
	ncc_xlat_core_register(NULL, NCC_XLAT_ETHADDR_RAND, _ncc_xlat_ethaddr_rand, NULL, NULL, 0, 0, true);
}
