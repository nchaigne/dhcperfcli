#pragma once
/*
 * ncc_xlat.h
 */

extern REQUEST *FX_request;


/*
 *	Functions in ncc_xlat_core.c
 */
int ncc_xlat_core_register(void *mod_inst, char const *name,
		  xlat_func_sync_t func, xlat_escape_t escape,
		  xlat_instantiate_t instantiate, size_t inst_size,
		  size_t buf_len, bool async_safe);

int ncc_xlat_core_init(void);
void ncc_xlat_core_free(void);


/*
 *	Functions in ncc_xlat_func.c
 */
void ncc_xlat_init_request(VALUE_PAIR *vps);
void ncc_xlat_set_num(uint64_t num);
int ncc_xlat_get_rcode();

int ncc_parse_num_range(uint64_t *num1, uint64_t *num2, char const *in);
ssize_t ncc_xlat_num_range(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt);
ssize_t ncc_xlat_num_rand(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt);

int ncc_parse_ipaddr_range(fr_ipaddr_t *ipaddr1, fr_ipaddr_t *ipaddr2, char const *in);
ssize_t ncc_xlat_ipaddr_range(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt);
ssize_t ncc_xlat_ipaddr_rand(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt);

int ncc_parse_ethaddr_range(uint8_t ethaddr1[6], uint8_t ethaddr2[6], char const *in);
ssize_t ncc_xlat_ethaddr_range(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt);
ssize_t ncc_xlat_ethaddr_rand(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt);

void ncc_xlat_register(void);
