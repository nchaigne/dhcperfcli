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


/*
 *	Functions in ncc_xlat_func.c
 */
void ncc_xlat_init_request(VALUE_PAIR *vps);
void ncc_xlat_set_num(uint64_t num);
void ncc_xlat_register(void);
