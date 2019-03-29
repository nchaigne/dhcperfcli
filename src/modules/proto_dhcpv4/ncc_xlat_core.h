#pragma once
/*
 * ncc_xlat_core.h
 */

int ncc_xlat_core_register(void *mod_inst, char const *name,
		  xlat_func_sync_t func, xlat_escape_t escape,
		  xlat_instantiate_t instantiate, size_t inst_size,
		  size_t buf_len, bool async_safe);

int ncc_xlat_core_init(void);
