/**
 * @file ncc_xlat_core.c
 * @brief Xlat core functions
 */

/*
 *	Reuse from FreeRADIUS, see:
 *	src/lib/server/xlat_func.c
 *
 *	We need that to do our own xlat'ing without pulling the whole server in.
 *	And also, to avoid having unchecked xlat functions which can crash our process. :'(
 *
 *	Note: we need to link with libfreeradius-server (and libfreeradius-unlang) for xlat_tokenize, xlat_eval, etc.
 */

#include <freeradius-devel/server/base.h>
#include <freeradius-devel/server/xlat_priv.h>

#include "ncc_util.h"
#include "ncc_xlat.h"


/*
 *	The following is copied verbatim from src/lib/server/xlat_func.c
 *
 *	xlat_cmp
 *	xlat_func_find
 *	_xlat_func_talloc_free
 *	_xlat_func_tree_free
 *
 *	In addition, the following functions are copied, but altered:
 *
 *	xlat_init (ncc_xlat_core_init) - it does not register any of FreeRADIUS unlang / server xlat functions.
 *	xlat_free (ncc_xlat_core_free).
 *	xlat_register (ncc_xlat_core_register) - calls ncc_xlat_core_init.
 */

static rbtree_t *xlat_root = NULL;

/*
 *	Compare two xlat_t structs, based ONLY on the module name.
 */
static int xlat_cmp(void const *one, void const *two)
{
	xlat_t const *a = one, *b = two;
	size_t a_len, b_len;
	int ret;

	a_len = strlen(a->name);
	b_len = strlen(b->name);

	ret = (a_len > b_len) - (a_len < b_len);
	if (ret != 0) return ret;

	return memcmp(a->name, b->name, a_len);
}

/*
 *	find the appropriate registered xlat function.
 */
xlat_t *xlat_func_find(char const *name)
{
	xlat_t *found;

	if (!xlat_root) return NULL;

	found = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });

	return found;
}

/** Remove an xlat function from the function tree
 *
 * @param[in] xlat	to free.
 * @return 0
 */
static int _xlat_func_talloc_free(xlat_t *xlat)
{
	if (!xlat_root) return 0;

	rbtree_deletebydata(xlat_root, xlat);
	if (rbtree_num_elements(xlat_root) == 0) TALLOC_FREE(xlat_root);

	return 0;
}

/** Callback for the rbtree to clear out any xlats still registered
 *
 */
static void _xlat_func_tree_free(void *xlat)
{
	talloc_free(xlat);
}

/** Register an xlat function.
 *
 * @param[in] mod_inst		Instance of module that's registering the xlat function.
 * @param[in] name		xlat name.
 * @param[in] func 		xlat function to be called.
 * @param[in] escape		function to sanitize any sub expansions passed to the xlat function.
 * @param[in] instantiate	function to pre-parse any xlat specific data.
 * @param[in] inst_size		sizeof() this xlat's instance data.
 * @param[in] buf_len		Size of the output buffer to allocate when calling the function.
 *				May be 0 if the function allocates its own buffer.
 * @param[in] async_safe	whether or not the function is async-safe.
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int ncc_xlat_core_register(void *mod_inst, char const *name,
		  xlat_func_sync_t func, xlat_escape_t escape,
		  xlat_instantiate_t instantiate, size_t inst_size,
		  size_t buf_len, bool async_safe)
{
	xlat_t	*c;
	bool	new = false;

	if (!xlat_root && (ncc_xlat_core_init() < 0)) return -1;;

	if (!name || !*name) {
		ERROR("%s: Invalid xlat name", __FUNCTION__);
		return -1;
	}

	/*
	 *	If it already exists, replace the instance.
	 */
	c = rbtree_finddata(xlat_root, &(xlat_t){ .name = name });
	if (c) {
		if (c->internal) {
			ERROR("%s: Cannot re-define internal expansion %s", __FUNCTION__, name);
			return -1;
		}

		if (c->async_safe != async_safe) {
			ERROR("%s: Cannot change async capability of %s", __FUNCTION__, name);
			return -1;
		}

	/*
	 *	Doesn't exist.  Create it.
	 */
	} else {
		c = talloc_zero(xlat_root, xlat_t);
		c->name = talloc_typed_strdup(c, name);
		talloc_set_destructor(c, _xlat_func_talloc_free);
		new = true;
	}

	c->func.sync = func;
	c->type = XLAT_FUNC_SYNC;
	c->buf_len = buf_len;
	c->escape = escape;
	c->mod_inst = mod_inst;
	c->instantiate = instantiate;
	c->inst_size = inst_size;
	c->async_safe = async_safe;

	DEBUG3("%s: %s", __FUNCTION__, c->name);

	if (new && !rbtree_insert(xlat_root, c)) {
		ERROR("Failed inserting xlat registration for %s",
		      c->name);
		talloc_free(c);
		return -1;
	}

	return 0;
}

/** Global initialisation for xlat
 *
 * @note Free memory with #xlat_free
 *
 * @return
 *	- 0 on success.
 *	- -1 on failure.
 */
int ncc_xlat_core_init(void)
{
	if (xlat_root) return 0;

	UNUSED xlat_t *c;

	/*
	 *	Create the function tree
	 */
	xlat_root = rbtree_talloc_create(NULL, xlat_cmp, xlat_t, _xlat_func_tree_free, RBTREE_FLAG_REPLACE);
	if (!xlat_root) {
		ERROR("%s: Failed to create tree", __FUNCTION__);
		return -1;
	}

	return 0;
}

/** De-register all xlat functions we created
 *
 */
void ncc_xlat_core_free(void)
{
	rbtree_t *xr = xlat_root;		/* Make sure the tree can't be freed multiple times */

	if (!xr) return;

	xlat_root = NULL;
	talloc_free(xr);

	xlat_eval_free();
}


/*
 *	Wrapper to FreeRADIUS xlat_eval with a fake REQUEST provided,
 *	which allows access to "control" and "packet" lists of value pairs
 */
ssize_t ncc_xlat_eval(char *out, size_t outlen, char const *fmt, VALUE_PAIR *vps)
{
	ncc_xlat_init_request(vps);

	size_t len = xlat_eval(out, outlen, FX_request, fmt, NULL, NULL);
	CHECK_BUFFER_SIZE(-1, len + 1, outlen, "xlat"); /* push error and return -1. */

	/* Check if our xlat functions returned an error. */
	if (ncc_xlat_get_rcode() != 0) return -1;

	return len;
}

/*
 *	Wrapper to FreeRADIUS xlat_eval_compiled with a fake REQUEST provided,
 *	which allows access to "control" and "packet" lists of value pairs
 */
ssize_t ncc_xlat_eval_compiled(char *out, size_t outlen, xlat_exp_t const *xlat, VALUE_PAIR *vps)
{
	ncc_xlat_init_request(vps);

	size_t len = xlat_eval_compiled(out, outlen, FX_request, xlat, NULL, NULL);
	CHECK_BUFFER_SIZE(-1, len + 1, outlen, "xlat"); /* push error and return -1. */

	/* Check if our xlat functions returned an error. */
	if (ncc_xlat_get_rcode() != 0) return -1;

	return len;
}
