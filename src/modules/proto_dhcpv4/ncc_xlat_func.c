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
#define NCC_XLAT_FILE_RAW      "file.raw"
#define NCC_XLAT_FILE_CSV      "file.csv"
#define NCC_XLAT_NUM_RANGE     "num.range"
#define NCC_XLAT_NUM_RAND      "num.rand"
#define NCC_XLAT_IPADDR_RANGE  "ipaddr.range"
#define NCC_XLAT_IPADDR_RAND   "ipaddr.rand"
#define NCC_XLAT_ETHADDR_RANGE "ethaddr.range"
#define NCC_XLAT_ETHADDR_RAND  "ethaddr.rand"
#define NCC_XLAT_RANDSTR       "randstr"


/*
 *	Different kinds of xlat contexts.
 */
typedef enum {
	NCC_CTX_TYPE_FILE = 1,
	NCC_CTX_TYPE_FILE_CSV,
	NCC_CTX_TYPE_NUM_RANGE,
	NCC_CTX_TYPE_NUM_RAND,
	NCC_CTX_TYPE_IPADDR_RANGE,
	NCC_CTX_TYPE_IPADDR_RAND,
	NCC_CTX_TYPE_ETHADDR_RANGE,
	NCC_CTX_TYPE_ETHADDR_RAND,
} ncc_xlat_frame_type_t;

typedef struct ncc_xlat_frame {
	/* Generic chaining */
	ncc_list_t *list;       //!< The list to which this entry belongs (NULL for an unchained entry).
	ncc_list_item_t *prev;
	ncc_list_item_t *next;

	/* Specific item data */
	uint32_t num;
	ncc_xlat_frame_type_t type;

	union {
		struct {
			uint32_t idx_file;
		} file;
		struct {
			uint32_t idx_file;
			uint32_t idx_value;
		} file_csv;
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

} ncc_xlat_frame_t;

typedef struct ncc_xlat_file {
	uint32_t idx_file; /* Index of this xlat file. */
	FILE *fp;
	uint32_t num_line; /* Last line read. */

	bool is_read; /* If current line has been read yet. */
	char *value; /* Store single value read from current line using xlat "file". */
	VALUE_PAIR *vps; /* Store list of values read from current line using xlat "file.csv". */
} ncc_xlat_file_t;

static bool done_init = false;

static TALLOC_CTX *xlat_ctx;

static ncc_list_t *ncc_xlat_frame_list; /* This is an array of lists. */
static uint32_t num_xlat_frame_list = 0;

static ncc_xlat_file_t *ncc_xlat_file_list;
static uint32_t num_xlat_file = 0;

static fr_dict_t *dict_freeradius;

static fr_dict_autoload_t _dict_autoload[] = {
	{ .out = &dict_freeradius, .proto = "freeradius" },
	{ NULL }
};

static fr_dict_attr_t const *attr_tmp_string;

static fr_dict_attr_autoload_t _dict_attr_autoload[] = {
	{ .out = &attr_tmp_string, .name = "Tmp-String-0", .type = FR_TYPE_STRING, .dict = &dict_freeradius },
	{ NULL }
};


int ncc_xlat_init()
{
	if (done_init) return 0;

	if (!xlat_ctx) xlat_ctx = talloc_new(talloc_autofree_context());

	if (fr_dict_autoload(_dict_autoload) < 0) {
		PERROR("Failed to autoload dictionaries");
		return -1;
	}
	if (fr_dict_attr_autoload(_dict_attr_autoload) < 0) {
		PERROR("Failed to autoload dictionary attributes");
		fr_dict_autofree(_dict_autoload);
		return -1;
	}

	done_init = true;
	return 0;
}

void ncc_xlat_free()
{
	fr_dict_autofree(_dict_autoload);

	if (FX_request) TALLOC_FREE(FX_request);
	TALLOC_FREE(xlat_ctx);

	done_init = false;
}

/*
 *	To use FreeRADIUS xlat engine, we need a REQUEST (which is a "typedef struct rad_request").
 *	This is defined in src/lib/server/request.h
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
		FX_request = request_alloc(xlat_ctx);
		FX_request->packet = fr_radius_alloc(FX_request, false);
	}

	FX_request->control = vps; /* Allow to use %{control:Attr} */
	FX_request->packet->vps = vps; /* Allow to use %{packet:Attr} or directly %{Attr} */
	FX_request->rcode = 0;
}


/*
 *	Initialize xlat context in our fake request for processing a list of input vps.
 */
void ncc_xlat_set_num(uint64_t num)
{
	ncc_xlat_init_request(NULL);
	FX_request->number = num; /* Our input id. */
	FX_request->child_number = 0; /* The index of the xlat context for this input. */
	FX_request->rcode = 0; /* Stores xlat error code. */

	/* Free previously stored values for xlat file. */
	int i;
	for (i = 0; i < num_xlat_file; i++) {
		ncc_xlat_file_t *xlat_file = &ncc_xlat_file_list[i];
		TALLOC_FREE(xlat_file->value);
		fr_pair_list_free(&xlat_file->vps);
		xlat_file->is_read = false;
	}
}

/*
 *	Retrieve xlat error code stored in our fake request.
 */
int ncc_xlat_get_rcode()
{
	return FX_request->rcode;
}

/*
 *	Add a xlat file from which values will be read sequentially.
 */
int ncc_xlat_file_add(char const *filename)
{
	FILE *fp = fopen(filename, "r");
	if (!fp) {
		ERROR("Error opening %s: %s", filename, strerror(errno));
		return -1;
	}

	TALLOC_REALLOC_ZERO(xlat_ctx, ncc_xlat_file_list, ncc_xlat_file_t, num_xlat_file, num_xlat_file + 1);
	ncc_xlat_file_t *xlat_file = &ncc_xlat_file_list[num_xlat_file];
	xlat_file->idx_file = num_xlat_file;
	xlat_file->fp = fp;

	num_xlat_file++;

	return 0;
}


#define XLAT_ERR_RETURN \
	request->rcode = -1; \
	return -1;


/*
 *	Retrieve a specific xlat context, using information from our fake request.
 */
static ncc_xlat_frame_t *ncc_xlat_get_ctx(TALLOC_CTX *ctx)
{
	ncc_xlat_frame_t *xlat_frame;

	uint32_t id_list = FX_request->number;
	uint32_t id_item = FX_request->child_number;

	/* Get the list for this input item. If it doesn't exist yet, allocate a new one. */
	ncc_list_t *list;
	if (id_list >= num_xlat_frame_list) {
		uint32_t num_xlat_frame_list_pre = num_xlat_frame_list;
		num_xlat_frame_list = id_list + 1;

		/* Allocate lists to all input items, even if they don't need xlat'ing. This is simpler. */
		TALLOC_REALLOC_ZERO(ctx, ncc_xlat_frame_list, ncc_list_t,
		                    num_xlat_frame_list_pre, num_xlat_frame_list);
	}
	list = &ncc_xlat_frame_list[id_list];

	/* Now get the xlat context. If it doesn't exist yet, allocate a new one and add it to the list. */
	xlat_frame = NCC_LIST_INDEX(list, id_item);
	if (!xlat_frame) {
		/* We don't have a context element yet, need to add a new one. */
		MEM(xlat_frame = talloc_zero(ctx, ncc_xlat_frame_t));

		xlat_frame->num = id_item;

		NCC_LIST_ENQUEUE(list, xlat_frame);
	}

	FX_request->child_number ++; /* Prepare next xlat context. */

	return xlat_frame;
}


/*
 *	Read a list of values from a xlat file.
 *	Rewind if we're at EOF.
 */
int ncc_xlat_get_vps_from_file(TALLOC_CTX *ctx, ncc_xlat_file_t *xlat_file)
{
	if (xlat_file->is_read && !xlat_file->vps) {
		fr_strerror_printf("Cannot read CSV values (file #%u): inconsistent usage", xlat_file->idx_file);
		return -1;
	}

	if (xlat_file->vps) {
		return 0;
	}

	int tries = 0;
	while (!xlat_file->vps && tries < 2) {
		bool filedone = false;
		tries++;
		if (ncc_value_list_afrom_file(ctx, attr_tmp_string, &xlat_file->vps, xlat_file->fp, &xlat_file->num_line, &filedone) < 0) {
			goto error;
		}

		if (filedone) {
			/* Rewind file. */
			fseek(xlat_file->fp, 0L, SEEK_SET);
			xlat_file->num_line = 0;
		}
	}

	if (!xlat_file->vps) {
		fr_strerror_printf("No data");
		goto error;
	}

	xlat_file->is_read = true;
	return 0;

error:
	fr_strerror_printf("Failed to read CSV values (file #%u, line %u): %s",
	                   xlat_file->idx_file, xlat_file->num_line, fr_strerror());
	return -1;
}

/*
 *	Get a value from CSV file. First, read a new line if it has not already been done.
 *	Then extract the Nth value as requested.
 */
VALUE_PAIR *ncc_xlat_get_value_from_csv_file(TALLOC_CTX *ctx, ncc_xlat_file_t *xlat_file, uint32_t idx_value)
{
	/* Read a line from the file, or check we've already read. */
	if (ncc_xlat_get_vps_from_file(ctx, xlat_file) < 0) {
		return NULL;
	}

	/* Retrieve the requested value from the list. */
	VALUE_PAIR *vp = xlat_file->vps;
	int i = 0;
	while (vp) {
		if (i == idx_value) break;
		vp = vp->next;
		i++;
	}
	if (!vp) {
		fr_strerror_printf("Not enough CSV values (file #%u, line %u)", xlat_file->idx_file, xlat_file->num_line);
		return NULL;
	}

	return vp;
}

/*
 *	Parse csv file "<file index>.<value index>".
 *	Default: <file index> = 0 (first file); <value index> is mandatory.
 */
int ncc_parse_file_csv(uint32_t *idx_file, uint32_t *idx_value, char const *in)
{
	fr_type_t type = FR_TYPE_UINT32;
	fr_value_box_t vb = { 0 };
	ssize_t len;
	char const *p = NULL;

	if (!in || in[0] == '\0') {
		fr_strerror_printf("No input format provided");
		return -1;
	}

	*idx_file = 0; /* Default. */

	p = strchr(in, '.');
	if (p) {
		/* Convert the file index. */
		len = p - in;
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, in, len, '\0', false) < 0) {
			fr_strerror_printf("Invalid file index, in: [%s]", in);
			return -1;
		}
		*idx_file = vb.vb_uint32;
	}

	if (*idx_file >= num_xlat_file) { /* Not a valid file. */
		fr_strerror_printf("Not a valid file index: %u", *idx_file);
		return -1;
	}

	/* Convert the value index. */
	p = (p ? p + 1 : in);
	if (fr_value_box_from_str(NULL, &vb, &type, NULL, p, -1, '\0', false) < 0) {
		fr_strerror_printf("Invalid value index, in: [%s]", in);
		return -1;
	}
	*idx_value = vb.vb_uint32;

	/* Note: value index cannot be checked at parsing time. */

	return 0;
}

/** Read comma-separated values sequentially from a file.
 *
 *  %{file.csv:<file index>.<value index>}
 *  <file index> (0, 1, ...) corresponds to xlat files added through ncc_xlat_file_add.
 *  <value index> (0, 1, ...) is the index of the value obtained from one line of the xlat file.
 */
static ssize_t _ncc_xlat_file_csv(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	*out = NULL;

	/* Do *not* use the TALLOC context we get from FreeRADIUS. We don't want our contexts to be freed. */
	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		if (ncc_parse_file_csv(&xlat_frame->file_csv.idx_file, &xlat_frame->file_csv.idx_value, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat file.csv: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_FILE_CSV;
	}

	ncc_xlat_file_t *xlat_file = &ncc_xlat_file_list[xlat_frame->file_csv.idx_file];

	/* Read the requested value from CSV file. */
	VALUE_PAIR *vp = ncc_xlat_get_value_from_csv_file(ctx, xlat_file, xlat_frame->file_csv.idx_value);
	if (!vp) {
		XLAT_ERR_RETURN;
	}

	*out = talloc_strdup(ctx, vp->vp_strvalue);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	return strlen(*out);
}

/*
 *	Parse file "<index>". Default: <index> = 0 (first file).
 */
int ncc_parse_file_raw(uint32_t *idx_file, char const *in)
{
	fr_type_t type = FR_TYPE_UINT32;
	fr_value_box_t vb = { 0 };

	*idx_file = 0; /* Default. */

	if (in) {
		/* Convert the file index. */
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, in, -1, '\0', false) < 0) {
			fr_strerror_printf("Invalid index, in: [%s]", in);
			return -1;
		}
		*idx_file = vb.vb_uint32;
	}

	if (*idx_file >= num_xlat_file) { /* Not a valid file. */
		fr_strerror_printf("Not a valid file index: %u", *idx_file);
		return -1;
	}
	return 0;
}

/** Read raw values sequentially from a file.
 *
 *  %{file:<index>} - where <index> (0, 1, ...) corresponds to xlat files added through ncc_xlat_file_add.
 */
static ssize_t _ncc_xlat_file_raw(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	*out = NULL;

	/* Do *not* use the TALLOC context we get from FreeRADIUS. We don't want our contexts to be freed. */
	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		if (ncc_parse_file_raw(&xlat_frame->file.idx_file, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat file.raw: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_FILE;
	}

	ncc_xlat_file_t *xlat_file = &ncc_xlat_file_list[xlat_frame->file.idx_file];

	if (xlat_file->is_read && !xlat_file->value) {
		fr_strerror_printf("Cannot read raw value (file #%u): inconsistent usage", xlat_file->idx_file);
		XLAT_ERR_RETURN;
	}

	/* If we have a value stored already, use it. */
	if (xlat_file->value) {
		*out = talloc_strdup(ctx, xlat_file->value);
		return strlen(*out);
	}

	/* Otherwise, read a new value from file. */
	FILE *fp = xlat_file->fp;
	if (!fp) {
		return -1;
	}

	char buf[8192];
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		/* Rewind file. Then read again. */
		fseek(fp, 0L, SEEK_SET);

		if (fgets(buf, sizeof(buf), fp) == NULL) {
			/* Should never happen: even if the file is empty, we can read once (obtaining an empty string). */
			return -1;
		}
	}

	/* Remove trailing \n if there is one. */
	size_t len = strlen(buf);
	if (len > 0 && buf[len-1] == '\n') {
		buf[--len] = '\0';
	}

	if (!xlat_file->value) {
		/* Store value in case we need it later on. */
		xlat_file->is_read = true;
		xlat_file->value = talloc_strdup(xlat_ctx, buf);
	}

	*out = talloc_strdup(ctx, buf);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	return strlen(*out);
}


/*
 *	Parse a num range "<num1>-<num2>" and extract <num1> / <num2> as uint64_t.
 */
int ncc_parse_num_range(uint64_t *num1, uint64_t *num2, char const *in)
{
	fr_type_t type = FR_TYPE_UINT64;
	fr_value_box_t vb = { 0 };
	ssize_t len;
	size_t inlen = 0;
	char const *p = NULL;

	if (in) {
		inlen = strlen(in);
		p = strchr(in, '-'); /* Range delimiter can be omitted (only lower bound is provided). */
	}

	if ((inlen > 0) && (!p || p > in)) {
		len = (p ? p - in : -1);

		/* Convert the first number. */
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, in, len, '\0', false) < 0) {
			fr_strerror_printf("Invalid first number, in: [%s]", in);
			return -1;
		}
		*num1 = vb.vb_uint64;

	} else {
		/* No first number: use 0 as lower bound. */
		*num1 = 0;
	}

	if (p && p < in + inlen - 1) {
		/* Convert the second number. */
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, (p + 1), -1, '\0', false) < 0) {
			fr_strerror_printf("Invalid second number, in: [%s]", in);
			return -1;
		}
		*num2 = vb.vb_uint64;

	} else {
		/* No first number: use 0 as lower bound. */
		*num2 = UINT64_MAX;
	}

	if (*num1 > *num2) { /* Not a valid range. */
		fr_strerror_printf("Not a valid num range (%"PRIu64" > %"PRIu64")", *num1, *num2);
		return -1;
	}
	return 0;
}

/** Generate increasing numeric values from a range.
 *
 *  %{num.range:1000-2000} -> 1000, 1001, etc.
 */
static ssize_t _ncc_xlat_num_range(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	*out = NULL;

	/* Do *not* use the TALLOC context we get from FreeRADIUS. We don't want our contexts to be freed. */
	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		uint64_t num1, num2;
		if (ncc_parse_num_range(&num1, &num2, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat num range: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_NUM_RANGE;
		xlat_frame->num_range.min = num1;
		xlat_frame->num_range.max = num2;
		xlat_frame->num_range.next = num1;
	}

	*out = talloc_typed_asprintf(ctx, "%lu", xlat_frame->num_range.next);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	/* Prepare next value. */
	if (xlat_frame->num_range.next == xlat_frame->num_range.max) {
		xlat_frame->num_range.next = xlat_frame->num_range.min;
	} else {
		xlat_frame->num_range.next ++;
	}

	return strlen(*out);
}

ssize_t ncc_xlat_num_range(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt)
{
	return _ncc_xlat_num_range(ctx, out, outlen, NULL, NULL, NULL, fmt);
}

/** Generate random numeric values from a range.
 *
 *  %{num.rand:1000-2000} -> 1594, ...
 */
static ssize_t _ncc_xlat_num_rand(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	uint64_t delta, value;

	*out = NULL;

	/* Do *not* use the TALLOC context we get from FreeRADIUS. We don't want our contexts to be freed. */
	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		uint64_t num1, num2;
		if (ncc_parse_num_range(&num1, &num2, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat num range: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_NUM_RAND;
		xlat_frame->num_range.min = num1;
		xlat_frame->num_range.max = num2;
	}

	double rnd = (double)fr_rand() / UINT32_MAX; /* Random value between 0..1 */

	//delta = xlat_frame->num_range.max - xlat_frame->num_range.min + 1;
	delta = xlat_frame->num_range.max - xlat_frame->num_range.min;
	if (delta < UINT64_MAX) delta++; /* Don't overthrow. */
	value = (uint64_t)(rnd * delta) + xlat_frame->num_range.min;

	*out = talloc_typed_asprintf(ctx, "%lu", value);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	return strlen(*out);
}

ssize_t ncc_xlat_num_rand(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt)
{
	return _ncc_xlat_num_rand(ctx, out, outlen, NULL, NULL, NULL, fmt);
}


/*
 *	Parse an IPv4 range "<IP1>-<IP2>" and extract <IP1> / <IP2> as fr_ipaddr_t.
 */
int ncc_parse_ipaddr_range(fr_ipaddr_t *ipaddr1, fr_ipaddr_t *ipaddr2, char const *in)
{
	fr_type_t type = FR_TYPE_IPV4_ADDR;
	fr_value_box_t vb = { 0 };
	ssize_t len;
	size_t inlen = 0;
	char const *p = NULL;

	if (in) {
		inlen = strlen(in);
		p = strchr(in, '-'); /* Range delimiter can be omitted (only lower bound is provided). */
	}

	if ((inlen > 0) && (!p || p > in)) {
		len = (p ? p - in : -1);

		/* Convert the first IPv4 address. */
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, in, len, '\0', false) < 0) {
			fr_strerror_printf("Invalid first ipaddr, in: [%s]", in);
			return -1;
		}
		*ipaddr1 = vb.vb_ip;

	} else {
		/* No first IPv4 address: use 0.0.0.1 as lower bound. */
		fr_ipaddr_t ipaddr_min = { .af = AF_INET, .prefix = 32, .addr.v4.s_addr = htonl(0x00000001) };
		*ipaddr1 = ipaddr_min;
	}

	if (p && p < in + inlen - 1) {
		/* Convert the second IPv4 address. */
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, (p + 1), -1, '\0', false) < 0) {
			fr_strerror_printf("Invalid second ipaddr, in: [%s]", in);
			return -1;
		}
		*ipaddr2 = vb.vb_ip;

	} else {
		/* No second IPv4 address: use 255.255.255.254 as upper bound. */
		fr_ipaddr_t ipaddr_max = { .af = AF_INET, .prefix = 32, .addr.v4.s_addr = htonl(0xfffffffe) };
		*ipaddr2 = ipaddr_max;
	}

	if (ipaddr1->af != AF_INET || ipaddr2->af  != AF_INET) { /* Not IPv4. */
		fr_strerror_printf("Only IPv4 addresses are supported, in: [%s]", in);
		return -1;
	}

	if (ntohl(ipaddr1->addr.v4.s_addr) > ntohl(ipaddr2->addr.v4.s_addr)) { /* Not a valid range. */
		fr_strerror_printf("Not a valid ipaddr range, in: [%s]", in);
		return -1;
	}

	return 0;
}

/** Generate increasing IP addr values from a range.
 *
 *  %{ipaddr.range:10.0.0.1-10.0.0.255} -> 10.0.0.1, 10.0.0.2, etc.
 */
static ssize_t _ncc_xlat_ipaddr_range(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	*out = NULL;

	/* Do *not* use the TALLOC context we get from FreeRADIUS. We don't want our contexts to be freed. */
	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		fr_ipaddr_t ipaddr1, ipaddr2;
		if (ncc_parse_ipaddr_range(&ipaddr1, &ipaddr2, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat ipaddr range: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_IPADDR_RANGE;
		xlat_frame->ipaddr_range.min = ipaddr1.addr.v4.s_addr;
		xlat_frame->ipaddr_range.max = ipaddr2.addr.v4.s_addr;
		xlat_frame->ipaddr_range.next = ipaddr1.addr.v4.s_addr;
	}

	char ipaddr_buf[FR_IPADDR_STRLEN] = "";
	struct in_addr addr;
	addr.s_addr = xlat_frame->ipaddr_range.next;
	if (inet_ntop(AF_INET, &addr, ipaddr_buf, sizeof(ipaddr_buf)) == NULL) { /* Cannot happen. */
		fr_strerror_printf("%s", fr_syserror(errno));
		XLAT_ERR_RETURN;
	}

	*out = talloc_typed_asprintf(ctx, "%s", ipaddr_buf);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	/* Prepare next value. */
	if (xlat_frame->ipaddr_range.next == xlat_frame->ipaddr_range.max) {
		xlat_frame->ipaddr_range.next = xlat_frame->ipaddr_range.min;
	} else {
		xlat_frame->ipaddr_range.next = htonl(ntohl(xlat_frame->ipaddr_range.next) + 1);
	}

	return strlen(*out);
}

ssize_t ncc_xlat_ipaddr_range(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt)
{
	return _ncc_xlat_ipaddr_range(ctx, out, outlen, NULL, NULL, NULL, fmt);
}

/** Generate random IP addr values from a range.
 *
 *  %{ipaddr.rand:10.0.0.1-10.0.0.255} -> 10.0.0.120, ...
 *
 *  %{ipaddr.rand}
 */
static ssize_t _ncc_xlat_ipaddr_rand(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	uint32_t num1, num2, value;
	uint64_t delta; /* Allow UINT32_MAX + 1. */

	*out = NULL;

	/* Do *not* use the TALLOC context we get from FreeRADIUS. We don't want our contexts to be freed. */
	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		fr_ipaddr_t ipaddr1, ipaddr2;
		if (ncc_parse_ipaddr_range(&ipaddr1, &ipaddr2, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat ipaddr range: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_IPADDR_RAND;
		xlat_frame->ipaddr_range.min = ipaddr1.addr.v4.s_addr;
		xlat_frame->ipaddr_range.max = ipaddr2.addr.v4.s_addr;
	}

	num1 = ntohl(xlat_frame->ipaddr_range.min);
	num2 = ntohl(xlat_frame->ipaddr_range.max);

	double rnd = (double)fr_rand() / UINT32_MAX; /* Random value between 0..1 */

	delta = (uint64_t)num2 - num1 + 1;
	value = (uint32_t)(rnd * delta) + num1;

	char ipaddr_buf[FR_IPADDR_STRLEN] = "";
	struct in_addr addr;
	addr.s_addr = htonl(value);;
	if (inet_ntop(AF_INET, &addr, ipaddr_buf, sizeof(ipaddr_buf)) == NULL) { /* Cannot happen. */
		fr_strerror_printf("%s", fr_syserror(errno));
		XLAT_ERR_RETURN;
	}
	*out = talloc_typed_asprintf(ctx, "%s", ipaddr_buf);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	return strlen(*out);
}

ssize_t ncc_xlat_ipaddr_rand(TALLOC_CTX *ctx, char **out, UNUSED size_t outlen, char const *fmt)
{
	return _ncc_xlat_ipaddr_rand(ctx, out, outlen, NULL, NULL, NULL, fmt);
}


/*
 *	Parse an Ethernet address range "<Ether1>-<Ether2>" and extract <Ether1> / <Ether2> as uint8_t[6].
 */
int ncc_parse_ethaddr_range(uint8_t ethaddr1[6], uint8_t ethaddr2[6], char const *in)
{
	fr_type_t type = FR_TYPE_ETHERNET;
	fr_value_box_t vb = { 0 };
	ssize_t len;
	size_t inlen = 0;
	char const *p = NULL;

	if (in) {
		inlen = strlen(in);
		p = strchr(in, '-'); /* Range delimiter can be omitted (only lower bound is provided). */
	}

	/* FreeRADIUS bug when handling just an int, cf. fr_value_box_from_str (src\lib\util\value.c)
	 * https://github.com/FreeRADIUS/freeradius-server/issues/2596
	 * => Now fixed, so we can allow int values once again.
	 */
	if ((inlen > 0) && (!p || p > in)) {
		len = (p ? p - in : -1);

		/* Convert the first Ethernet address. */
		//if (is_integer_n(in, len)
		//    || fr_value_box_from_str(NULL, &vb, &type, NULL, in, len, '\0', false) < 0) {
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, in, len, '\0', false) < 0) {
			fr_strerror_printf("Invalid first ethaddr, in: [%s]", in);
			return -1;
		}
		memcpy(ethaddr1, &vb.vb_ether, 6);

	} else {
		/* No first Ethernet address: use 00:00:00:00:00:01 as lower bound. */
		uint8_t ethaddr_min[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
		memcpy(ethaddr1, &ethaddr_min, 6);
	}

	if (p && p < in + inlen - 1) {
		/* Convert the second Ethernet address. */
		//if (is_integer_n(p + 1, -1)
		//    || fr_value_box_from_str(NULL, &vb, &type, NULL, (p + 1), -1, '\0', false) < 0) {
		if (fr_value_box_from_str(NULL, &vb, &type, NULL, (p + 1), -1, '\0', false) < 0) {
			fr_strerror_printf("Invalid second ethaddr, in: [%s]", in);
			return -1;
		}
		memcpy(ethaddr2, &vb.vb_ether, 6);

	} else {
		/* No second Ethernet address: use ff:ff:ff:ff:ff:fe as upper bound. */
		uint8_t ethaddr_max[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe };
		memcpy(ethaddr2, &ethaddr_max, 6);
	}

	/* Ensure this is a valid range. */
	uint64_t num1, num2;
	memcpy(&num1, ethaddr1, 6);
	num1 = (ntohll(num1) >> 16);

	memcpy(&num2, ethaddr2, 6);
	num2 = (ntohll(num2) >> 16);

	if (num1 > num2) { /* Not a valid range. */
		fr_strerror_printf("Not a valid ethaddr range, in: [%s]", in);
		return -1;
	}

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
	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		uint8_t ethaddr1[6], ethaddr2[6];
		if (ncc_parse_ethaddr_range(ethaddr1, ethaddr2, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat ethaddr range: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_ETHADDR_RANGE;
		memcpy(xlat_frame->ethaddr_range.min, ethaddr1, 6);
		memcpy(xlat_frame->ethaddr_range.max, ethaddr2, 6);
		memcpy(xlat_frame->ethaddr_range.next, ethaddr1, 6);
	}

	char ethaddr_buf[NCC_ETHADDR_STRLEN] = "";
	ncc_ether_addr_sprint(ethaddr_buf, xlat_frame->ethaddr_range.next);

	*out = talloc_typed_asprintf(ctx, "%s", ethaddr_buf);
	/* Note: we allocate our own output buffer (outlen = 0) as specified when registering. */

	/* Prepare next value. */
	if (memcmp(xlat_frame->ethaddr_range.next, xlat_frame->ethaddr_range.max, 6) == 0) {
		memcpy(xlat_frame->ethaddr_range.next, xlat_frame->ethaddr_range.min, 6);
	} else {
		/* Store the 6 octets of Ethernet addr in a uint64_t to perform an integer increment.
		 */
		uint64_t ethaddr = 0;
		memcpy(&ethaddr, xlat_frame->ethaddr_range.next, 6);

		ethaddr = (ntohll(ethaddr) >> 16) + 1;
		ethaddr = htonll(ethaddr << 16);
		memcpy(xlat_frame->ethaddr_range.next, &ethaddr, 6);
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

	ncc_xlat_frame_t *xlat_frame = ncc_xlat_get_ctx(xlat_ctx);
	if (!xlat_frame) return -1; /* Cannot happen. */

	if (!xlat_frame->type) {
		/* Not yet parsed. */
		uint8_t ethaddr1[6], ethaddr2[6];
		if (ncc_parse_ethaddr_range(ethaddr1, ethaddr2, fmt) < 0) {
			fr_strerror_printf("Failed to parse xlat ethaddr range: %s", fr_strerror());
			XLAT_ERR_RETURN;
		}

		xlat_frame->type = NCC_CTX_TYPE_ETHADDR_RAND;
		memcpy(xlat_frame->ethaddr_range.min, ethaddr1, 6);
		memcpy(xlat_frame->ethaddr_range.max, ethaddr2, 6);
	}

	memcpy(&num1, xlat_frame->ethaddr_range.min, 6);
	num1 = (ntohll(num1) >> 16);

	memcpy(&num2, xlat_frame->ethaddr_range.max, 6);
	num2 = (ntohll(num2) >> 16);

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


/** Generate a string of random chars
 *
 *  Reuse from FreeRADIUS xlat_func_randstr (src/lib/server/xlat_func.c)
 *  converted to non async - because we can't use that.
 */
static ssize_t _ncc_xlat_randstr(UNUSED TALLOC_CTX *ctx, char **out, size_t outlen,
				UNUSED void const *mod_inst, UNUSED void const *xlat_inst,
				UNUSED REQUEST *request, char const *fmt)
{
	/*
 	 *	Lookup tables for randstr char classes
 	 */
	static char	randstr_punc[] = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
	static char	randstr_salt[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz/.";

 	/*
 	 *	Characters humans rarely confuse. Reduces char set considerably
 	 *	should only be used for things such as one time passwords.
 	 */
	static char	randstr_otp[] = "469ACGHJKLMNPQRUVWXYabdfhijkprstuvwxyz";

	char const 	*p, *start, *end;
	char		*endptr;
	char		*buff, *buff_p;
	unsigned int	result;
	unsigned int	reps;
	//size_t		outlen = 0;

	/** Max repetitions of a single character class
	 *
	 */
#define REPETITION_MAX 1024

	/*
	 *	Nothing to do if input is empty
	 */
	if (!fmt) {
		fr_strerror_printf("No format provided");
		return -1;
	}

	start = p = fmt;
	end = p + strlen(fmt);

	/*
	 *	Calculate size of output
	 */
	while (p < end) {
		/*
		 *	Repetition modifiers.
		 *
		 *	We limit it to REPETITION_MAX, because we don't want
		 *	utter stupidity.
		 */
		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) reps = REPETITION_MAX;
			/* hexits take up 2 characters */
			outlen += reps;
			p = endptr;
		} else {
			outlen++;
		}
		p++;
	}

	buff = buff_p = talloc_array(NULL, char, outlen + 1);

	/* Reset p to start position */
	p = start;

	while (*p) {
		size_t i;

		if (isdigit((int) *p)) {
			reps = strtol(p, &endptr, 10);
			if (reps > REPETITION_MAX) {
				/* Limit repetition to REPETITION_MAX */
				reps = REPETITION_MAX;
			}
			p = endptr;
		} else {
			reps = 1;
		}

		for (i = 0; i < reps; i++) {
			result = fr_rand();
			switch (*p) {
			/*
			 *  Lowercase letters
			 */
			case 'c':
				*buff_p++ = 'a' + (result % 26);
				break;

			/*
			 *  Uppercase letters
			 */
			case 'C':
				*buff_p++ = 'A' + (result % 26);
				break;

			/*
			 *  Numbers
			 */
			case 'n':
				*buff_p++ = '0' + (result % 10);
				break;

			/*
			 *  Alpha numeric
			 */
			case 'a':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 3)];
				break;

			/*
			 *  Punctuation
			 */
			case '!':
			case ',': // added alternative because "!" is complicated to use from command line + xlat.
				*buff_p++ = randstr_punc[result % (sizeof(randstr_punc) - 1)];
				break;

			/*
			 *  Alpha numeric + punctuation
			 */
			case '.':
				*buff_p++ = '!' + (result % 95);
				break;

			/*
			 *  Alpha numeric + salt chars './'
			 */
			case 's':
				*buff_p++ = randstr_salt[result % (sizeof(randstr_salt) - 1)];
				break;

			/*
			 *  Chars suitable for One Time Password tokens.
			 *  Alpha numeric with easily confused char pairs removed.
			 */
			case 'o':
				*buff_p++ = randstr_otp[result % (sizeof(randstr_otp) - 1)];
				break;

			/*
			 *	Binary data - Copy between 1-4 bytes at a time
			 */
			case 'b':
			{
				size_t copy = (reps - i) > sizeof(result) ? sizeof(result) : reps - i;

				memcpy(buff_p, (uint8_t *)&result, copy);
				buff_p += copy;
				i += (copy - 1);	/* Loop +1 */
			}
				break;

			case ' ': // allow to have spaces within format
				*buff_p++ = ' ';
				break;

			default:
				fr_strerror_printf("Invalid character class '%c'", *p);
				talloc_free(buff);
				XLAT_ERR_RETURN;
			}
		}

		p++;
	}

	*buff_p++ = '\0';

	*out = buff;
	return strlen(*out);
}


/*
 *	Register our own xlat functions (and implicitly initialize the xlat framework).
 */
int ncc_xlat_register(void)
{
	if (ncc_xlat_init() < 0) return -1;

	if (
		ncc_xlat_core_register(NULL, NCC_XLAT_FILE_RAW, _ncc_xlat_file_raw, NULL, NULL, 0, 0, true) < 0 ||
		ncc_xlat_core_register(NULL, NCC_XLAT_FILE_CSV, _ncc_xlat_file_csv, NULL, NULL, 0, 0, true) < 0 ||

		ncc_xlat_core_register(NULL, NCC_XLAT_NUM_RANGE, _ncc_xlat_num_range, NULL, NULL, 0, 0, true) < 0 ||
		ncc_xlat_core_register(NULL, NCC_XLAT_NUM_RAND, _ncc_xlat_num_rand, NULL, NULL, 0, 0, true) < 0 ||

		ncc_xlat_core_register(NULL, NCC_XLAT_IPADDR_RANGE, _ncc_xlat_ipaddr_range, NULL, NULL, 0, 0, true) < 0 ||
		ncc_xlat_core_register(NULL, NCC_XLAT_IPADDR_RAND, _ncc_xlat_ipaddr_rand, NULL, NULL, 0, 0, true) < 0 ||

		ncc_xlat_core_register(NULL, NCC_XLAT_ETHADDR_RANGE, _ncc_xlat_ethaddr_range, NULL, NULL, 0, 0, true) < 0 ||
		ncc_xlat_core_register(NULL, NCC_XLAT_ETHADDR_RAND, _ncc_xlat_ethaddr_rand, NULL, NULL, 0, 0, true) < 0 ||

		ncc_xlat_core_register(NULL, NCC_XLAT_RANDSTR, _ncc_xlat_randstr, NULL, NULL, 0, 0, true) < 0
		)
	{
		return -1;
	}

	return 0;
}
