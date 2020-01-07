/**
 * @file ncc_curl.c
 * @brief Libcurl interface.
 *
 * Requires libcurl-devel. Optionally libjson-c-devel.
 */

/* Our own auto-configuration header.
 * Will define HAVE_LIBCURL if libcurl is available.
 */
#include "config.h"

#include "ncc_util.h"
#include "ncc_curl.h"
#ifdef HAVE_LIBCURL

/**
 * Table of encoder/decoder support.
 * (verbatim copy from FreeRADIUS "rest.c")
 */
const http_body_type_t http_body_type_supported[REST_HTTP_BODY_NUM_ENTRIES] = {
	REST_HTTP_BODY_UNKNOWN,		// REST_HTTP_BODY_UNKNOWN
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_UNSUPPORTED
	REST_HTTP_BODY_UNSUPPORTED,  	// REST_HTTP_BODY_UNAVAILABLE
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_INVALID
	REST_HTTP_BODY_NONE,			// REST_HTTP_BODY_NONE
	REST_HTTP_BODY_CUSTOM_XLAT,		// REST_HTTP_BODY_CUSTOM_XLAT
	REST_HTTP_BODY_CUSTOM_LITERAL,	// REST_HTTP_BODY_CUSTOM_LITERAL
	REST_HTTP_BODY_POST,			// REST_HTTP_BODY_POST
#ifdef HAVE_JSON
	REST_HTTP_BODY_JSON,			// REST_HTTP_BODY_JSON
#else
	REST_HTTP_BODY_UNAVAILABLE,
#endif
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_XML
	REST_HTTP_BODY_UNSUPPORTED,		// REST_HTTP_BODY_YAML
	REST_HTTP_BODY_INVALID,		// REST_HTTP_BODY_HTML
	REST_HTTP_BODY_PLAIN			// REST_HTTP_BODY_PLAIN
};

/*
 * Lib CURL doesn't define symbols for unsupported auth methods.
 * (verbatim copy from FreeRADIUS "rest.c")
 */
#ifndef CURLOPT_TLSAUTH_SRP
#  define CURLOPT_TLSAUTH_SRP	0
#endif
#ifndef CURLAUTH_BASIC
#  define CURLAUTH_BASIC	0
#endif
#ifndef CURLAUTH_DIGEST
#  define CURLAUTH_DIGEST	0
#endif
#ifndef CURLAUTH_DIGEST_IE
#  define CURLAUTH_DIGEST_IE	0
#endif
#ifndef CURLAUTH_GSSNEGOTIATE
#  define CURLAUTH_GSSNEGOTIATE	0
#endif
#ifndef CURLAUTH_NTLM
#  define CURLAUTH_NTLM		0
#endif
#ifndef CURLAUTH_NTLM_WB
#  define CURLAUTH_NTLM_WB	0
#endif
#ifndef CURLAUTH_BEARER
#  define CURLAUTH_BEARER	0
#endif // -> addition to "rest.c" (addition in libcurl 7.61.0)

/*
 * Set CURL headers
 */
DIAG_OPTIONAL
DIAG_OFF(disabled-macro-expansion)
#define SET_OPTION(_x, _y)\
do {\
	if ((ret = curl_easy_setopt(candle, _x, _y)) != CURLE_OK) {\
		option = STRINGIFY(_x);\
		goto error;\
	}\
} while (0)

/* (verbatim copy from FreeRADIUS "rest.c")
 */
const unsigned long http_curl_auth[REST_HTTP_AUTH_NUM_ENTRIES] = {
	[REST_HTTP_AUTH_UNKNOWN]		= 0,
	[REST_HTTP_AUTH_NONE]			= 0,
	[REST_HTTP_AUTH_TLS_SRP]		= CURLOPT_TLSAUTH_SRP,
	[REST_HTTP_AUTH_BASIC]			= CURLAUTH_BASIC,
	[REST_HTTP_AUTH_DIGEST]			= CURLAUTH_DIGEST,
	[REST_HTTP_AUTH_DIGEST_IE]		= CURLAUTH_DIGEST_IE,
	[REST_HTTP_AUTH_GSSNEGOTIATE]		= CURLAUTH_GSSNEGOTIATE,
	[REST_HTTP_AUTH_NTLM]			= CURLAUTH_NTLM,
	[REST_HTTP_AUTH_NTLM_WB]		= CURLAUTH_NTLM_WB,
	[REST_HTTP_AUTH_ANY]			= CURLAUTH_ANY,
	[REST_HTTP_AUTH_ANY_SAFE]		= CURLAUTH_ANYSAFE,
	[REST_HTTP_AUTH_BEARER]			= CURLAUTH_BEARER
};
// REST_HTTP_AUTH_BEARER -> addition to "rest.c" (addition in libcurl 7.61.0)

/**
 * Conversion table for method config values.
 * (verbatim copy from FreeRADIUS "rest.c")
 */
fr_table_num_sorted_t const http_method_table[] = {
	{ "DELETE",				REST_HTTP_METHOD_DELETE		},
	{ "GET",				REST_HTTP_METHOD_GET		},
	{ "PATCH",				REST_HTTP_METHOD_PATCH		},
	{ "POST",				REST_HTTP_METHOD_POST		},
	{ "PUT",				REST_HTTP_METHOD_PUT		},
	{ "UNKNOWN",				REST_HTTP_METHOD_UNKNOWN	}
};
size_t http_method_table_len = NUM_ELEMENTS(http_method_table);

/**
 * Conversion table for type config values.
 * (verbatim copy from FreeRADIUS "rest.c")
 */
fr_table_num_sorted_t const http_body_type_table[] = {
	{ "html",				REST_HTTP_BODY_HTML		},
	{ "invalid",				REST_HTTP_BODY_INVALID		},
	{ "json",				REST_HTTP_BODY_JSON		},
	{ "none",				REST_HTTP_BODY_NONE		},
	{ "plain",				REST_HTTP_BODY_PLAIN		},
	{ "post",				REST_HTTP_BODY_POST		},
	{ "unavailable",			REST_HTTP_BODY_UNAVAILABLE	},
	{ "unknown",				REST_HTTP_BODY_UNKNOWN		},
	{ "unsupported",			REST_HTTP_BODY_UNSUPPORTED	},
	{ "xml",				REST_HTTP_BODY_XML		},
	{ "yaml",				REST_HTTP_BODY_YAML		}
};
size_t http_body_type_table_len = NUM_ELEMENTS(http_body_type_table);

/* (verbatim copy from FreeRADIUS "rest.c")
 */
fr_table_num_sorted_t const http_auth_table[] = {
	{ "any",				REST_HTTP_AUTH_ANY		},
	{ "basic",				REST_HTTP_AUTH_BASIC		},
	{ "digest",				REST_HTTP_AUTH_DIGEST		},
	{ "digest-ie",				REST_HTTP_AUTH_DIGEST_IE	},
	{ "gss-negotiate",			REST_HTTP_AUTH_GSSNEGOTIATE	},
	{ "none",				REST_HTTP_AUTH_NONE		},
	{ "ntlm",				REST_HTTP_AUTH_NTLM		},
	{ "ntlm-winbind",			REST_HTTP_AUTH_NTLM_WB		},
	{ "safe",				REST_HTTP_AUTH_ANY_SAFE		},
	{ "srp",				REST_HTTP_AUTH_TLS_SRP		},
	{ "bearer",				REST_HTTP_AUTH_BEARER		} // -> addition to "rest.c"
};
size_t http_auth_table_len = NUM_ELEMENTS(http_auth_table);

/**
 * Conversion table for "Content-Type" header values.
 * (verbatim copy from FreeRADIUS "rest.c")
 */
fr_table_num_sorted_t const http_content_type_table[] = {
	{ "application/json",			REST_HTTP_BODY_JSON		},
	{ "application/x-www-form-urlencoded",	REST_HTTP_BODY_POST		},
	{ "application/x-yaml",			REST_HTTP_BODY_YAML		},
	{ "application/yaml",			REST_HTTP_BODY_YAML		},
	{ "text/html",				REST_HTTP_BODY_HTML		},
	{ "text/plain",				REST_HTTP_BODY_PLAIN		},
	{ "text/x-yaml",			REST_HTTP_BODY_YAML		},
	{ "text/xml",				REST_HTTP_BODY_XML		},
	{ "text/yaml",				REST_HTTP_BODY_YAML		}
};
size_t http_content_type_table_len = NUM_ELEMENTS(http_content_type_table);

/*
 * Encoder specific structures.
 */
typedef struct {
	char const *start; //!< Start of the buffer.
	char const *p;     //!< how much text we've sent so far.
	size_t len;        //!< Length of data.
} ncc_curl_custom_data_t;



/**
 * Get curl detailed error from buffer, if set (provides more detail than the generic error)
 * or fallback to curl_easy_strerror.
 * E.g.: detailed error: "Could not resolve host: 1.2.3.4:8086; Name or service not known"
 *     vs generic error: "Couldn't resolve host name"
 */
char const *ncc_curl_strerror(ncc_curl_handle_t *randle, CURLcode curl_ret)
{
	if (randle->error && randle->error[0] != '\0') {
		return randle->error;
	} else {
		return curl_easy_strerror(curl_ret);
	}
}

/**
 * Frees a libcurl handle, and any additional memory used by context data.
 *
 * (cf. _mod_conn_free from FreeRADIUS "rest.c")
 */
static int _mod_conn_free(ncc_curl_handle_t *randle)
{
	curl_easy_cleanup(randle->candle);

	return 0;
}

/**
 * Create a curl connection (optionnally pre-connecting to provided URI).
 *
 * (cf. mod_conn_create from FreeRADIUS "rest.c")
 */
void *ncc_curl_conn_create(TALLOC_CTX *ctx, void *instance)
{
	ncc_curl_mod_t *inst = instance;

	ncc_curl_handle_t *randle = NULL;
	ncc_curl_context_t	*curl_ctx = NULL;

	CURL *candle = NULL;

	char const *option = "unknown";
	CURLcode ret = CURLE_OK;

	candle = curl_easy_init();
	if (!candle) {
		fr_strerror_printf("Failed to start curl session");
		return NULL;
	}

	// FreeRADIUS v4 does not do preconnection anymore ("connect_timeout" is marked as "DEPRECATED").
	// maybe because it now handles multiplexing, so this is irrelevant ?
	// but we don't so I'll keep this.

	SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->connect_timeout));

	if (inst->connect_uri && inst->connect_uri[0] != '\0') {
		/*
		 * Pre-establish TCP connection to remote server.
		 */
		SET_OPTION(CURLOPT_SSL_VERIFYPEER, 0);
		SET_OPTION(CURLOPT_SSL_VERIFYHOST, 0);
		SET_OPTION(CURLOPT_CONNECT_ONLY, 1);
		SET_OPTION(CURLOPT_URL, inst->connect_uri);
		SET_OPTION(CURLOPT_NOSIGNAL, 1);

		DEBUG("curl: Connecting to \"%s\"", inst->connect_uri);

		ret = curl_easy_perform(candle);
		if (ret != CURLE_OK) {
			fr_strerror_printf("Connection failed: curl error (%i) [%s]", ret, curl_easy_strerror(ret));
			goto connection_error;
		}
		DEBUG("curl: Connection established to \"%s\"", inst->connect_uri);

	} else {
		DEBUG2("curl: Skipping pre-connect, connect_uri not specified");
	}

	/*
	 * Clear any previously configured options for the first request.
	 */
	curl_easy_reset(candle);

	/*
	 * Allocate memory for the connection handle abstraction.
	 */
	randle = talloc_zero(ctx, ncc_curl_handle_t);
	curl_ctx = talloc_zero(randle, ncc_curl_context_t);

	curl_ctx->headers = NULL; /* CURL needs this to be NULL */
	curl_ctx->request.instance = inst;
	curl_ctx->response.instance = inst;

	randle->ctx = curl_ctx;
	randle->candle = candle;

	randle->error = talloc_zero_array(randle, char, CURL_ERROR_SIZE + 1);
	SET_OPTION(CURLOPT_ERRORBUFFER, randle->error);

	/* Set a talloc context in response for allocations in decoder. */
	curl_ctx->response.talloc_ctx = randle;

	/*
	 * Don't try any curl stuff beyond this, so we don't risk a double free (curl_easy_cleanup).
	 */
	talloc_set_destructor(randle, _mod_conn_free);

	/*
	 * We don't have a connection API. There's only one connection.
	 * So we just store everything in our instance.
	 */
	inst->randle = randle;

	return randle;

	/*
	 * Cleanup.
	 */
error:
	fr_strerror_printf("Failed to set curl option \"%s\": curl error (%i) [%s]", option, ret, curl_easy_strerror(ret));

	/*
	 * So we don't leak CURL handles.
	 */
connection_error:
	curl_easy_cleanup(candle);
	if (randle) talloc_free(randle);
	return NULL;
}

/**
 * Queries libcurl to try and determine if the TCP socket associated with a
 * connection handle is still active.
 *
 * (cf. mod_conn_alive from FreeRADIUS "rest.c")
 */
bool ncc_curl_conn_alive(void *instance, void *handle)
{
	UNUSED ncc_curl_mod_t *inst = instance;
	ncc_curl_handle_t *randle = handle;

	if (!handle) return false;

	CURL *candle = randle->candle;

	long last_socket;
	CURLcode ret;

	ret = curl_easy_getinfo(candle, CURLINFO_LASTSOCKET, &last_socket);
	if (ret != CURLE_OK) {
		ERROR("curl: Couldn't determine socket state: curl error (%i) [%s]", ret, ncc_curl_strerror(randle, ret));
		return false;
	}

	if (last_socket == -1) {
		return false;
	}

	return true;
}

/**
 * Copies a provided string to the output buffer.
 *
 * (cf. rest_encode_custom from FreeRADIUS "rest.c")
 */
static size_t ncc_curl_encode_custom(void *out, size_t size, size_t nmemb, void *userdata)
{
	ncc_curl_request_t *ctx = userdata;
	ncc_curl_custom_data_t *data = ctx->encoder;

	size_t freespace = (size * nmemb) - 1;
	size_t len;
	size_t to_copy;

	/*
	 * Special case for empty body
	 */
	if (data->len == 0) return 0;

	/*
	 * If len > 0 then we must have these set.
	 */
	ncc_assert(data->start);
	ncc_assert(data->p);

	to_copy = data->len - (data->p - data->start);
	len = to_copy > freespace ? freespace : to_copy;
	if (len == 0) return 0;

	memcpy(out, data->p, len);
	data->p += len;

	DEBUG3("Encoded body data: %pV", fr_box_strvalue_len(out, len));

	return len;
}

/**
 * Emulates successive libcurl calls to an encoding function.
 *
 * (cf. rest_request_encode_wrapper from FreeRADIUS "rest.c")
 */
static ssize_t ncc_curl_request_encode_wrapper(char **out, curl_read_t func, size_t limit, void *userdata)
{
	char *buff = NULL;
	size_t alloc = REST_BODY_ALLOC_CHUNK; /* Size of buffer to alloc */
	// Note: we'll never need more than this (1024), so the loop is not strictly necessary.

	size_t used = 0; /* Size of data written */
	size_t len = 0;

	buff = talloc_array(NULL, char, alloc);
	for (;;) {
		len = func(buff + used, alloc - used, 1, userdata);
		used += len;
		if (!len) {
			*out = buff;
			return used;
		}

		alloc = alloc * 2;
		if (alloc > limit) break;

		MEM(buff = talloc_realloc(NULL, buff, char, alloc));
	};

	talloc_free(buff);

	return -1;
}

/**
 * Initialises the data in a ncc_curl_request_t.
 *
 * (cf. rest_request_init from FreeRADIUS "rest.c")
 */
UNUSED static void ncc_curl_request_init(ncc_curl_mod_section_t const *section, ncc_curl_request_t *ctx)
{
	ctx->section = section;
	ctx->state = READ_STATE_INIT;
}

#ifdef HAVE_JSON
/**
 * Decode a JSON raw response body.
 * Only extract what we need ("error" field if set).
 */
static int ncc_curl_decode_json(ncc_curl_response_t *response)
{
	int ret = 0;
	char *raw = response->buffer;
	char const *p = raw;
	struct json_object *json;
	char const *value;

	/*
	 * Empty response?
	 */
	fr_skip_whitespace(p);
	if (*p == '\0') {
		DEBUG3("Empty JSON response");
		return 0;
	}

	json = json_tokener_parse(p);
	if (!json) {
		DEBUG3("Malformed JSON data \"%s\"", raw);
		return -1;
	}

	/* We only need to extract the "error" field.
	 */
	json_object *obj_error;
	//obj_error = json_object_object_get(json, "error");
	// json_object_object_get was deprecated at some point, and then "un-deprecated"...

	json_object_object_get_ex(json, "error", &obj_error);
	if (!obj_error || !fr_json_object_is_type(obj_error, json_type_string)) {
		DEBUG3("No \"error\" in JSON response");
		goto end;
	}

	value = json_object_get_string(obj_error);

	response->error = talloc_strdup(response->talloc_ctx, value);

end:
	/*
	 * Decrement reference count for root object, should free entire JSON tree.
	 */
	json_object_put(json);

	return ret;
}
#endif

/**
 * Extract TLS certificate chain information from the response.
 *
 * (cf. rest_response_certinfo from FreeRADIUS "rest.c")
 */
int ncc_curl_response_certinfo(ncc_curl_mod_t const *inst, UNUSED ncc_curl_mod_section_t const *section, void *handle)
{
	// NOT IMPLEMENTED
	return 0;
}

/**
 * Sends the response to the decode function.
 *
 * (cf. rest_response_decode from FreeRADIUS "rest.c")
 */
int ncc_curl_response_decode(void *handle)
{
	ncc_curl_handle_t *randle = handle;
	ncc_curl_context_t *ctx = randle->ctx;
	http_body_type_t type = ctx->response.type;

	int ret = -1;

	if (!ctx->response.buffer) {
		DEBUG3("Skipping response decoding, no valid body data received");
		return 0;
	}

	DEBUG3("Decoding response (type: %u = %s)", type, fr_table_str_by_value(http_body_type_table, type, "<INVALID>"));

	switch (type) {
#ifdef HAVE_JSON
	case REST_HTTP_BODY_JSON:
		ret = ncc_curl_decode_json(&ctx->response);
		break;
#endif

	// we really only expect JSON response.
	default:
		break;
	}

	return ret;
}

/**
 * Processes incoming HTTP header data from libcurl.
 *
 * (cf. rest_response_header from FreeRADIUS "rest.c")
 */
static size_t ncc_curl_response_header(void *in, size_t size, size_t nmemb, void *userdata)
{
	ncc_curl_response_t *ctx = userdata;
	ncc_curl_mod_section_t const *section = ctx->section;
	TALLOC_CTX *talloc_ctx = ctx->talloc_ctx;

	char const *start = (char *)in, *p = start, *end = p + (size * nmemb);
	char *q;
	size_t len;

	size_t len_errh = 0; /* Length of specific header from which we'll try to get an error message. */
	if (section->error_from_header) len_errh = strlen(section->error_from_header);

	http_body_type_t type;

	DEBUG4("curl: Header received: [%pV]", fr_box_strvalue_len(in, STR_LEN_TRIM_EOL(in)));

	if (ctx->state == WRITE_STATE_DISCARD) {
	discard:
		/* Failed to handle previous data from curl, so now just don't do anything more.
		 */
		//return (end - start);
		return 0;
		// Note: returning 0 triggers a: curl error (23) [Failed writing header]
	}

	/*
	 * This seems to be curl's indication there are no more header lines.
	 */
	if (((end - p) == 2) && ((p[0] == '\r') && (p[1] == '\n'))) {
		/*
		 * If we got a 100 Continue, we need to send additional payload data.
		 * reset the state to WRITE_STATE_INIT, so that when were called again
		 * we overwrite previous header data with that from the proper header.
		 */
		if (ctx->code == 100) {
			DEBUG3("Continuing...");
			ctx->state = WRITE_STATE_INIT;
		}

		return (end - start);
	}

	switch (ctx->state) {
	case WRITE_STATE_INIT:
		DEBUG3("Processing response header");

		/*
		 * HTTP/<version> <reason_code>[ <reason_phrase>]\r\n
		 *
		 * "HTTP/1.1 " (8) + "100 " (4) + "\r\n" (2) = 14
		 * "HTTP/2 " (8) + "100 " (4) + "\r\n" (2) = 12
		 */
		if ((end - p) < 12) {
			DEBUG3("Malformed HTTP header: Status line too short");
		malformed:
			DEBUG3("Received %zu bytes of invalid header data: %pV",
				(end - start), fr_box_strvalue_len(in, (end - start)));

			ctx->code = 0;

			// fix to FreeRADIUS ? else we get called to decode the rest but we don't care at this point...
			ctx->state = WRITE_STATE_DISCARD;
			goto discard;

			/*
			 * Indicate we parsed the entire line, otherwise
			 * bad things seem to happen internally with
			 * libcurl when we try and use it with asynchronous
			 * I/O handlers.
			 */
			return (end - start);
		}
		/*
		 * Check start of header matches...
		 */
		if (strncasecmp("HTTP/", p, 5) != 0) {
			DEBUG3("Malformed HTTP header: Missing HTTP version");
			goto malformed;
		}
		p += 5;

		/*
		 * Skip the version field, next space should mark start of reason_code.
		 */
		q = memchr(p, ' ', (end - p));
		if (!q) {
			DEBUG3("Malformed HTTP header: Missing reason code");
			goto malformed;
		}

		p = q;

		/*
		 * Process reason_code.
		 *
		 * " 100" (4) + "\r\n" (2) = 6
		 */
		if ((end - p) < 6) {
			DEBUG3("Malformed HTTP header: Reason code too short");
			goto malformed;
		}
		p++;

		/*
		 * "xxx( |\r)" status code and terminator.
		 */
		if (!isdigit(p[0]) || !isdigit(p[1]) || !isdigit(p[2]) || !((p[3] == ' ') || (p[3] == '\r'))) {
			DEBUG3("Malformed HTTP header: Reason code malformed. "
				"Expected three digits then space or end of header, got \"%pV\"",
				fr_box_strvalue_len(p, 4));
			goto malformed;
		}

		/*
		 * Convert status code into an integer value
		 */
		q = NULL;
		ctx->code = (int)strtoul(p, &q, 10);
		ncc_assert(q == (p + 3)); /* We check this above */
		p = q;

		/*
		 * Process reason_phrase (if present).
		 */
		if (*p == ' ') {
			q = memchr(p, '\r', (end - p));
			if (!q) goto malformed;
			//DEBUG3("Status : %i (%pV)", ctx->code, fr_box_strvalue_len(p, q - p)); // very minor FreeRADIUS issue:
			DEBUG3("Response HTTP Status: %i (%pV)", ctx->code, fr_box_strvalue_len(p + 1, q - p - 1));
		} else {
			DEBUG3("Response HTTP Status: %i", ctx->code);
		}

		ctx->state = WRITE_STATE_PARSE_HEADERS;

		break;

	case WRITE_STATE_PARSE_HEADERS:
		if (((end - p) >= 14) && (strncasecmp("Content-Type: ", p, 14) == 0)) {
			p += 14;

			/*
			 * Check to see if there's a parameter separator.
			 */
			q = memchr(p, ';', (end - p));

			/*
			 * If there's not, find the end of this header.
			 */
			if (!q) q = memchr(p, '\r', (end - p));

			len = (size_t)(!q ? (end - p) : (q - p));
			type = fr_table_value_by_substr(http_content_type_table, p, len, REST_HTTP_BODY_UNKNOWN);

			DEBUG3("Response type: %u = %s (%pV)", type, fr_table_str_by_value(http_body_type_table, type, "<INVALID>"),
			       fr_box_strvalue_len(p, len));

			/*
			 * Figure out if the type is supported by one of the decoders.
			 */
			ctx->type = http_body_type_supported[type];
		}

		/* Look for specific header to get an error message
		 */
		if (len_errh && ((end - p) >= len_errh + 2)
		    && (strncasecmp(section->error_from_header, p, len_errh) == 0) && (strncasecmp(": ", p + len_errh, 2) == 0)) {
			p += len_errh + 2;

			/* Expose the error.
			 * Note: we won't have this in case of authorization failure.
			 */
			ctx->error = talloc_strdup(talloc_ctx, p);
			STR_TRIM_EOL(ctx->error);

			DEBUG3("Obtained error from header \"%s\": [%s]", section->error_from_header, ctx->error);
		}
		break;

	default:
		break;
	}

	return (end - start);
}

/**
 * Processes incoming HTTP body data from libcurl.
 *
 * (cf. rest_response_body from FreeRADIUS "rest.c")
 */
static size_t ncc_curl_response_body(void *in, size_t size, size_t nmemb, void *userdata)
{
	ncc_curl_response_t *ctx = userdata;

	char const *start = in, *p = start, *end = p + (size * nmemb);
	//char *q;

	size_t needed;

	if (start == end) return 0; /* Nothing to process */

	/*
	 * Any post processing of headers should go here...
	 */
	if (ctx->state == WRITE_STATE_PARSE_HEADERS) ctx->state = WRITE_STATE_PARSE_CONTENT;

	switch (ctx->type) {
	// we only handle default case, whatever type is set to.
	default:
	{
		char *out_p;

		needed = ROUND_UP(ctx->used + (end - p), REST_BODY_ALLOC_CHUNK);
		if (needed > ctx->alloc) {
			MEM(ctx->buffer = talloc_bstr_realloc(ctx->talloc_ctx, ctx->buffer, needed));
			ctx->alloc = needed;
		}

		out_p = ctx->buffer + ctx->used;
		memcpy(out_p, p, (end - p));
		out_p += (end - p);
		*out_p = '\0';
		ctx->used += (end - p);
	}
		break;
	}

	return (end - start);
}

/**
 * Print out the response error.
 *
 * (cf. rest_response_error from FreeRADIUS "rest.c")
 */
void ncc_curl_response_error(ncc_curl_handle_t *handle)
{
	char *error;

	/* If we stored an error, use it.
	 */
	error = ncc_curl_handle_get_error(handle);
	if (error) {
		fr_strerror_printf("%s", error);
		return;
	}

	/* The server returns a JSON body that we can parse to obtain the "error", e.g.:
	 * {\"error\":\"authorization failed\"}
	 */
	ncc_curl_response_decode(handle);

	error = ncc_curl_handle_get_error(handle);
	if (error) {
		fr_strerror_printf("%s", error);
		return;
	}

	/* If we still have nothing, return the HTTP Status code.
	 */
	fr_strerror_printf("HTTP Status %i", NCC_CURL_HANDLE_GET_CODE(handle));
}

/**
 * Debug the response text.
 *
 * (cf. rest_response_debug from FreeRADIUS rest.c)
 */
void ncc_curl_response_debug(ncc_curl_handle_t *handle)
{
	char const *p, *end;
	char *q;
	size_t len;

	len = ncc_curl_handle_get_data(&p, handle);
	if (len == 0) return;

	end = p + len;

	DEBUG3("curl: Response from server:");
	while ((q = memchr(p, '\n', (end - p)))) {
		DEBUG3("%pV", fr_box_strvalue_len(p, q - p));
		p = q + 1;
	}

	if (p != end) DEBUG3("%pV", fr_box_strvalue_len(p, end - p));
}

/**
 * (Re-)Initialises the data in a rlm_rest_response_t.
 *
 * (cf. rest_response_init from FreeRADIUS "rest.c")
 */
static void ncc_curl_response_init(ncc_curl_mod_section_t const *section, ncc_curl_response_t *ctx, http_body_type_t type)
{
	ctx->section = section;
	ctx->type = type;
	ctx->state = WRITE_STATE_INIT;
	ctx->alloc = 0;
	ctx->used = 0;

	/* Free eventual response data from a previous call.
	 */
	TALLOC_FREE(ctx->buffer);
	TALLOC_FREE(ctx->error);
}

/**
 * Set request data for custom encoding.
 */
void ncc_curl_handle_set_request_data(ncc_curl_handle_t *handle, char const *data)
{
	if (!handle) return;

	ncc_curl_context_t *ctx = handle->ctx;
	ctx->request.data = data;
}

/**
 * Extracts pointer to buffer containing response data.
 * Note: this will be NULL in the normal case ("204 No Content").
 *
 * (cf. rest_get_handle_data from FreeRADIUS "rest.c")
 */
size_t ncc_curl_handle_get_data(char const **out, ncc_curl_handle_t *handle)
{
	*out = NULL;
	if (!handle) return 0;

	ncc_curl_context_t *ctx = handle->ctx;
	*out = ctx->response.buffer;
	return ctx->response.used;
}

/**
 * Obtain the response error from last call.
 */
char *ncc_curl_handle_get_error(ncc_curl_handle_t *handle)
{
	if (!handle) return NULL;

	ncc_curl_context_t *ctx = handle->ctx;
	return ctx->response.error;
}

/**
 * Configures body specific curl options.
 *
 * (cf. rest_request_config_body from FreeRADIUS "rest.c")
 */
static int ncc_curl_request_config_body(ncc_curl_mod_t const *instance, ncc_curl_mod_section_t const *section,
                                        ncc_curl_handle_t *handle, curl_read_t func)
{
	ncc_curl_context_t *ctx = handle->ctx;
	CURL *candle = handle->candle;

	CURLcode ret = CURLE_OK;
	char const *option = "unknown";

	ssize_t len;

	/*
	 * We were provided with no read function, assume this means
	 * no body should be sent.
	 */
	if (!func) {
		SET_OPTION(CURLOPT_POSTFIELDSIZE, 0);
		return 0;
	}

	// Note: we're not handling chunked encoding.

	/*
	 * Read the entire body into a buffer, and send it in one go.
	 */
	len = ncc_curl_request_encode_wrapper(&ctx->body, func, REST_BODY_MAX_LEN, &ctx->request);
	if (len <= 0) {
		fr_strerror_printf_push("Failed to create HTTP body content");
		return -1;
	}
	DEBUG3("Content-Length will be %zu bytes", len);

	SET_OPTION(CURLOPT_POSTFIELDS, ctx->body);
	SET_OPTION(CURLOPT_POSTFIELDSIZE, len);

	return 0;

error:
	fr_strerror_printf("Failed to set curl option \"%s\": curl error (%i) [%s]", option, ret, ncc_curl_strerror(handle, ret));
	return -1;
}

/**
 * Callback to receive debugging data from libcurl
 *
 * (cf. rest_debug_log from FreeRADIUS "rest.c")
 */
static int ncc_curl_debug_log(UNUSED CURL *candle, curl_infotype type, char *data, size_t len, void *uctx)
{
	char const *p = data, *q, *end = p + len;
	char const *verb;

	switch (type) {
	case CURLINFO_TEXT:
		/*
		 * Curl debug output has trailing newlines, and could conceivably
		 * span multiple lines. Take care of both cases.
		 */
		while (p < end) {
			q = memchr(p, '\n', end - p);
			if (!q) q = end;

			DEBUG3("curl - %pV", fr_box_strvalue_len(p, q ? q - p : p - end));
			p = q + 1;
		}
		break;

	case CURLINFO_HEADER_IN:
		verb = "received";
	print_header:
		while (p < end) {
			q = memchr(p, '\n', end - p);
			q = q ? q + 1 : end;

			DEBUG3("curl - %s header: %pV", verb, fr_box_strvalue_len(p, STR_LEN_TRIM_EOL(p)));

			p = q;
		}
		break;

	case CURLINFO_HEADER_OUT:
		verb = "sending";
		goto print_header;

	case CURLINFO_DATA_IN:
		DEBUG3("curl - received data (len %zu): %pV", len, fr_box_strvalue_len(data, len));
		break;

	case CURLINFO_DATA_OUT:
		DEBUG3("curl - sending data (len %zu): %pV", len, fr_box_strvalue_len(data, len));
		break;

	default:
		DEBUG4("curl - debug data (len %zu): %pV", len, fr_box_strvalue_len(data, len));
		break;
	}

	return 0;
}

/**
 * Configure curl options for a request.
 *
 * (cf. rest_request_config from FreeRADIUS "rest.c")
 */
int ncc_curl_request_config(ncc_curl_mod_t const *inst, ncc_curl_mod_section_t const *section, void *handle,
                            http_method_t method, http_body_type_t type, char const *uri)
{
	ncc_curl_handle_t *randle = handle;
	ncc_curl_context_t *ctx = randle->ctx;
	CURL *candle = randle->candle;

	http_auth_type_t auth = section->auth;

	CURLcode ret = CURLE_OK;
	char const *option = "unknown";
	char const *content_type;

	char buffer[512];

	ncc_assert(candle);

	buffer[(sizeof(buffer) - 1)] = '\0';

	/*
	 * Set the debugging function if needed.
	 */
	if (inst->curl_debug) {
		SET_OPTION(CURLOPT_DEBUGFUNCTION, ncc_curl_debug_log);
		//SET_OPTION(CURLOPT_DEBUGDATA, request);
		SET_OPTION(CURLOPT_VERBOSE, 1L);
	}

	/*
	 * Setup any header options and generic headers.
	 */
	SET_OPTION(CURLOPT_URL, uri);
	SET_OPTION(CURLOPT_NOSIGNAL, 1);
	SET_OPTION(CURLOPT_USERAGENT, "FreeRADIUS " RADIUSD_VERSION_STRING);

	/*
	 * HTTP/1.1 doesn't require a content type, so only set it
	 * if we were provided with one explicitly.
	 */
	if (type != REST_HTTP_BODY_NONE) {
		content_type = fr_table_str_by_value(http_content_type_table, type, section->body_str);

		DEBUG3("Configuring request body type: %u, content type: %s", type, content_type);

		snprintf(buffer, sizeof(buffer), "Content-Type: %s", content_type);
		ctx->headers = curl_slist_append(ctx->headers, buffer);
		if (!ctx->headers) {
		error_header:
			fr_strerror_printf("Failed to append curl headers");
			return -1;
		}
	}

	DEBUG3("Connect timeout is %pVs, request timeout is %pVs",
	       fr_box_time_delta(inst->connect_timeout), fr_box_time_delta(section->timeout));

	SET_OPTION(CURLOPT_CONNECTTIMEOUT_MS, fr_time_delta_to_msec(inst->connect_timeout));
	SET_OPTION(CURLOPT_TIMEOUT_MS, fr_time_delta_to_msec(section->timeout));

#ifdef CURLOPT_PROTOCOLS
	SET_OPTION(CURLOPT_PROTOCOLS, (CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif

	// TODO: custom/configurable headers ?

	/*
	 * Configure HTTP verb (GET, POST, PUT, PATCH, DELETE, other...)
	 * This should be 'POST'.
	 */
	switch (method) {
	case REST_HTTP_METHOD_GET:
		SET_OPTION(CURLOPT_HTTPGET, 1L);
		break;

	case REST_HTTP_METHOD_POST:
		SET_OPTION(CURLOPT_POST, 1L);
		break;

	case REST_HTTP_METHOD_PUT:
		/*
		 *	Do not set CURLOPT_PUT, this will cause libcurl
		 *	to ignore CURLOPT_POSTFIELDs and attempt to read
		 *	whatever was set with CURLOPT_READDATA, which by
		 *	default is stdin.
		 *
		 *	This is many cases will cause the server to block,
		 *	indefinitely.
		 */
		SET_OPTION(CURLOPT_CUSTOMREQUEST, "PUT");
		break;

	case REST_HTTP_METHOD_PATCH:
		SET_OPTION(CURLOPT_CUSTOMREQUEST, "PATCH");
		break;

	case REST_HTTP_METHOD_DELETE:
		SET_OPTION(CURLOPT_CUSTOMREQUEST, "DELETE");
		break;

	case REST_HTTP_METHOD_CUSTOM:
		SET_OPTION(CURLOPT_CUSTOMREQUEST, section->method_str);
		break;

	default:
		ncc_void_assert(0);
		break;
	};

	/*
	 * Set user based authentication parameters.
	 */
	if (auth > REST_HTTP_AUTH_NONE) {
		#define SET_AUTH_OPTION SET_OPTION

		DEBUG3("Configuring HTTP auth type %s",
			fr_table_str_by_value(http_auth_table, auth, "<INVALID>"));

		if ((auth >= REST_HTTP_AUTH_BASIC) &&
		    (auth <= REST_HTTP_AUTH_ANY_SAFE)) {
			SET_AUTH_OPTION(CURLOPT_HTTPAUTH, http_curl_auth[auth]);
			SET_AUTH_OPTION(CURLOPT_USERNAME, section->username);
			SET_AUTH_OPTION(CURLOPT_PASSWORD, section->password);
		}
		else if (auth == REST_HTTP_AUTH_BEARER) {
			SET_AUTH_OPTION(CURLOPT_HTTPAUTH, http_curl_auth[auth]);

#ifdef LIBCURL_OPT_XOAUTH2_BEARER
			/*
			 * Use Curl option XOAUTH2_BEARER if available (added in 7.33.0).
			 * (Note: will fail if we're linked to an older libcurl...)
			 */
			SET_AUTH_OPTION(CURLOPT_XOAUTH2_BEARER, section->bearer_token);
#else
			/* Otherwise just do it ourselves. */
			snprintf(buffer, sizeof(buffer), "Authorization: Bearer %s", section->bearer_token);
			ctx->headers = curl_slist_append(ctx->headers, buffer);
			if (!ctx->headers) goto error_header;
#endif
		}

	}

	/*
	 * Set SSL/TLS authentication parameters
	 */
	if (section->tls_ca_file) SET_OPTION(CURLOPT_ISSUERCERT, section->tls_ca_file);
	if (section->tls_ca_info_file) SET_OPTION(CURLOPT_CAINFO, section->tls_ca_info_file);
	if (section->tls_ca_path) SET_OPTION(CURLOPT_CAPATH, section->tls_ca_path);

	SET_OPTION(CURLOPT_SSL_VERIFYPEER, (section->tls_check_cert == true) ? 1L : 0L);
	SET_OPTION(CURLOPT_SSL_VERIFYHOST, (section->tls_check_cert_cn == true) ? 2L : 0L);
	if (section->tls_extract_cert_attrs) SET_OPTION(CURLOPT_CERTINFO, 1L);

	// we don't handle more authentication (for now).

	/*
	 * Tell CURL how to get HTTP body content, and how to process incoming data.
	 */
	ncc_curl_response_init(section, &ctx->response, type);

	SET_OPTION(CURLOPT_HEADERFUNCTION, ncc_curl_response_header);
	SET_OPTION(CURLOPT_HEADERDATA, &ctx->response);
	SET_OPTION(CURLOPT_WRITEFUNCTION, ncc_curl_response_body);
	SET_OPTION(CURLOPT_WRITEDATA, &ctx->response);

	/*
	 * Setup encoder specific options.
	 */
	switch (type) {
	case REST_HTTP_BODY_NONE:
		if (ncc_curl_request_config_body(inst, section, handle, NULL) < 0) return -1;

		break;

	case REST_HTTP_BODY_CUSTOM_LITERAL:
	{
		ncc_curl_custom_data_t *data;

		MEM(data = talloc_zero(randle, ncc_curl_custom_data_t));
		data->start = ctx->request.data;
		data->p = data->start;
		data->len = strlen(data->start);

		/* Use the encoder specific pointer to store the data we need to encode */
		ctx->request.encoder = data;
		if (ncc_curl_request_config_body(inst, section, handle, ncc_curl_encode_custom) < 0) {
			TALLOC_FREE(ctx->request.encoder);
			return -1;
		}
	}
		break;

#if 0
	case REST_HTTP_BODY_POST:
	// we don't really need this, just use custom.
	{
		/* Handle POST body */
		ncc_curl_request_init(&ctx->request);

		if (ncc_curl_request_config_body(inst, section, handle, ncc_curl_encode_post) < 0) {
			return -1;
		}
	}
		break;
#endif

	// we don't handle anything else.
	default:
		ncc_void_assert(0);
	}

//finish:
	SET_OPTION(CURLOPT_HTTPHEADER, ctx->headers);

	return 0;

error:
	fr_strerror_printf("Failed to set curl option \"%s\": curl error (%i) [%s]", option, ret, ncc_curl_strerror(randle, ret));
	return -1;
}

/**
 * Send the actual HTTP request to the server.
 *
 * (cf. rest_request_perform from FreeRADIUS "rest.c")
 */
int ncc_curl_request_perform(ncc_curl_mod_t const *instance, void *handle)
{
	ncc_curl_handle_t *randle = handle;
	CURL *candle = randle->candle;
	CURLcode ret;

	ret = curl_easy_perform(candle);
	if (ret != CURLE_OK) {
		fr_strerror_printf("Request failed: curl error (%i) [%s]", ret, ncc_curl_strerror(randle, ret));
		return -1;
	}

	return 0;
}

/**
 * Cleans up after a REST request.
 *
 * (cf. rest_request_cleanup from FreeRADIUS "rest.c")
 */
void ncc_curl_request_cleanup(void *handle)
{
	ncc_curl_handle_t *randle = handle;
	ncc_curl_context_t *ctx = randle->ctx;
	CURL *candle = randle->candle;

	/*
	 * Clear any previously configured options
	 */
	curl_easy_reset(candle);

	/*
	 * Free header list
	 */
	if (ctx->headers != NULL) {
		curl_slist_free_all(ctx->headers);
		ctx->headers = NULL;
	}

	/*
	 * Free response data
	 */
	TALLOC_FREE(ctx->body);
	TALLOC_FREE(ctx->request.encoder);
	TALLOC_FREE(ctx->response.decoder);

	// don't do these here (allow retrieval after execution):
	//TALLOC_FREE(ctx->response.buffer);
	//TALLOC_FREE(ctx->response.error);
}



////////////////////////////////////////////////////////////////////////////////

/**
 * Configure curl options, perform the request, handle response and error if relevant.
 *
 * (cf. rlm_rest_perform from FreeRADIUS "rlm_rest.c")
 */
static int ncc_curl_perform(ncc_curl_mod_t const *inst, ncc_curl_mod_section_t const *section, void *handle)
{
	int ret;
	int hcode;
	int rcode = 0;

	fr_strerror(); /* Clear the error buffer */

	char const *uri = section->uri;
	if (!uri || uri[0] == '\0') {
		fr_strerror_printf("No request URI specified");
		return -1;
	}

	DEBUG3("Sending HTTP %s to \"%s\"",
	       fr_table_str_by_value(http_method_table, section->method, section->method_str), uri);

	/*
	 * Configure curl options.
	 */
	ret = ncc_curl_request_config(inst, section, handle, section->method, section->body, uri);
	if (ret < 0) return -1;

	/*
	 * Send the curl request.
	 */
	ret = ncc_curl_request_perform(inst, handle);
	if (ret < 0) return -1;

	if (section->tls_extract_cert_attrs) ncc_curl_response_certinfo(inst, section, handle);

	/*
	 * Check the response HTTP code.
	 */
	hcode = NCC_CURL_HANDLE_GET_CODE(handle);

	if (hcode >= 500) { /* Server error. */
		rcode = -1;

	} else if (hcode == 204) {
		/* No Content.
		 * Which is what we are supposed to get when writing a measurement.
		 */
		rcode = 0;

	} else if ((hcode >= 200) && (hcode < 300)) {
		/* This means there is data that we could process.
		 */
		rcode = 0;

	} else {
		rcode = -1;
	}

	ncc_curl_response_debug(handle);

	if (rcode != 0) {
		ncc_curl_response_error(handle);
	}
	ncc_curl_request_cleanup(handle);

	return rcode;
}

/**
 * Perform module curl request with custom data.
 */
int ncc_curl_mod_perform_custom(void *instance, char const *data)
{
	ncc_curl_mod_t *inst = instance;
	ncc_curl_mod_section_t const *section = &inst->custom;
	int ret;

	/* Get our connection handle from instance (no pool). */
	void *randle = inst->randle;
	if (!randle) return -1;

	ncc_curl_handle_set_request_data(randle, data);

	ret = ncc_curl_perform(instance, section, randle);
	if (ret < 0) return -1;

	return 0;
}

/**
 * Initialize libcurl.
 *
 * (cf. mod_load from FreeRADIUS "rlm_rest.c")
 */
int ncc_curl_load()
{
	CURLcode ret;
	curl_version_info_data *curlversion;

	ret = curl_global_init(CURL_GLOBAL_ALL);
	if (ret != CURLE_OK) {
		ERROR("curl: Global initialization failed: %i - %s", ret, curl_easy_strerror(ret));
		return -1;
	}

	curlversion = curl_version_info(CURLVERSION_NOW);
	if (strcmp(LIBCURL_VERSION, curlversion->version) != 0) {
		WARN("libcurl - version changed since the program was built");
		WARN("libcurl - linked: %s built: %s", curlversion->version, LIBCURL_VERSION);
	}

	INFO("libcurl version: %s", curl_version());

	return 0;
}

/**
 * Clean-up libcurl.
 *
 * (cf. mod_unload from FreeRADIUS "rlm_rest.c")
 */
void ncc_curl_unload(void)
{
	curl_global_cleanup();
}


/*
 * TLS configuration
 */
static CONF_PARSER tls_conf_parser[] = {
	{ FR_CONF_OFFSET("ca_file", FR_TYPE_FILE_INPUT, ncc_curl_mod_section_t, tls_ca_file) },
	{ FR_CONF_OFFSET("ca_info_file", FR_TYPE_FILE_INPUT, ncc_curl_mod_section_t, tls_ca_info_file) },
	{ FR_CONF_OFFSET("ca_path", FR_TYPE_FILE_INPUT, ncc_curl_mod_section_t, tls_ca_path) },
	{ FR_CONF_OFFSET("check_cert", FR_TYPE_BOOL, ncc_curl_mod_section_t, tls_check_cert), .dflt = "no" },
	{ FR_CONF_OFFSET("check_cert_cn", FR_TYPE_BOOL, ncc_curl_mod_section_t, tls_check_cert_cn), .dflt = "no" },
	{ FR_CONF_OFFSET("extract_cert_attrs", FR_TYPE_BOOL, ncc_curl_mod_section_t, tls_extract_cert_attrs), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER ncc_curl_section_conf_parser[] = {
	{ FR_CONF_OFFSET("method", FR_TYPE_STRING, ncc_curl_mod_section_t, method_str), .dflt = "POST" },
	{ FR_CONF_OFFSET("body", FR_TYPE_STRING, ncc_curl_mod_section_t, body_str), .dflt = "plain" },

	{ FR_CONF_OFFSET("uri", FR_TYPE_STRING | FR_TYPE_XLAT, ncc_curl_mod_section_t, uri), .dflt = "" },
	{ FR_CONF_OFFSET("timeout", FR_TYPE_TIME_DELTA, ncc_curl_mod_section_t, timeout), .dflt = "1.0" },

	{ FR_CONF_OFFSET("username", FR_TYPE_STRING | FR_TYPE_XLAT, ncc_curl_mod_section_t, username) },
	{ FR_CONF_OFFSET("password", FR_TYPE_STRING | FR_TYPE_SECRET | FR_TYPE_XLAT, ncc_curl_mod_section_t, password) },
	{ FR_CONF_OFFSET("bearer_token", FR_TYPE_STRING | FR_TYPE_XLAT, ncc_curl_mod_section_t, bearer_token) },

	{ FR_CONF_OFFSET("error_from_header", FR_TYPE_STRING, ncc_curl_mod_section_t, error_from_header) },

	{ FR_CONF_POINTER("tls", FR_TYPE_SUBSECTION, NULL), .subcs = (void const *) tls_conf_parser },

	CONF_PARSER_TERMINATOR
};

static const CONF_PARSER ncc_curl_conf_parser[] = {
	{ FR_CONF_OFFSET("connect_uri", FR_TYPE_STRING | FR_TYPE_XLAT, ncc_curl_mod_t, connect_uri), .dflt = "" },
	{ FR_CONF_OFFSET("connect_timeout", FR_TYPE_TIME_DELTA, ncc_curl_mod_t, connect_timeout), .dflt = "1.0" },

	{ FR_CONF_OFFSET("curl_debug", FR_TYPE_BOOL, ncc_curl_mod_t, curl_debug), .dflt = "no" },

	CONF_PARSER_TERMINATOR
};

/**
 * Parse a given curl sub-section configuration.
 */
static int ncc_curl_sub_section_parse(TALLOC_CTX *ctx, CONF_SECTION *parent,
                                      CONF_PARSER const *config_items, ncc_curl_mod_section_t *config, char const *name)
{
	CONF_SECTION *cs = NULL;

	cs = cf_section_find(parent, name, CF_IDENT_ANY);
	if (!cs) {
		/* Not configured. */
		return 0;
	}

	if (cf_section_rules_push(cs, config_items) < 0) goto error;
	if (cf_section_parse(ctx, config, cs) < 0) goto error;

	/*
	 * Add section name.
	 */
	config->name = name;

	/*
	 * Sanity check
	 */
	if ((config->username && !config->password) || (!config->username && config->password)) {
		cf_log_err(cs, "'username' and 'password' must both be set or both be absent");
		goto error;
	}

	/*
	 * Enable Authentication method.
	 */
	if (config->bearer_token) {
		config->auth = REST_HTTP_AUTH_BEARER;
	} else if (config->username && config->password) {
		config->auth = REST_HTTP_AUTH_BASIC;
	}

	/* 'method': should be "POST". */
	config->method = fr_table_value_by_str(http_method_table, config->method_str, REST_HTTP_METHOD_CUSTOM);

	/* We only handle custom body, whose data will be provided by our client.
	 * 'body' should be "plain".
	 */
	{
		http_body_type_t body;

		config->body = REST_HTTP_BODY_CUSTOM_LITERAL;

		body = fr_table_value_by_str(http_body_type_table, config->body_str, REST_HTTP_BODY_UNKNOWN);

		if (body != REST_HTTP_BODY_UNKNOWN) {
			config->body_str = fr_table_str_by_value(http_content_type_table, body, config->body_str);
		}
	}

	return 0;

error:
	return -1;
}

/**
 * Parse curl configuration section.
 */
int ncc_curl_section_parse(TALLOC_CTX *ctx, CONF_SECTION *parent, ncc_curl_mod_t *config, char const *name)
{
	CONF_SECTION *cs = NULL;
	int ret;

	cs = cf_section_find(parent, name, CF_IDENT_ANY);
	if (!cs) {
		/* Not configured. */
		return 0;
	}

	/* Parse this.
	 */
	if (cf_section_rules_push(cs, ncc_curl_conf_parser) < 0) goto error;
	if (cf_section_parse(ctx, config, cs) < 0) goto error;

	/* Parse sub-section custom configuration.
	 */
	ret = ncc_curl_sub_section_parse(ctx, cs, ncc_curl_section_conf_parser, &config->custom, "custom");
	if (ret == 0) {
		/*
		 * Maybe all is in the same section ?
		 */
		ret = ncc_curl_sub_section_parse(ctx, parent, ncc_curl_section_conf_parser, &config->custom, name);
	}

	return ret;

error:
	return -1;
}

/**
 * Debug curl configuration.
 */
void ncc_curl_config_debug(ncc_curl_mod_t *config, char const *name, int depth)
{
	ncc_section_debug_start(depth, name, NULL);
	ncc_parser_config_debug(ncc_curl_conf_parser, config, depth + 1, check_config ? name : NULL);
	ncc_parser_config_debug(ncc_curl_section_conf_parser, &config->custom, depth + 1, check_config ? name : NULL);
	ncc_section_debug_end(depth);
}

#endif // HAVE_LIBCURL
