#pragma once
/*
 * ncc_curl.h
 */

#ifdef HAVE_LIBCURL
#include <curl/curl.h>


/* Replace the first EOL character (\r or \n) in buffer with '\0'.
 */
#define STR_TRIM_EOL(_buf) \
	if (_buf) { \
		_buf[strcspn(_buf, "\r\n")] = '\0'; \
	}

/* Get number of characters in string before EOL (\r or \n). Works if no EOL.
 */
#define STR_LEN_TRIM_EOL(_buf) (strcspn(_buf, "\r\n"))


/* (verbatim copy from FreeRADIUS "rest.h")
 */

/*
 *	The common JSON library (also tells us if we have json-c)
 */
#include <freeradius-devel/json/base.h>
#define REST_URI_MAX_LEN		2048
#define REST_BODY_MAX_LEN		8192
#define REST_BODY_ALLOC_CHUNK		1024
#define REST_BODY_MAX_ATTRS		256

typedef enum {
	REST_HTTP_METHOD_UNKNOWN = 0,
	REST_HTTP_METHOD_GET,
	REST_HTTP_METHOD_POST,
	REST_HTTP_METHOD_PUT,
	REST_HTTP_METHOD_PATCH,
	REST_HTTP_METHOD_DELETE,
	REST_HTTP_METHOD_CUSTOM		//!< Must always come last, should not be in method table
} http_method_t;

typedef enum {
	REST_HTTP_BODY_UNKNOWN = 0,
	REST_HTTP_BODY_UNSUPPORTED,
	REST_HTTP_BODY_UNAVAILABLE,
	REST_HTTP_BODY_INVALID,
	REST_HTTP_BODY_NONE,
	REST_HTTP_BODY_CUSTOM_XLAT,
	REST_HTTP_BODY_CUSTOM_LITERAL,
	REST_HTTP_BODY_POST,
	REST_HTTP_BODY_JSON,
	REST_HTTP_BODY_XML,
	REST_HTTP_BODY_YAML,
	REST_HTTP_BODY_HTML,
	REST_HTTP_BODY_PLAIN,
	REST_HTTP_BODY_NUM_ENTRIES
} http_body_type_t;

typedef enum {
	REST_HTTP_AUTH_UNKNOWN = 0,
	REST_HTTP_AUTH_NONE,
	REST_HTTP_AUTH_TLS_SRP,
	REST_HTTP_AUTH_BASIC,
	REST_HTTP_AUTH_DIGEST,
	REST_HTTP_AUTH_DIGEST_IE,
	REST_HTTP_AUTH_GSSNEGOTIATE,
	REST_HTTP_AUTH_NTLM,
	REST_HTTP_AUTH_NTLM_WB,
	REST_HTTP_AUTH_ANY,
	REST_HTTP_AUTH_ANY_SAFE,
	REST_HTTP_AUTH_BEARER, // -> addition to "rest.h"
	REST_HTTP_AUTH_NUM_ENTRIES
} http_auth_type_t;

extern fr_table_num_sorted_t const http_auth_table[];
extern size_t http_auth_table_len;

extern fr_table_num_sorted_t const http_method_table[];
extern size_t http_method_table_len;

extern fr_table_num_sorted_t const http_body_type_table[];
extern size_t http_body_type_table_len;

extern fr_table_num_sorted_t const http_content_type_table[];
extern size_t http_content_type_table_len;
/*
 * (END verbatim copy from FreeRADIUS "rest.h")
 */


typedef struct ncc_curl_handle_t ncc_curl_handle_t;

/*
 * Structure for section configuration.
 */
typedef struct ncc_curl_mod_section_t {
	char const *name;                //!< Section name.
	char const *uri;                 //!< URI to send HTTP request to.

	char const *method_str;          //!< The string version of the HTTP method.
	http_method_t method;            //!< What HTTP method should be used, GET, POST etc...

	char const *body_str;            //!< The string version of the encoding/content type.
	http_body_type_t body;           //!< What encoding type should be used.

	//char const *force_to_str;        //!< Force decoding with this decoder.
	//http_body_type_t force_to;       //!< Override the Content-Type header in the response
	//                                 //!< to force decoding as a particular type.

	http_auth_type_t auth;           //!< HTTP auth type.

	char const *username;            //!< Username for HTTP Authentication.
	char const *password;            //!< Password for HTTP Authentication.
	char const *bearer_token;        //<! Token for Bearer Authentication.

	char const *error_from_header;   //!< Allow to extract error message from a specific HTTP header.

	fr_time_delta_t timeout;         //!< Request timeout.

	/*
	 * TLS configuration
	 */
	char const *tls_ca_file;         //<! File containing a bundle of certificates, which allow to handle
	                                 //<! certificate chain validation (CURLOPT_CAINFO).
	char const *tls_ca_issuer_file;  //<! File containing a single CA, which is the issuer of the server
	                                 //<! certificate (CURLOPT_ISSUERCERT).
	char const *tls_ca_path;         //<! Directory holding CA certificates to verify the peer with (CURLOPT_CAPATH).

	/* Note:
	 *
	 * CURLOPT_ISSUERCERT by itself is not sufficient, even if the "issuer" is also the root CA.
	 * CURLOPT_CAINFO must also be set to a file bundle which contains the root CA (and intermediate CA if need be).
	 * Set by default (on RHEL) to "/etc/pki/tls/certs/ca-bundle.crt".
	 *
	 * CURLOPT_ISSUERCERT and CURLOPT_CAINFO can be the same file containing the root CA certificate.
	 * CURLOPT_ISSUERCERT however can be omitted, it's only useful in multi-level PKI.
	 */

	bool tls_check_cert;             //<! Verify the peer's SSL certificate (CURLOPT_SSL_VERIFYPEER).
	bool tls_check_cert_cn;          //<! Check that Common Name in server certificate matches configured URI (CURLOPT_SSL_VERIFYHOST).
	bool tls_extract_cert_attrs;

} ncc_curl_mod_section_t;

/*
 * Configuration for curl module.
 */
typedef struct ncc_curl_mod_t {

	char const *connect_uri;         //!< URI we attempt to connect to, to pre-establish TCP connections.
	fr_time_delta_t connect_timeout; //!< Connection timeout.

	bool curl_debug;                //<! To active curl verbose debug.

	ncc_curl_mod_section_t custom;  //!< Configuration section.

	/* We do not handle a connection pool, a single connection is enough. */
	ncc_curl_handle_t *randle;

} ncc_curl_mod_t;


/*
 *	States for stream based attribute encoders
 */
typedef enum {
	READ_STATE_INIT	= 0,
	READ_STATE_ATTR_BEGIN,
	READ_STATE_ATTR_CONT,
	READ_STATE_ATTR_END,
	READ_STATE_END,
} read_state_t;

/*
 *	States for the response parser
 */
typedef enum {
	WRITE_STATE_INIT = 0,
	WRITE_STATE_PARSE_HEADERS,
	WRITE_STATE_PARSE_CONTENT,
	WRITE_STATE_DISCARD,
} write_state_t;


/*
 * Outbound data context (passed to CURLOPT_READFUNCTION as CURLOPT_READDATA)
 * (cf. rlm_rest_request_t in FreeRADIUS "rest.h")
 */
typedef struct ncc_curl_request_t {
	ncc_curl_mod_t const *instance;        //!< This instance.
	ncc_curl_mod_section_t const *section; //!< Section configuration.

	read_state_t state;       //!< Encoder state.

	//size_t chunk;             //!< Chunk size.
	void *encoder;            //!< Encoder specific data.

	char const *data;         //!< Data string we want to send.
} ncc_curl_request_t;

/*
 * curl inbound data context (passed to CURLOPT_WRITEFUNCTION and
 * CURLOPT_HEADERFUNCTION as CURLOPT_WRITEDATA and CURLOPT_HEADERDATA)
 * (cf. rlm_rest_response_t in FreeRADIUS "rest.h")
 */
typedef struct ncc_curl_response_t {
	ncc_curl_mod_t const *instance;        //!< This instance.
	ncc_curl_mod_section_t const *section; //!< Section configuration.

	write_state_t state;    //!< Decoder state.

	char *buffer;           //!< Raw incoming HTTP data.
	size_t alloc;           //!< Space allocated for buffer.
	size_t used;            //!< Space used in buffer.

	int code;               //!< HTTP Status Code.
	http_body_type_t type;  //!< HTTP Content Type.

	void *decoder;          //!< Decoder specific data.

	TALLOC_CTX *talloc_ctx; //<! Provided talloc context for memory allocations.
	char *error;            //!< InfluxDB error, if any.
} ncc_curl_response_t;

/*
 * curl context data (cf. rlm_rest_curl_context_t in FreeRADIUS "rest.h")
 */
typedef struct ncc_curl_context_t {
	struct curl_slist *headers;   //!< Any HTTP headers which will be sent with the request
	char *body;                   //!< Pointer to the buffer which contains body data.

	ncc_curl_request_t request;   //!< Request context data.
	ncc_curl_response_t response; //!< Response context data.

} ncc_curl_context_t;

/*
 * Connection API handle (cf. rlm_rest_handle_t in FreeRADIUS "rest.h")
 */
typedef struct ncc_curl_handle_t {
	CURL *candle;            //!< Libcurl easy handle.
	char *error;             //<! Error buffer allocated for curl.
	ncc_curl_context_t *ctx; //!< Context.
} ncc_curl_handle_t;

/*
 * Function prototype for ncc_curl_request_config_body.
 * Matches CURL's CURLOPT_READFUNCTION prototype.
 */
typedef size_t (*curl_read_t)(void *ptr, size_t size, size_t nmemb, void *userdata);


char const *ncc_curl_strerror(ncc_curl_handle_t *randle, CURLcode curl_ret);
void *ncc_curl_conn_create(TALLOC_CTX *ctx, void *instance);
bool ncc_curl_conn_alive(void *instance, void *handle);

void ncc_curl_response_error(ncc_curl_handle_t *handle);
void ncc_curl_response_debug(ncc_curl_handle_t *handle);

int ncc_curl_request_config(ncc_curl_mod_t const *inst, ncc_curl_mod_section_t const *section, void *handle,
                            http_method_t method, http_body_type_t type, char const *uri);
int ncc_curl_request_perform(ncc_curl_mod_t const *instance, void *handle);
void ncc_curl_request_cleanup(void *handle);

void ncc_curl_handle_set_request_data(ncc_curl_handle_t *handle, char const *data);
size_t ncc_curl_handle_get_data(char const **out, ncc_curl_handle_t *handle);
char *ncc_curl_handle_get_error(ncc_curl_handle_t *handle);

#define NCC_CURL_HANDLE_GET_CODE(handle)(((ncc_curl_context_t*)((ncc_curl_handle_t*)handle)->ctx)->response.code)


/*
 * --- module exposed functions
 */
int ncc_curl_load(void);
void ncc_curl_unload(void);

int ncc_curl_mod_perform_custom(void *instance, char const *data);

int ncc_curl_section_parse(TALLOC_CTX *ctx, CONF_SECTION *parent, ncc_curl_mod_t *config, char const *name);

void ncc_curl_config_debug(ncc_curl_mod_t *config, char const *name, int depth);

#endif // HAVE_LIBCURL