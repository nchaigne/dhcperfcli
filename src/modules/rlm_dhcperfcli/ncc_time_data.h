#pragma once
/*
 * ncc_time_data.h
 */

#include <pthread.h>
#include <semaphore.h>



typedef enum {
	TIMEDATA_DST_NULL = 0, //!< Discard.
	TIMEDATA_DST_STDOUT,   //!< Write to stdout.
	TIMEDATA_DST_FILE,     //!< Write to a file on disk.
	TIMEDATA_DST_INFLUX,   //!< Send to InfluxDB.

	TIMEDATA_DST_NUM_DEST
} ncc_timedata_dst_t;

/*
 *	Time-data configuration
 */
typedef struct {
	ncc_timedata_dst_t dst;        //<! Type of destination where data points are sent.
	char const *destination;       //<! Type of destination (string).

	fr_time_delta_t time_interval; //<! Timespan of a data point (default: 1 s).
	uint32_t max_history;          //<! Limit entries stored in the time-data lists.

	char const *instance;
	char const *instance_esc;      //<! Escaped instance which can safely be used for writing to Influx.

} ncc_timedata_config_t;

/*
 *	Time-data point
 */
typedef struct ncc_timedata_stat_t {
	/* Generic chaining */
	fr_dlist_t dlist;          //!< Our entry into the linked list.

	/* Specific item data
	 */
	fr_time_t start;           //<! When element was initialized.
	fr_time_t end;             //<! When element stopped being used.

	struct timeval timestamp;  //<! Timestamp (UTC time) for this data point.
	bool sent;                 //<! Has this data point been sent?

	void *data;                //<! Measurement specific data.

} ncc_timedata_stat_t;

/*
 * Function prototype for time-data sending functions.
 */
typedef int (*ncc_timedata_stat_send)(ncc_timedata_stat_t *stat);

/*
 *	Time-data context
 */
typedef struct ncc_timedata_context_t {
	char const *name;

	ncc_timedata_stat_t *stat_cur;   //<! Current time-data point.
	ncc_dlist_t *dlist;              //<! List of past time-data points.
	pthread_mutex_t mutex;           //<! Mutex for accessing the list.
	/*
	 * Items are only inserted to the head, so we need to lock when: getting the head, adding an item, and removing items.
	 * Iterating (without addition or removal) does not require locking once the head has been obtained.
	 */

	ncc_timedata_stat_send send_func;

} ncc_timedata_context_t;


#define NCC_INFLUX_ESCAPE_KEY(_out, _outlen, _in) ncc_influx_data_escape(_out, _outlen, _in, ",= ")
#define NCC_INFLUX_ESCAPE_STR(_out, _outlen, _in) ncc_influx_data_escape(_out, _outlen, _in, "\"")
/* A string value is enclosed within double quotes; double-quotes in the value must be escaped. */


int ncc_timedata_config_init(CONF_SECTION *cs, char const *name);
char const *ncc_timedata_get_inst_esc(void);
int ncc_timedata_write(char const *data);
ncc_timedata_context_t *ncc_timedata_context_add(TALLOC_CTX *ctx, char const *name);
ncc_timedata_stat_t *ncc_timedata_get_storage(ncc_timedata_context_t *context);
int ncc_timedata_start(void);
void ncc_timedata_stop(void);
