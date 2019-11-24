#pragma once
/*
 * dpc_time_data.h
 */

#include <pthread.h>
#include <semaphore.h>


typedef enum {
	TIMEDATA_DST_NULL = 0, //!< Discard.
	TIMEDATA_DST_STDOUT,   //!< Write to stdout.
	TIMEDATA_DST_FILE,     //!< Write to a file on disk.
	TIMEDATA_DST_INFLUX,   //!< Send to InfluxDB.

	TIMEDATA_DST_NUM_DEST
} dpc_timedata_dst_t;

/*
 *	Time-data configuration
 */
typedef struct {
	dpc_timedata_dst_t dst;        //<! Type of destination where data points are sent.
	char const *destination;       //<! Type of destination (string).

	fr_time_delta_t time_interval; //<! Timespan of a data point (default: 1 s).
	uint32_t max_history;          //<! Limit entries stored in the time-data lists.

	char const *instance;

} dpc_timedata_config_t;

/*
 *	Time-data point
 */
typedef struct dpc_timedata_stat_t {
	/* Generic chaining */
	fr_dlist_t dlist;          //!< Our entry into the linked list.

	/* Specific item data
	 */
	fr_time_t start;           //<! When element was initialized.
	fr_time_t end;             //<! When element stopped being used.

	struct timeval timestamp;  //<! Timestamp (UTC time) for this data point.
	bool sent;                 //<! Has this data point been sent?

	void *data;                //<! Measurement specific data.

} dpc_timedata_stat_t;



int dpc_timedata_config_load(dpc_config_t *config);
int dpc_timedata_init(TALLOC_CTX *ctx);
int dpc_timedata_start(void);
void dpc_timedata_stop(void);

void dpc_packet_stat_add(dpc_packet_stat_field_t stat_type, uint32_t packet_type);
int dpc_packet_stat_send(bool ending);
int dpc_process_exec_send(bool ending);

#ifdef HAVE_LIBCURL
int dpc_influx_connection_get(TALLOC_CTX *ctx);
#endif
