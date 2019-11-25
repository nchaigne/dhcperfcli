/**
 * @file dpc_time_data.c
 * @brief Handle time-data statistics.
 *
 * Periodically send aggregated time-data values to the configured destination.
 *
 * Requires libcurl for the Influx back-end.
 */

/* Our own auto-configuration header.
 * Will define HAVE_LIBCURL if libcurl is available.
 */
#include "config.h"

#include "ncc_util.h"
#include "ncc_curl.h"

#include "dhcperfcli.h"
#include "dpc_config.h"

#include "dpc_time_data.h"


static ncc_dlist_t *packet_stat_dlist;

static dpc_timedata_config_t timedata_config;
static bool with_influx;
static bool store_timedata;

static pthread_t worker_thread;
static sem_t worker_semaphore;
static bool worker_started;
static bool signal_done;

static uint32_t send_fail; /* Keep track of previous send failures so we don't spam errors. */
static uint32_t num_discard; /* Points discarded in case of destination unavailable + full history */
static uint32_t num_points; /* All time-data points handled (successfully sent or not). */

#ifdef HAVE_LIBCURL
static ncc_curl_mod_t *influx_config;
#endif


fr_table_num_sorted_t const dpc_timedata_str2dst[] = {
	{ "file",   TIMEDATA_DST_FILE },
	{ "influx", TIMEDATA_DST_INFLUX },
	{ "null",   TIMEDATA_DST_NULL },
	{ "stdout", TIMEDATA_DST_STDOUT },
};
size_t dpc_timedata_str2dst_len = NUM_ELEMENTS(dpc_timedata_str2dst);

static CONF_PARSER _timedata_config[] = {
	{ FR_CONF_OFFSET("destination", FR_TYPE_STRING, dpc_timedata_config_t, destination), .dflt = "influx" },
	{ FR_CONF_OFFSET("time_interval", FR_TYPE_TIME_DELTA, dpc_timedata_config_t, time_interval), .dflt = "1.0" },
	{ FR_CONF_OFFSET("max_history", FR_TYPE_UINT32, dpc_timedata_config_t, max_history), .dflt = "300" },

	CONF_PARSER_TERMINATOR
};


/**
 * Load configured 'influx' sub-section within 'time-data'.
 */
int dpc_timedata_config_influx(TALLOC_CTX *ctx, CONF_SECTION *cs_parent)
{
#ifndef HAVE_LIBCURL
	INFO("libcurl is not available: cannot load 'influx' configuration");
	return 0;
#else
	MEM(influx_config = talloc_zero(ctx, ncc_curl_mod_t));

	if (ncc_curl_section_parse(ctx, cs_parent, influx_config, "influx") != 0) {
		ERROR("Failed to load 'influx' sub-section from configuration file");
		return -1;
	}

	if (ncc_curl_load() < 0) return -1;

	/* Pre-establish connection to Influx (if connect_uri is set).
	 */
	if (dpc_influx_connection_get(influx_config) < 0) return -1;

	/* Write "process start" data point.
	 * This allows to check that we are authorized and that the target database exists.
	 * If this succeeds, sending actual statistics should only fail if the remote becomes unavailable.
	 */
	if (dpc_process_exec_send(false) < 0) {
		PERROR(NULL);
		return -1;
	}

	/* All good. */
	with_influx = true;

	INFO("time-data: 'influx' destination configured with libcurl support");

	/* JSON support is optional. */
#ifndef HAVE_JSON
	INFO("time-data: libjson-c is not available: JSON decoding is not supported");
#endif

	return 0;
#endif
}

/**
 * Escape data for sending to Influx.
 *
 * From the InfluxDB documentation:
 * "If a measurement, tag key, tag value, or field key contains a space, comma, or an equals sign
 *  it must be escaped using the backslash character \. Backslash characters do not need to be escaped."
 *
 * And: "Measurements, tag keys, tag values, and field keys are never quoted".
 *
 * So they say. But... a backslash at the end of a value is not supported (bug ?).
 * Anyway, trying to use backslashes in values is dumb. Don't do that.
 */
size_t dpc_influx_data_escape(char *out, size_t outlen, char const *in, char const *escape_chars)
{
	size_t freespace = outlen;

	while (*in) {
		if (strchr(escape_chars, *in) != NULL) {
			if (freespace <= 2) break;
			*out++ = '\\';
			freespace --;
		} else {
			if (freespace <= 1) break;
		}

		*out++ = *in++;
		freespace --;
	}

	*out = '\0';
	return outlen - freespace;
}

#define DPC_INFLUX_ESCAPE_KEY(_out, _outlen, _in) dpc_influx_data_escape(_out, _outlen, _in, ",= ")
#define DPC_INFLUX_ESCAPE_STR(_out, _outlen, _in) dpc_influx_data_escape(_out, _outlen, _in, "\"")
/* A string value is enclosed within double quotes; double-quotes in the value must be escaped. */


/**
 * Load configured 'time-data' section.
 */
int dpc_timedata_config_load(dpc_config_t *config)
{
	CONF_SECTION *cs = config->root_cs;
	TALLOC_CTX *ctx = cs;
	char buf[256];

	DEBUG2("%s: #### Parsing 'time-data' section ####", config->name);
	cs = cf_section_find(cs, "time-data", CF_IDENT_ANY);
	if (!cs) {
		/* Not configured. */
		return 0;
	}

	if (dpc_timedata_init(ctx) < 0) goto error;

	/* If we don't have an instance set, use program instance name.
	 */
	if (!timedata_config.instance) {
		timedata_config.instance = config->name;
	}

	/* Handle escaping so it can safely be sent to Influx. */
	DPC_INFLUX_ESCAPE_KEY(buf, sizeof(buf), timedata_config.instance);
	timedata_config.instance = talloc_strdup(ctx, buf);

	/* Parse 'time-data' section.
	*/
	if (cf_section_rules_push(cs, _timedata_config) < 0) goto error;
	if (cf_section_parse(ctx, &timedata_config, cs) < 0) goto error;

	timedata_config.dst = fr_table_value_by_str(dpc_timedata_str2dst, timedata_config.destination, TIMEDATA_DST_NUM_DEST);

	switch (timedata_config.dst) {
	case TIMEDATA_DST_NUM_DEST:
		ERROR("Unknown time-data destination: %s", timedata_config.destination);
		goto error;

	case TIMEDATA_DST_NULL:
	case TIMEDATA_DST_STDOUT:
	case TIMEDATA_DST_FILE:
		// TODO
		break;

	case TIMEDATA_DST_INFLUX:
		if (dpc_timedata_config_influx(cs, cs) < 0) goto error;
		break;

	default:
		break;
	}

	/* If time-data storage is initialized, start the worker thread.
	 */
	if (store_timedata) {
		if (dpc_timedata_start() < 0) return -1;
		config->with_timedata = true;
	}

	return 0;

error:
	return -1;
}

#ifdef HAVE_LIBCURL
/**
 * Get a curl connection handle. If we don't have one yet, initialize one.
 * Note: libcurl will automatically reconnect if necessary. We don't have to handle reconnection.
 */
int dpc_influx_connection_get(TALLOC_CTX *ctx)
{
	ncc_curl_mod_t *my_influx = influx_config;

	ncc_curl_handle_t *randle = my_influx->randle;
	if (!randle) {
		randle = ncc_curl_conn_create(ctx, my_influx);
		if (!randle) {
			PERROR("Failed to open connection to InfluxDB");
			return -1;
		}
		my_influx->randle = randle;
	}

	/* Check connection status. */
	bool alive = ncc_curl_conn_alive(my_influx, randle);
	DEBUG3("curl: Connection alive ? %s", alive ? "yes" : "no");

	return 0;
}

/**
 * Write time-data to Influx.
 */
int dpc_influx_write(char const *data)
{
	ncc_curl_mod_t *my_influx = influx_config;

	if (dpc_influx_connection_get(my_influx) < 0) return -1;

	if (ncc_curl_mod_perform_custom(my_influx, data) < 0) {
		fr_strerror_printf_push("Failed to write to InfluxDB");
		return -1;
	}

	return 0;
}
#endif

/**
 * Write time-data to configured destination.
 */
int dpc_timedata_write(char const *data)
{
	int ret = 0;

	switch (timedata_config.dst) {
	case TIMEDATA_DST_NULL:
		break;

	case TIMEDATA_DST_STDOUT:
	case TIMEDATA_DST_FILE:
		// TODO
		break;

#ifdef HAVE_LIBCURL
	case TIMEDATA_DST_INFLUX:
		ret = dpc_influx_write(data);
		break;
#endif

	default:
		break;
	}

	return ret;
}

/**
 * Initialize time-data storage.
 */
int dpc_timedata_init(TALLOC_CTX *ctx)
{
	packet_stat_dlist = talloc_zero(ctx, ncc_dlist_t);
	NCC_DLIST_INIT(packet_stat_dlist, dpc_timedata_stat_t);

	store_timedata = true;
	return 0;
}

/**
 * Clean-up a list of time-data.
 * Remove items that have been sent successfully.
 * If items cannot be sent (because destination is unavailable), only keep a limited history as configured.
 */
void dpc_timedata_list_cleanup(ncc_dlist_t *dlist, bool force)
{
	/* Remove entries that have been sent successfully.
	 * We don't need them anymore.
	 */
	dpc_timedata_stat_t *stat, *prev = NULL;
	stat = NCC_DLIST_HEAD(dlist);
	while (stat) {
		prev = stat;
		if (stat->sent) {
			NCC_DLIST_REMOVE_ITER(packet_stat_dlist, stat, prev);
			talloc_free(stat); /* Safe because we continue iteration from previous. */
		}
		stat = NCC_DLIST_NEXT(packet_stat_dlist, prev);
	}

	/* Only keep a max number of entries.
	 * (Or force remove all when stopping.)
	 */
	if ( (timedata_config.max_history && NCC_DLIST_SIZE(dlist) > timedata_config.max_history)
	    || force) {
		stat = NCC_DLIST_HEAD(dlist);

		if (!force) {
			/* Skip the first "max_history" entries, which we keep.
			 */
			uint32_t skip = timedata_config.max_history;
			while (stat && skip) {
				skip--;
				stat = NCC_DLIST_NEXT(packet_stat_dlist, stat);
			}
		}

		/* Then remove everything after that. */
		while (stat) {
			prev = stat;
			num_discard++;
			NCC_DLIST_REMOVE_ITER(packet_stat_dlist, stat, prev);
			talloc_free(stat);
			stat = NCC_DLIST_NEXT(packet_stat_dlist, prev);
		}
	}
}

void dpc_packet_stat_add(dpc_packet_stat_field_t stat_type, uint32_t packet_type)
{
	if (!store_timedata) return;

	bool work = false;
	fr_time_t now = fr_time();
	fr_time_t fte_start = now; /* Start of new item, if applicable. */

	dpc_timedata_stat_t *stat = NCC_DLIST_HEAD(packet_stat_dlist);
	if (stat) {
		if (now >= stat->start + timedata_config.time_interval) {
			/*
			 * Stop using this. Prepare a new item.
			 */
			stat->end = now;
			work = true;

			/* Have new data point start at "previous" start + interval, to avoid drifting. */
			fte_start = stat->start + timedata_config.time_interval;
			stat = NULL;
		}
	}

	if (!stat) {
		num_points++;
		NCC_DLIST_ALLOC_ITEM(packet_stat_dlist, stat, dpc_timedata_stat_t);
		stat->data = talloc_zero_array(stat, dpc_packet_stat_t, DHCP_MAX_MESSAGE_TYPE + 1);

		stat->start = fte_start;
		gettimeofday(&stat->timestamp, NULL);

		/* Push new item to list head. */
		NCC_DLIST_PUSH(packet_stat_dlist, stat);
	}

	/* Signal worker if there's work to be done. */
	if (work) {
		sem_post(&worker_semaphore);
	}

	PACKET_STAT_NUM_INCR(stat->data, stat_type, packet_type);
}

/**
 * Check if items in the packet stat list are ready to be sent to their destination.
 * If so, prepare and send the data point, and mark item as "sent".
 */
int dpc_packet_stat_send(bool force)
{
	fr_time_t now = fr_time();

	dpc_timedata_stat_t *stat = NCC_DLIST_HEAD(packet_stat_dlist);
	while (stat) {
		if (stat->sent) {
			/* Already sent.
			 * This entails that older items also have been. We can stop here.
			 */
			break;
		}

		if (!stat->end && force) stat->end = now;

		if (stat->end) {
			/*
			 * Item is ready to send. Do that now.
			 */
			char influx_data[1024];
			int i;

			for (i = 1; i < DHCP_MAX_MESSAGE_TYPE; i ++) {
				/* Don't write if we have nothing for this type of packet.
				 */
				if (PACKET_STAT_GET(stat->data, recv, i) == 0 && PACKET_STAT_GET(stat->data, sent, i) == 0
					&& PACKET_STAT_GET(stat->data, retr, i) == 0 && PACKET_STAT_GET(stat->data, lost, i) == 0) {
					continue;
				}

				snprintf(influx_data, sizeof(influx_data), "packet,instance=%s,type=%s recv=%ui,sent=%ui,retr=%ui,lost=%ui %lu%06lu000",
					timedata_config.instance,
					dpc_message_types[i],
					PACKET_STAT_GET(stat->data, recv, i),
					PACKET_STAT_GET(stat->data, sent, i),
					PACKET_STAT_GET(stat->data, retr, i),
					PACKET_STAT_GET(stat->data, lost, i),
					stat->timestamp.tv_sec, stat->timestamp.tv_usec);

				/* Note: an annoying bug in Influx < 1.7.8: https://github.com/influxdata/influxdb/issues/10052
				 * If fields are created with a given type (e.g. the default "float"),
				 * then they cannot be re-created later with another type ("integer") even if the measurement is dropped.
				 * The database has to be dropped (or manually remove "fields.idx" files).
				 */

				if (dpc_timedata_write(influx_data) < 0) {
					return -1;
				}
				stat->sent = true;
			}
		}

		stat = NCC_DLIST_NEXT(packet_stat_dlist, stat);
	}

	return 0;
}

/**
 * Send data point of the process execution (start or stop).
 */
int dpc_process_exec_send(bool ending)
{
	char influx_data[1024];

	struct timeval tv;
	gettimeofday(&tv, NULL);

	size_t len, freespace = sizeof(influx_data);
	char *p = influx_data;

	len = snprintf(p, freespace, "process");
	p += len; freespace -= len;

	if (timedata_config.instance) {
		len = snprintf(p, freespace, ",instance=%s ", timedata_config.instance);
		p += len; freespace -= len;
	}

	len = snprintf(p, freespace, " type=\"%s\" %lu%06lu000", ending ? "stop" : "start", tv.tv_sec, tv.tv_usec);

	if (dpc_timedata_write(influx_data) < 0) {
		return -1;
	}

	return 0;
}

/**
 * Time-data handler loop - worker thread.
 */
void *dpc_timedata_handler(UNUSED void *input_ctx)
{
	int ret;
	while (!signal_done) {

		ret = dpc_packet_stat_send(false);
		if (ret == 0) {
			/* Sending successful.
			 */
			if (send_fail) {
				INFO("Time-data destination is now available again");
				send_fail = 0;
			}
		} else {
			/* Failed sending. Will retry later.
			 */

			/* Only log when the problem first appears. */
			// e.g. "Failed to write to InfluxDB: Request failed: curl error (7) [Couldn't connect to server]"
			if (!send_fail) PERROR(NULL);
			send_fail++;
		}

		dpc_timedata_list_cleanup(packet_stat_dlist, false);

		/* Wait until signaled to wake up,
		 * or timeout expires, in which case we can retry sending if in failed mode.
		 */
		//sem_wait(&worker_semaphore);

		/* sem_timedwait wants a timespec absolute time since the Epoch...
		 * This is not a proper way to handle a timeout, but it's good enough for what we need.
		 */
		struct timespec timeout;
		struct timeval tv;
		gettimeofday(&tv, NULL);
		tv.tv_sec += 1;
		TIMEVAL_TO_TIMESPEC(&tv, &timeout);

		sem_timedwait(&worker_semaphore, &timeout);
	}

	/* Process last entry. */
	ret = dpc_packet_stat_send(true);
	if (ret != 0) {
		PERROR(NULL);
	}

	/* Final clean-up. */
	dpc_timedata_list_cleanup(packet_stat_dlist, true);

	return NULL;
}

/**
 * Create time-data worker thread.
 */
int dpc_timedata_pthread_create(pthread_t *thread, void *(*func)(void *), void *arg)
{
	pthread_attr_t attr;
	int ret;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	ret = pthread_create(thread, &attr, func, arg);
	if (ret != 0) {
		fr_strerror_printf("Failed creating thread: %s", fr_syserror(ret));
		return -1;
	}

	return 0;
}

/**
 * Start the worker thread for periodically sending data point measurements.
 */
int dpc_timedata_start()
{
	DEBUG("Starting time-data handler");

	if (sem_init(&worker_semaphore, 0, 0) != 0) {
		ERROR("Failed creating semaphore: %s", fr_syserror(errno));
		return -1;
	}

	if (dpc_timedata_pthread_create(&worker_thread, dpc_timedata_handler, NULL) < 0) {
		PERROR(NULL);
		return -1;
	}

	worker_started = true;
	return 0;
}

/**
 * Stop time-data handler.
 */
void dpc_timedata_stop()
{
	if (!store_timedata) return;

	if (worker_started) {
		/* Signal the worker.
		 */
		DEBUG("Signaling time-data handler to stop");

		signal_done = true;
		sem_post(&worker_semaphore);

		/* Wait for worker to terminate. */
		(void) pthread_join(worker_thread, NULL);
		worker_started = false;
	}

	/* Write "process stop" data point. */
	if (dpc_process_exec_send(true) < 0) {
		PERROR(NULL);
	}

	if (num_discard) {
		WARN("Time-data: discarded %u data point(s) (of %u) due to destination unavailability",
		     num_discard, num_points);
	}
}
