/**
 * @file dpc_time_data.c
 * @brief Handle time-data statistics.
 *
 * Periodically send aggregated time-data values to the configured destination.
 *
 * Requires libcurl for the Influx back-end.
 */


#include "ncc_util.h"
#include "ncc_time_data.h"

#include "dhcperfcli.h"
#include "dpc_util.h"
#include "dpc_config.h"
#include "dpc_time_data.h"


ncc_timedata_context_t *packet_stat_context;
ncc_timedata_context_t *tr_stat_context;
ncc_timedata_context_t *session_stat_context;


/* Note: an annoying bug in Influx < 1.7.8: https://github.com/influxdata/influxdb/issues/10052
 * If fields are created with a given type (e.g. the default "float"),
 * then they cannot be re-created later with another type ("integer") even if the measurement is dropped.
 * The database has to be dropped (or manually remove "fields.idx" files).
 */


/**
 * Initialize time-data storage.
 */
static int dpc_timedata_init(TALLOC_CTX *ctx)
{
	packet_stat_context = ncc_timedata_context_add(ctx, "packet_stat");
	if (!packet_stat_context) return -1;

	packet_stat_context->send_func = dpc_timedata_send_packet_stat;

	tr_stat_context = ncc_timedata_context_add(ctx, "transaction_stat");
	if (!tr_stat_context) return -1;

	tr_stat_context->send_func = dpc_timedata_send_tr_stat;

	session_stat_context =  ncc_timedata_context_add(ctx, "session_stat");
	if (!session_stat_context) return -1;

	session_stat_context->send_func = dpc_timedata_send_session_stat;

	return 0;
}

/**
 * Load configured 'time-data' section, and initialize time-data handling.
 */
int dpc_timedata_config_load(dpc_config_t *config)
{
	CONF_SECTION *cs = config->root_cs;
	TALLOC_CTX *ctx = cs;

	DEBUG2("%s: #### Parsing 'time-data' section ####", config->name);
	cs = cf_section_find(cs, "time-data", CF_IDENT_ANY);
	if (!cs) {
		/* Not configured. */
		return 0;
	}

	/* Initialize time-data storage. */
	if (dpc_timedata_init(ctx) < 0) return -1;

	/* Parse time-data section and start the worker thread. */
	if (ncc_timedata_config_init(cs, config->name) < 0) return -1;

	config->with_timedata = true;
	return 0;
}

/**
 * Debug time-data configuration.
 */
void dpc_timedata_config_debug(dpc_config_t *config)
{
	if (!config->with_timedata) return;

	DEBUG("  time-data {");
	ncc_parser_config_debug(timedata_conf_parser, &ncc_timedata_config, 2, check_config ? "time-data" : NULL);
	DEBUG("  }");
}

/**
 * Store packet statistics into time-data.
 */
void dpc_timedata_store_packet_stat(dpc_packet_stat_field_t stat_type, uint32_t packet_type)
{
	ncc_timedata_stat_t *stat = ncc_timedata_context_get_storage(packet_stat_context);
	if (!stat) return;

	if (!stat->data) {
		/* Newly allocated item.
		 * Now allocate specific data storage.
		 */
		stat->data = talloc_zero_array(stat, dpc_packet_stat_t, DHCP_MAX_MESSAGE_TYPE + 1);
	}

	dpc_packet_stat_t *packet_stat = stat->data;
	PACKET_STAT_NUM_INCR(packet_stat, stat_type, packet_type);
}

/**
 * Prepare and send a packet statistics data point to its destination.
 */
int dpc_timedata_send_packet_stat(ncc_timedata_stat_t *stat)
{
	char influx_data[1024];
	int i;

	dpc_packet_stat_t *packet_stat = stat->data;
	for (i = 1; i < DHCP_MAX_MESSAGE_TYPE; i ++) {
		/* Don't write if we have nothing for this type of packet.
		 */
		if (PACKET_STAT_GET(packet_stat, recv, i) == 0 && PACKET_STAT_GET(packet_stat, sent, i) == 0
			&& PACKET_STAT_GET(packet_stat, retr, i) == 0 && PACKET_STAT_GET(packet_stat, lost, i) == 0) {
			continue;
		}

		snprintf(influx_data, sizeof(influx_data),
			"packet,instance=%s,type=%s recv=%ui,sent=%ui,retr=%ui,lost=%ui %lu%06lu000",
			ncc_timedata_get_inst_esc(),
			dpc_message_types[i],
			PACKET_STAT_GET(packet_stat, recv, i),
			PACKET_STAT_GET(packet_stat, sent, i),
			PACKET_STAT_GET(packet_stat, retr, i),
			PACKET_STAT_GET(packet_stat, lost, i),
			stat->timestamp.tv_sec, stat->timestamp.tv_usec);

		if (ncc_timedata_write(influx_data) < 0) {
			return -1;
		}
	}

	return 0;
}

/**
 * Store transaction statistics into time-data.
 */
void dpc_timedata_store_tr_stat(char const *name, fr_time_delta_t rtt)
{
	ncc_timedata_stat_t *stat = ncc_timedata_context_get_storage(tr_stat_context);
	if (!stat) return;

	if (!stat->data) {
		/* Newly allocated item.
		 * Now allocate specific data storage.
		 */
		stat->data = talloc_zero(stat, dpc_dyn_tr_stats_t);
	}

	dpc_dyn_tr_stats_t *dyn_tr_stats = stat->data;
	dpc_dyn_tr_stats_update(stat, dyn_tr_stats, name, rtt);
}

/**
 * Prepare and send a transaction statistics data point to its destination.
 */
int dpc_timedata_send_tr_stat(ncc_timedata_stat_t *stat)
{
	char influx_data[1024];
	char name_buf[256];

	dpc_dyn_tr_stats_t *dyn_tr_stats = stat->data;

	size_t num_names = talloc_array_length(dyn_tr_stats->names);
	size_t num_transaction_type = talloc_array_length(dyn_tr_stats->stats);

	int i;
	for (i = 0; i < num_transaction_type; i++) {
		if (i >= num_names) break; /* Should never happen. */

		dpc_transaction_stats_t *transaction_stat = &dyn_tr_stats->stats[i];

		double rtt_avg = 1000 * ncc_fr_time_to_float(transaction_stat->rtt_cumul) / transaction_stat->num;
		double rtt_min = 1000 * ncc_fr_time_to_float(transaction_stat->rtt_min);
		double rtt_max = 1000 * ncc_fr_time_to_float(transaction_stat->rtt_max);

		NCC_INFLUX_ESCAPE_KEY(name_buf, sizeof(name_buf), dyn_tr_stats->names[i]);

		snprintf(influx_data, sizeof(influx_data),
			"transaction,instance=%s,type=%s num=%ui,rtt.avg=%.3f,rtt.min=%.3f,rtt.max=%.3f %lu%06lu000",
			ncc_timedata_get_inst_esc(),
			name_buf,
			transaction_stat->num,
			rtt_avg, rtt_min, rtt_max,
			stat->timestamp.tv_sec, stat->timestamp.tv_usec);

		if (ncc_timedata_write(influx_data) < 0) {
			return -1;
		}
	}

	return 0;
}

/**
 * Update statistics for a dynamically discovered session type.
 */
void dpc_dyn_session_stats_update(TALLOC_CTX *ctx, dpc_dyn_session_stats_t *dyn_session_stats,
                                  uint32_t input_id, char const *input_name, ncc_segment_t *segment,
                                  uint32_t target_add)
{
	int num = talloc_array_length(dyn_session_stats->stats);
	int i;

	/* Get the item index. */
	for (i = 0; i < num; i++) {
		if (dyn_session_stats->stats[i].input_id == input_id
		    && ( (!segment && !dyn_session_stats->stats[i].segment)
			  || (segment && dyn_session_stats->stats[i].segment && segment == dyn_session_stats->stats[i].segment)
			   )
		) break;
	}
	if (i == num) {
		/* Not found, add a new item. */
		TALLOC_REALLOC_ZERO(ctx, dyn_session_stats->stats, dpc_session_stats_t, num, num + 1);
		dyn_session_stats->stats[i].input_id = input_id;
		dyn_session_stats->stats[i].input_name = input_name;
		dyn_session_stats->stats[i].segment = segment;
	}

	dyn_session_stats->stats[i].num ++;

	/* Update the target number of sessions. */
	dyn_session_stats->stats[i].target += target_add;
}

/**
 * Store session statistics into time-data.
 */
void dpc_timedata_store_session_stat(uint32_t input_id, char const *input_name, ncc_segment_t *segment,
                                     uint32_t target_add)
{
	ncc_timedata_stat_t *stat = ncc_timedata_context_get_storage(session_stat_context);
	if (!stat) return;

	if (!stat->data) {
		/* Newly allocated item.
		 * Now allocate specific data storage.
		 */
		stat->data = talloc_zero(stat, dpc_dyn_session_stats_t);
	}

	dpc_dyn_session_stats_t *dyn_session_stats = stat->data;
	dpc_dyn_session_stats_update(stat, dyn_session_stats, input_id, input_name, segment, target_add);
}

/**
 * Prepare and send a session statistics data point to its destination.
 */
int dpc_timedata_send_session_stat(ncc_timedata_stat_t *stat)
{
	char influx_data[1024];
	char input_buf[256];
	char segment_buf[256];

	dpc_dyn_session_stats_t *dyn_session_stats = stat->data;

	size_t num = talloc_array_length(dyn_session_stats->stats);

	int i;
	for (i = 0; i < num; i++) {
		dpc_session_stats_t *session_stat = &dyn_session_stats->stats[i];

		/* Use input name if it has one, otherwise use its Id. */
		if (session_stat->input_name) {
			NCC_INFLUX_ESCAPE_KEY(input_buf, sizeof(input_buf), session_stat->input_name);
		} else {
			sprintf(input_buf, "#%u", session_stat->input_id);
		}

		/* Segment is optional.
		 */
		if (session_stat->segment) {
			/* Use segment name if it has one, otherwise use its Id.
			 */
			if (session_stat->segment->name) {
				NCC_INFLUX_ESCAPE_KEY(segment_buf, sizeof(segment_buf), session_stat->segment->name);
			} else {
				sprintf(segment_buf, "#%u", session_stat->segment->id);
			}
		}

		size_t len, freespace = sizeof(influx_data);
		char *p = influx_data;

		len = snprintf(p, freespace, "session,instance=%s,input=%s",
		               ncc_timedata_get_inst_esc(), input_buf);
		p += len; freespace -= len;

		if (session_stat->segment) {
			len = snprintf(p, freespace, ",segment=%s", segment_buf);
			p += len; freespace -= len;
		}

		len = snprintf(p, freespace, " num=%ui", session_stat->num);
		p += len; freespace -= len;

		/* Don't write "target" if unlimited. */
		if (session_stat->target) {
			len = snprintf(p, freespace, ",target=%ui", session_stat->target);
			p += len; freespace -= len;
		}

		len = snprintf(p, freespace, " %lu%06lu000", stat->timestamp.tv_sec, stat->timestamp.tv_usec);

		if (ncc_timedata_write(influx_data) < 0) {
			return -1;
		}
	}

	return 0;
}
