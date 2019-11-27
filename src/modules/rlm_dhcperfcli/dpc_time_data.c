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
#include "dpc_config.h"
#include "dpc_time_data.h"


ncc_timedata_context_t *packet_stat_context;


/**
 * Initialize time-data storage.
 */
static int dpc_timedata_init(TALLOC_CTX *ctx)
{
	packet_stat_context = ncc_timedata_context_add(ctx, "packet_stat");
	if (!packet_stat_context) return -1;

	packet_stat_context->send_func = dpc_timedata_send_packet_stat;

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

	if (ncc_timedata_config_init(cs, config->name) < 0) return -1;
	if (dpc_timedata_init(ctx) < 0) return -1;

	config->with_timedata = true;
	return 0;
}

/**
 * Store packet statistics into time-data.
 */
void dpc_timedata_store_packet_stat(dpc_packet_stat_field_t stat_type, uint32_t packet_type)
{
	ncc_timedata_stat_t *stat = ncc_timedata_get_storage(packet_stat_context);
	if (!stat) return;

	if (!stat->data) {
		/* Newly allocated item.
		 * Now allocate specific data storage.
		 */
		stat->data = talloc_zero_array(stat, dpc_packet_stat_t, DHCP_MAX_MESSAGE_TYPE + 1);
	}

	PACKET_STAT_NUM_INCR(stat->data, stat_type, packet_type);
}

/**
 * Prepare and send a packet statistics data point to its destination.
 */
int dpc_timedata_send_packet_stat(ncc_timedata_stat_t *stat)
{
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
			"INSTANCE", //timedata_config.instance, // TODO
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

		if (ncc_timedata_write(influx_data) < 0) {
			return -1;
		}
	}

	return 0;
}
