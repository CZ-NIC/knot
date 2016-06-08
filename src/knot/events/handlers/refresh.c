/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <stdint.h>

#include "contrib/trim.h"
#include "dnssec/random.h"
#include "knot/common/log.h"
#include "knot/conf/conf.h"
#include "knot/query/query.h"
#include "knot/zone/zone.h"
#include "libknot/errcode.h"

#define BOOTSTRAP_RETRY (30) /*!< Interval between AXFR bootstrap retries. */
#define BOOTSTRAP_MAXTIME (24*60*60) /*!< Maximum AXFR retry cap of 24 hours. */

#include "knot/nameserver/log.h"

// XXX: duplicate message
/* @note Module specific, expects some variables set. */
#define LOG_TRANSFER(severity, pkt_type, msg, ...) \
	if (pkt_type == KNOT_QUERY_AXFR) { \
		ZONE_QUERY_LOG(severity, zone, master, "AXFR, incoming", msg, ##__VA_ARGS__); \
	} else { \
		ZONE_QUERY_LOG(severity, zone, master, "IXFR, incoming", msg, ##__VA_ARGS__); \
	}

/*! \brief Progressive bootstrap retry timer. */
static uint32_t bootstrap_next(uint32_t timer)
{
	timer *= 2;
	timer += dnssec_random_uint32_t() % BOOTSTRAP_RETRY;
	if (timer > BOOTSTRAP_MAXTIME) {
		timer = BOOTSTRAP_MAXTIME;
	}
	return timer;
}

/*! \brief Get SOA from zone. */
static const knot_rdataset_t *zone_soa(zone_t *zone)
{
	return node_rdataset(zone->contents->apex, KNOT_RRTYPE_SOA);
}

static int try_refresh(conf_t *conf, zone_t *zone, const conf_remote_t *master, void *ctx)
{
	assert(zone);
	assert(master);

	int ret = zone_query_execute(conf, zone, KNOT_QUERY_NORMAL, master);
	if (ret != KNOT_EOK && ret != KNOT_LAYER_ERROR) {
		ZONE_QUERY_LOG(LOG_WARNING, zone, master, "refresh, outgoing",
		               "failed (%s)", knot_strerror(ret));
	}

	return ret;
}

/*! \brief Schedule expire event, unless it is already scheduled. */
static void start_expire_timer(conf_t *conf, zone_t *zone, const knot_rdataset_t *soa)
{
	if (zone_events_is_scheduled(zone, ZONE_EVENT_EXPIRE)) {
		return;
	}

	zone_events_schedule(zone, ZONE_EVENT_EXPIRE, knot_soa_expire(soa));
}

int event_refresh(conf_t *conf, zone_t *zone)
{
	assert(zone);

	/* Ignore if not slave zone. */
	if (!zone_is_slave(conf, zone)) {
		return KNOT_EOK;
	}

	if (zone_contents_is_empty(zone->contents)) {
		/* No contents, schedule retransfer now. */
		zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);
		return KNOT_EOK;
	}

	int ret = zone_master_try(conf, zone, try_refresh, NULL, "refresh");
	const knot_rdataset_t *soa = zone_soa(zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "refresh, failed (%s)",
		               knot_strerror(ret));
		/* Schedule next retry. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_retry(soa));
		start_expire_timer(conf, zone, soa);
	} else {
		/* SOA query answered, reschedule refresh timer. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	}

	return KNOT_EOK;
}

/*! \brief Execute zone transfer request. */
static int zone_query_transfer(conf_t *conf, zone_t *zone, const conf_remote_t *master,
                               uint16_t pkt_type)
{
	assert(zone);
	assert(master);

	int ret = zone_query_execute(conf, zone, pkt_type, master);
	if (ret != KNOT_EOK) {
		/* IXFR failed, revert to AXFR. */
		if (pkt_type == KNOT_QUERY_IXFR) {
			LOG_TRANSFER(LOG_NOTICE, pkt_type, "fallback to AXFR");
			return zone_query_transfer(conf, zone, master, KNOT_QUERY_AXFR);
		}

		/* Log connection errors. */
		LOG_TRANSFER(LOG_WARNING, pkt_type, "failed (%s)", knot_strerror(ret));
	}

	return ret;
}

struct transfer_data {
	uint16_t pkt_type;
};

static int try_xfer(conf_t *conf, zone_t *zone, const conf_remote_t *master, void *_data)
{
	assert(zone);
	assert(master);
	assert(_data);

	struct transfer_data *data = _data;

	return zone_query_transfer(conf, zone, master, data->pkt_type);
}

int event_xfer(conf_t *conf, zone_t *zone)
{
	assert(zone);

	/* Ignore if not slave zone. */
	if (!zone_is_slave(conf, zone)) {
		return KNOT_EOK;
	}

	struct transfer_data data = { 0 };
	const char *err_str = "";

	/* Determine transfer type. */
	bool is_bootstrap = zone_contents_is_empty(zone->contents);
	if (is_bootstrap || zone->flags & ZONE_FORCE_AXFR) {
		data.pkt_type = KNOT_QUERY_AXFR;
		err_str = "AXFR, incoming";
	} else {
		data.pkt_type = KNOT_QUERY_IXFR;
		err_str = "IXFR, incoming";
	}

	/* Execute zone transfer. */
	int ret = zone_master_try(conf, zone, try_xfer, &data, err_str);
	zone_clear_preferred_master(zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "%s, failed (%s)", err_str,
		               knot_strerror(ret));
		if (is_bootstrap) {
			zone->bootstrap_retry = bootstrap_next(zone->bootstrap_retry);
			zone_events_schedule(zone, ZONE_EVENT_XFER, zone->bootstrap_retry);
		} else {
			const knot_rdataset_t *soa = zone_soa(zone);
			zone_events_schedule(zone, ZONE_EVENT_XFER, knot_soa_retry(soa));
			start_expire_timer(conf, zone, soa);
		}

		return KNOT_EOK;
	}

	assert(!zone_contents_is_empty(zone->contents));
	const knot_rdataset_t *soa = zone_soa(zone);

	/* Rechedule events. */
	zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY,  ZONE_EVENT_NOW);
	zone_events_cancel(zone, ZONE_EVENT_EXPIRE);
	conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout == 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
	} else if (sync_timeout > 0 &&
	           !zone_events_is_scheduled(zone, ZONE_EVENT_FLUSH)) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, sync_timeout);
	}

	/* Transfer cleanup. */
	zone->bootstrap_retry = ZONE_EVENT_NOW;
	zone->flags &= ~ZONE_FORCE_AXFR;

	/* Trim extra heap. */
	if (!is_bootstrap) {
		mem_trim();
	}

	return KNOT_EOK;
}
