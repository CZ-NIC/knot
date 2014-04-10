/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <sys/stat.h>
#include <unistd.h>
#include <inttypes.h>

#include "common/descriptor.h"
#include "common/lists.h"
#include "common/log.h"
#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "knot/server/server.h"
#include "knot/server/xfr-handler.h"
#include "knot/server/zone-load.h"
#include "knot/server/zones.h"
#include "knot/server/serialization.h"
#include "knot/zone/zone-dump.h"
#include "libknot/dname.h"
#include "libknot/dnssec/random.h"
#include "libknot/rdata/soa.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/nameserver/chaos.h"
#include "libknot/tsig-op.h"
#include "knot/updates/changesets.h"
#include "knot/updates/ddns.h"
#include "knot/updates/xfr-in.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonedb.h"
#include "knot/zone/zonefile.h"
#include "libknot/util/utils.h"

/*!
 * \brief Apply jitter to time interval.
 *
 * Amount of jitter is specified by ZONES_JITTER_PCT.
 *
 * \param interval base value.
 * \return interval value minus rand(0, ZONES_JITTER_PCT) %
 */
static uint32_t zones_jitter(uint32_t interval)
{
	return (interval * (100 - (knot_random_uint32_t() % ZONES_JITTER_PCT))) / 100;
}

/*!
 * \brief Return SOA timer value.
 *
 * \param zone Pointer to zone.
 * \param rr_func RDATA specificator.
 * \return Timer in miliseconds.
 */
static uint32_t zones_soa_timer(zone_t *zone, uint32_t (*rr_func)(const knot_rdataset_t*))
{
	if (!zone) {
		dbg_zones_verb("zones: zones_soa_timer() called "
		               "with NULL zone\n");
		return 0;
	}

	uint32_t ret = 0;

	/* Retrieve SOA RDATA. */
	const knot_rdataset_t *soa_rrs = NULL;

	rcu_read_lock();

	zone_contents_t * zc = zone->contents;
	if (!zc) {
		rcu_read_unlock();
		return 0;
	}

	soa_rrs = knot_node_rdataset(zc->apex, KNOT_RRTYPE_SOA);
	assert(soa_rrs != NULL);
	ret = rr_func(soa_rrs);

	rcu_read_unlock();

	/* Convert to miliseconds. */
	return ret * 1000;
}

/*!
 * \brief Return SOA REFRESH timer value.
 *
 * \param zone Pointer to zone.
 * \return REFRESH timer in miliseconds.
 */
static uint32_t zones_soa_refresh(zone_t *zone)
{
	return zones_soa_timer(zone, knot_soa_refresh);
}

/*!
 * \brief Return SOA RETRY timer value.
 *
 * \param zone Pointer to zone.
 * \return RETRY timer in miliseconds.
 */
static uint32_t zones_soa_retry(zone_t *zone)
{
	return zones_soa_timer(zone, knot_soa_retry);
}

/*!
 * \brief Return SOA EXPIRE timer value.
 *
 * \param zone Pointer to zone.
 * \return EXPIRE timer in miliseconds.
 */
static uint32_t zones_soa_expire(zone_t *zone)
{
	return zones_soa_timer(zone, knot_soa_expire);
}

/*!
 * \brief Zone REFRESH or RETRY event.
 */
int zones_refresh_ev(event_t *event)
{
	assert(event);

	dbg_zones("zone: REFRESH/RETRY timer event\n");
	rcu_read_lock();
	zone_t *zone = (zone_t *)event->data;
	if (zone == NULL) {
		rcu_read_unlock();
		return KNOT_EINVAL;
	}

	if (zone->flags & ZONE_DISCARDED) {
		rcu_read_unlock();
		return KNOT_EOK;
	}

	/* Create XFR request. */
	knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_SOA, XFR_FLAG_TCP);
	rcu_read_unlock(); /* rq now holds a reference to zone */
	if (!rq) {
		return KNOT_EINVAL;
	}

	const conf_iface_t *master = zone_master(zone);
	xfr_task_setaddr(rq, &master->addr, &master->via);
	rq->tsig_key = master->key;

	/* Check for contents. */
	int ret = KNOT_EOK;
	if (!zone->contents) {

		/* Bootstrap over TCP. */
		rq->type = XFR_TYPE_AIN;
		rq->flags = XFR_FLAG_TCP;
		evsched_end_process(event->sched);

		/* Check transfer state. */
		pthread_mutex_lock(&zone->lock);
		if (zone->xfr_in.state == XFR_PENDING) {
			pthread_mutex_unlock(&zone->lock);
			xfr_task_free(rq);
			return KNOT_EOK;
		} else {
			zone->xfr_in.state = XFR_PENDING;
		}

		/* Issue request. */
#warning "XFR enqueue."
		pthread_mutex_unlock(&zone->lock);
		return ret;
	}

	/* Reschedule as RETRY timer. */
	uint32_t retry_tmr = zones_jitter(zones_soa_retry(zone));
	evsched_schedule(event, retry_tmr);
	dbg_zones("zone: RETRY of '%s' after %u seconds\n",
	          zone->conf->name, retry_tmr / 1000);

	/* Issue request. */
	evsched_end_process(event->sched);
#warning "XFR enqueue."

	return ret;
}

/*----------------------------------------------------------------------------*/




/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/

knot_ns_xfr_type_t zones_transfer_to_use(zone_t *zone)
{
	if (zone == NULL || !journal_exists(zone->conf->ixfr_db)) {
		return XFR_TYPE_AIN;
	}

	return XFR_TYPE_IIN;
}

/*----------------------------------------------------------------------------*/

int zones_schedule_notify(zone_t *zone, server_t *server)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

	/* Do not issue NOTIFY queries if stub. */
	if (!zone->contents) {
		return KNOT_EOK;
	}

	/* Schedule NOTIFY to slaves. */
	conf_zone_t *cfg = zone->conf;
	conf_remote_t *r = 0;
	WALK_LIST(r, cfg->acl.notify_out) {

		/* Fetch remote. */
		conf_iface_t *cfg_if = r->remote;

		/* Create request. */
		knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_NOTIFY, XFR_FLAG_UDP);
		if (!rq) {
			log_zone_error("Failed to create NOTIFY for '%s', "
			               "not enough memory.\n", cfg->name);
			continue;
		}

		xfr_task_setaddr(rq, &cfg_if->addr, &cfg_if->via);
		rq->tsig_key = cfg_if->key;

		rq->data = (void *)((long)cfg->notify_retries);
#warning "XFR enqueue."
//		if (xfr_enqueue(server->xfr, rq) != KNOT_EOK) {
//			log_zone_error("Failed to enqueue NOTIFY for '%s'.\n",
//			               cfg->name);
//			continue;
//		}
	}

	return KNOT_EOK;
}

int zones_schedule_refresh(zone_t *zone, int64_t timeout)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

	/* Cancel REFRESH/EXPIRE timer. */
//	evsched_cancel(zone->xfr_in.expire);
//	evsched_cancel(zone->xfr_in.timer);

	/* Check XFR/IN master server. */
	pthread_mutex_lock(&zone->lock);
	rcu_read_lock();
	zone->xfr_in.state = XFR_IDLE;
	if (zone_master(zone) != NULL) {

		/* Schedule EXPIRE timer. */
		if (zone->contents != NULL) {
			int64_t expire_tmr = zones_jitter(zones_soa_expire(zone));
			// Allow for timeouts.  Otherwise zones with very short
			// expiry may expire before the timeout is reached.
			expire_tmr += 2 * (conf()->max_conn_idle * 1000);
//			evsched_schedule(zone->xfr_in.expire, expire_tmr);
			dbg_zones("zone: EXPIRE '%s' set to %"PRIi64"\n",
			          zone->conf->name, expire_tmr);
		}

		/* Schedule REFRESH timer. */
		if (timeout < 0) {
			if (zone->contents) {
				timeout = zones_jitter(zones_soa_refresh(zone));
			} else {
				timeout = zone->xfr_in.bootstrap_retry;
			}
		}
//		evsched_schedule(zone->xfr_in.timer, timeout);
		dbg_zones("zone: REFRESH '%s' set to %"PRIi64"\n",
		          zone->conf->name, timeout);
		zone->xfr_in.state = XFR_SCHED;

	}
	rcu_read_unlock();
	pthread_mutex_unlock(&zone->lock);

	return KNOT_EOK;
}

int zones_dnssec_sign(zone_t *zone, bool force, uint32_t *refresh_at)
{
	int ret = KNOT_EOK;
	char *msgpref = NULL;
	*refresh_at = 0;

	knot_changesets_t *chs = knot_changesets_create(1);
	if (chs == NULL) {
		ret = KNOT_ENOMEM;
		goto done;
	}
	knot_changeset_t *ch = knot_changesets_get_last(chs);

	char *zname = knot_dname_to_str(zone->name);
	msgpref = sprintf_alloc("DNSSEC: Zone %s -", zname);
	free(zname);
	if (msgpref == NULL) {
		ret = KNOT_ENOMEM;
		goto done;
	}

	if (force) {
		log_zone_info("%s Complete resign started (dropping all "
			      "previous signatures)...\n", msgpref);
	} else {
		log_zone_info("%s Signing zone...\n", msgpref);
	}

	if (force) {
		ret = knot_dnssec_zone_sign_force(zone->contents, zone->conf,
		                                  ch, refresh_at);
	} else {
		ret = knot_dnssec_zone_sign(zone->contents, zone->conf,
		                            ch, KNOT_SOA_SERIAL_UPDATE,
		                            refresh_at);
	}
	if (ret != KNOT_EOK) {
		goto done;
	}

	if (!knot_changesets_empty(chs)) {
		zone_contents_t *new_c = NULL;
		ret = zone_change_apply_and_store(chs, zone, &new_c, "DNSSEC");
		chs = NULL; // freed by zone_change_apply_and_store()
		if (ret != KNOT_EOK) {
			log_zone_error("%s Could not sign zone (%s).\n",
				       msgpref, knot_strerror(ret));
			goto done;
		}
	}

	log_zone_info("%s Successfully signed.\n", msgpref);

done:
	knot_changesets_free(&chs);
	free(msgpref);

	/* Trim extra heap. */
	mem_trim();

	return ret;
}

int zones_dnssec_ev(event_t *event)
{
	// We will be working with zone, don't want it to change in the meantime
	rcu_read_lock();
	zone_t *zone = (zone_t *)event->data;
	uint32_t refresh_at = 0;

	int ret = zones_dnssec_sign(zone, false, &refresh_at);
	if (refresh_at != 0) {
		ret = zones_schedule_dnssec(zone, refresh_at);
	}

	rcu_read_unlock();

	return ret;
}

int zones_cancel_dnssec(zone_t *zone)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

//	evsched_cancel(zone->dnssec.timer);

	return KNOT_EOK;
}

int zones_schedule_dnssec(zone_t *zone, time_t unixtime)
{
	if (!zone) {
		return KNOT_EINVAL;
	}

	char *zname = knot_dname_to_str(zone->name);

	// absolute time -> relative time

	time_t now = time(NULL);
	int32_t relative = 0;
	if (unixtime <= now) {
		log_zone_warning("DNSSEC: Zone %s: Signature life time too low, "
		                 "set higher value in configuration!\n", zname);
	} else {
		relative = unixtime - now;
	}

	// log the message

	char time_str[64] = {'\0'};
	struct tm time_gm = {0};

	gmtime_r(&unixtime, &time_gm);

	strftime(time_str, sizeof(time_str), KNOT_LOG_TIME_FORMAT, &time_gm);

	log_zone_info("DNSSEC: Zone %s: Next signing planned on %s.\n",
	              zname, time_str);

	free(zname);

	// schedule


//	evsched_schedule(zone->dnssec.timer, relative * 1000);

	return KNOT_EOK;
}
