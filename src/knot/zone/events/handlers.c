/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <urcu.h>

#include "dnssec/random.h"
#include "libknot/libknot.h"
#include "libknot/processing/requestor.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/trim.h"
#include "contrib/ucw/mempool.h"
#include "contrib/wire.h"

#include "knot/common/log.h"
#include "knot/server/udp-handler.h"
#include "knot/server/tcp-handler.h"
#include "knot/updates/changesets.h"
#include "knot/dnssec/zone-events.h"
#include "knot/zone/timers.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/events/events.h"
#include "knot/zone/events/handlers.h"
#include "knot/updates/apply.h"
#include "knot/nameserver/internet.h"
#include "knot/nameserver/update.h"
#include "knot/nameserver/notify.h"
#include "knot/nameserver/tsig_ctx.h"
#include "knot/nameserver/process_answer.h"

#define BOOTSTRAP_RETRY (30) /*!< Interval between AXFR bootstrap retries. */
#define BOOTSTRAP_MAXTIME (24*60*60) /*!< Maximum AXFR retry cap of 24 hours. */

/* ------------------------- zone query requesting -------------------------- */

/*! \brief Zone event logging. */
#define ZONE_QUERY_LOG(severity, zone, remote, operation, msg, ...) \
	NS_PROC_LOG(severity, &(remote)->addr, zone->name, operation, msg, ##__VA_ARGS__)

/*! \brief Create zone query packet. */
static knot_pkt_t *zone_query(const zone_t *zone, uint16_t pkt_type, knot_mm_t *mm)
{
	/* Determine query type and opcode. */
	uint16_t query_type = KNOT_RRTYPE_SOA;
	uint16_t opcode = KNOT_OPCODE_QUERY;
	switch(pkt_type) {
	case KNOT_QUERY_AXFR: query_type = KNOT_RRTYPE_AXFR; break;
	case KNOT_QUERY_IXFR: query_type = KNOT_RRTYPE_IXFR; break;
	case KNOT_QUERY_NOTIFY: opcode = KNOT_OPCODE_NOTIFY; break;
	}

	knot_pkt_t *pkt = knot_pkt_new(NULL, KNOT_WIRE_MAX_PKTSIZE, mm);
	if (pkt == NULL) {
		return NULL;
	}

	knot_wire_set_id(pkt->wire, dnssec_random_uint16_t());
	knot_wire_set_opcode(pkt->wire, opcode);
	if (pkt_type == KNOT_QUERY_NOTIFY) {
		knot_wire_set_aa(pkt->wire);
	}

	knot_pkt_put_question(pkt, zone->name, KNOT_CLASS_IN, query_type);

	/* Put current SOA (optional). */
	zone_contents_t *contents = zone->contents;
	if (pkt_type == KNOT_QUERY_IXFR) {  /* RFC1995, SOA in AUTHORITY. */
		knot_pkt_begin(pkt, KNOT_AUTHORITY);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &soa_rr, 0);
	} else if (pkt_type == KNOT_QUERY_NOTIFY) { /* RFC1996, SOA in ANSWER. */
		knot_pkt_begin(pkt, KNOT_ANSWER);
		knot_rrset_t soa_rr = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
		knot_pkt_put(pkt, KNOT_COMPR_HINT_QNAME, &soa_rr, 0);
	}

	return pkt;
}

/*! \brief Set EDNS section. */
static int prepare_edns(zone_t *zone, knot_pkt_t *pkt)
{
	conf_val_t val = conf_zone_get(conf(), C_REQUEST_EDNS_OPTION, zone->name);

	/* Check if an extra EDNS option is configured. */
	size_t opt_len;
	const uint8_t *opt_data = conf_data(&val, &opt_len);
	if (opt_data == NULL) {
		return KNOT_EOK;
	}

	knot_rrset_t opt_rr;
	conf_val_t *max_payload = &conf()->cache.srv_max_udp_payload;
	int ret = knot_edns_init(&opt_rr, conf_int(max_payload), 0,
	                         KNOT_EDNS_VERSION, &pkt->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_edns_add_option(&opt_rr, wire_read_u64(opt_data),
	                           yp_bin_len(opt_data + sizeof(uint64_t)),
	                           yp_bin(opt_data + sizeof(uint64_t)), &pkt->mm);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &pkt->mm);
		return ret;
	}

	knot_pkt_begin(pkt, KNOT_ADDITIONAL);

	ret = knot_pkt_put(pkt, KNOT_COMPR_HINT_NONE, &opt_rr, KNOT_PF_FREE);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(&opt_rr, &pkt->mm);
		return ret;
	}

	return KNOT_EOK;
}

/*! \brief Process query using requestor. */
static int zone_query_request(knot_pkt_t *query, const conf_remote_t *remote,
                              struct process_answer_param *param, knot_mm_t *mm)
{
	/* Create requestor instance. */
	struct knot_requestor re;
	int ret = knot_requestor_init(&re, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}
	ret = knot_requestor_overlay(&re, KNOT_STATE_ANSWER, param);
	if (ret != KNOT_EOK) {
		knot_requestor_clear(&re);
		return ret;
	}

	/* Create a request. */
	const struct sockaddr *dst = (const struct sockaddr *)&remote->addr;
	const struct sockaddr *src = (const struct sockaddr *)&remote->via;
	struct knot_request *req = knot_request_make(re.mm, dst, src, query, 0);
	if (req == NULL) {
		knot_requestor_clear(&re);
		return KNOT_ENOMEM;
	}

	/* Send the queries and process responses. */
	ret = knot_requestor_enqueue(&re, req);
	if (ret == KNOT_EOK) {
		conf_val_t *val = &conf()->cache.srv_tcp_reply_timeout;
		struct timeval tv = { conf_int(val), 0 };
		ret = knot_requestor_exec(&re, &tv);
	} else {
		knot_request_free(req, re.mm);
	}

	/* Cleanup. */
	knot_requestor_clear(&re);

	return ret;
}

/*!
 * \brief Create a zone event query, send it, wait for the response and process it.
 *
 * \note Everything in this function is executed synchronously, returns when
 *       the query processing is either complete or an error occurs.
 */
static int zone_query_execute(zone_t *zone, uint16_t pkt_type, const conf_remote_t *remote)
{
	/* Create a memory pool for this task. */
	knot_mm_t mm;
	mm_ctx_mempool(&mm, MM_DEFAULT_BLKSIZE);

	/* Create a query message. */
	knot_pkt_t *query = zone_query(zone, pkt_type, &mm);
	if (query == NULL) {
		mp_delete(mm.ctx);
		return KNOT_ENOMEM;
	}

	/* Set EDNS section. */
	int ret = prepare_edns(zone, query);
	if (ret != KNOT_EOK) {
		knot_pkt_free(&query);
		mp_delete(mm.ctx);
		return ret;
	}

	/* Answer processing parameters. */
	struct process_answer_param param = {
		.zone = zone,
		.query = query,
		.remote = &remote->addr
	};

	const knot_tsig_key_t *key = remote->key.name != NULL ?
	                             &remote->key : NULL;
	tsig_init(&param.tsig_ctx, key);

	ret = tsig_sign_packet(&param.tsig_ctx, query);
	if (ret != KNOT_EOK) {
		tsig_cleanup(&param.tsig_ctx);
		knot_pkt_free(&query);
		mp_delete(mm.ctx);
		return ret;
	}

	/* Process the query. */
	ret = zone_query_request(query, remote, &param, &mm);

	/* Cleanup. */
	tsig_cleanup(&param.tsig_ctx);
	knot_pkt_free(&query);
	mp_delete(mm.ctx);

	return ret;
}

/* @note Module specific, expects some variables set. */
#define ZONE_XFER_LOG(severity, pkt_type, msg, ...) \
	if (pkt_type == KNOT_QUERY_AXFR) { \
		ZONE_QUERY_LOG(severity, zone, master, "AXFR, incoming", msg, ##__VA_ARGS__); \
	} else { \
		ZONE_QUERY_LOG(severity, zone, master, "IXFR, incoming", msg, ##__VA_ARGS__); \
	}

/*! \brief Execute zone transfer request. */
static int zone_query_transfer(zone_t *zone, const conf_remote_t *master, uint16_t pkt_type)
{
	assert(zone);
	assert(master);

	int ret = zone_query_execute(zone, pkt_type, master);
	if (ret != KNOT_EOK) {
		/* IXFR failed, revert to AXFR. */
		if (pkt_type == KNOT_QUERY_IXFR) {
			ZONE_XFER_LOG(LOG_NOTICE, pkt_type, "fallback to AXFR");
			return zone_query_transfer(zone, master, KNOT_QUERY_AXFR);
		}

		/* Log connection errors. */
		ZONE_XFER_LOG(LOG_WARNING, pkt_type, "failed (%s)", knot_strerror(ret));
	}

	return ret;
}

#undef ZONE_XFER_LOG

/*!
 * \todo Separate signing from zone loading and drop this function.
 *
 * DNSSEC signing is planned from two places - after zone loading and after
 * successful resign. This function just logs the message and reschedules the
 * DNSSEC timer.
 *
 * I would rather see the invocation of the signing from event_dnssec()
 * function. This would require to split refresh event to zone load and zone
 * publishing.
 */
static void schedule_dnssec(zone_t *zone, time_t refresh_at)
{
	// log a message

	char time_str[64] = { 0 };
	struct tm time_gm = { 0 };
	localtime_r(&refresh_at, &time_gm);
	strftime(time_str, sizeof(time_str), KNOT_LOG_TIME_FORMAT, &time_gm);
	log_zone_info(zone->name, "DNSSEC, next signing on %s", time_str);

	// schedule

	zone_events_schedule_at(zone, ZONE_EVENT_DNSSEC, refresh_at);
}

/*! \brief Get SOA from zone. */
static const knot_rdataset_t *zone_soa(zone_t *zone)
{
	return node_rdataset(zone->contents->apex, KNOT_RRTYPE_SOA);
}

/*! \brief Fetch SOA expire timer and add a timeout grace period. */
static uint32_t soa_graceful_expire(const knot_rdataset_t *soa)
{
	// Allow for timeouts.  Otherwise zones with very short
	// expiry may expire before the timeout is reached.
	conf_val_t *val = &conf()->cache.srv_tcp_reply_timeout;
	return knot_soa_expire(soa) + 2 * conf_int(val);
}

/*! \brief Schedule expire event, unless it is already scheduled. */
static void start_expire_timer(zone_t *zone, const knot_rdataset_t *soa)
{
	if (zone_events_is_scheduled(zone, ZONE_EVENT_EXPIRE)) {
		return;
	}

	zone_events_schedule(zone, ZONE_EVENT_EXPIRE, soa_graceful_expire(soa));
}

/* -- zone events handling callbacks --------------------------------------- */

int event_load(zone_t *zone)
{
	assert(zone);

	/* Take zone file mtime and load it. */
	char *filename = conf_zonefile(conf(), zone->name);
	time_t mtime = zonefile_mtime(filename);
	free(filename);
	uint32_t dnssec_refresh = time(NULL);

	zone_contents_t *contents = NULL;
	int ret = zone_load_contents(conf(), zone->name, &contents);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	/* Store zonefile serial and apply changes from the journal. */
	zone->zonefile_serial = zone_contents_serial(contents);
	ret = zone_load_journal(conf(), zone, contents);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	/* Post load actions - calculate delta, sign with DNSSEC... */
	/*! \todo issue #242 dnssec signing should occur in the special event */
	ret = zone_load_post(conf(), contents, zone, &dnssec_refresh);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ESPACE) {
			log_zone_error(zone->name, "journal size is too small "
			               "to fit the changes");
		} else {
			log_zone_error(zone->name, "failed to store changes into "
			               "journal (%s)", knot_strerror(ret));
		}
		goto fail;
	}

	/* Check zone contents consistency. */
	ret = zone_load_check(conf(), contents);
	if (ret != KNOT_EOK) {
		goto fail;
	}

	/* Everything went alright, switch the contents. */
	zone->zonefile_mtime = mtime;
	zone_contents_t *old = zone_switch_contents(zone, contents);
	zone->flags &= ~ZONE_EXPIRED;
	uint32_t old_serial = zone_contents_serial(old);
	if (old != NULL) {
		synchronize_rcu();
		zone_contents_deep_free(&old);
	}

	/* Schedule notify and refresh after load. */
	if (zone_is_slave(zone)) {
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);
	}
	if (!zone_contents_is_empty(contents)) {
		zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);
		zone->bootstrap_retry = ZONE_EVENT_NOW;
	}

	/* Schedule zone resign. */
	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, zone->name);
	if (conf_bool(&val)) {
		schedule_dnssec(zone, dnssec_refresh);
	}

	/* Periodic execution. */
	val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout >= 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, sync_timeout);
	}

	uint32_t current_serial = zone_contents_serial(zone->contents);
	log_zone_info(zone->name, "loaded, serial %u -> %u",
	              old_serial, current_serial);

	return KNOT_EOK;

fail:
	zone_contents_deep_free(&contents);

	/* Try to bootsrap the zone if local error. */
	zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);

	return ret;
}

static int try_refresh(zone_t *zone, const conf_remote_t *master, void *ctx)
{
	assert(zone);
	assert(master);

	int ret = zone_query_execute(zone, KNOT_QUERY_NORMAL, master);
	if (ret != KNOT_EOK) {
		ZONE_QUERY_LOG(LOG_WARNING, zone, master, "refresh, outgoing",
		               "failed (%s)", knot_strerror(ret));
	}

	return ret;
}

int event_refresh(zone_t *zone)
{
	assert(zone);

	/* Ignore if not slave zone. */
	if (!zone_is_slave(zone)) {
		return KNOT_EOK;
	}

	if (zone_contents_is_empty(zone->contents)) {
		/* No contents, schedule retransfer now. */
		zone_events_schedule(zone, ZONE_EVENT_XFER, ZONE_EVENT_NOW);
		return KNOT_EOK;
	}

	int ret = zone_master_try(zone, try_refresh, NULL, "refresh");
	const knot_rdataset_t *soa = zone_soa(zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "refresh, failed (%s)",
		               knot_strerror(ret));
		/* Schedule next retry. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_retry(soa));
		start_expire_timer(zone, soa);
	} else {
		/* SOA query answered, reschedule refresh timer. */
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	}

	return KNOT_EOK;
}

struct transfer_data {
	uint16_t pkt_type;
};

static int try_xfer(zone_t *zone, const conf_remote_t *master, void *_data)
{
	assert(zone);
	assert(master);
	assert(_data);

	struct transfer_data *data = _data;

	return zone_query_transfer(zone, master, data->pkt_type);
}

int event_xfer(zone_t *zone)
{
	assert(zone);

	/* Ignore if not slave zone. */
	if (!zone_is_slave(zone)) {
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
	int ret = zone_master_try(zone, try_xfer, &data, err_str);
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
			start_expire_timer(zone, soa);
		}

		return KNOT_EOK;
	}

	assert(!zone_contents_is_empty(zone->contents));
	const knot_rdataset_t *soa = zone_soa(zone);

	/* Rechedule events. */
	zone_events_schedule(zone, ZONE_EVENT_REFRESH, knot_soa_refresh(soa));
	zone_events_schedule(zone, ZONE_EVENT_NOTIFY,  ZONE_EVENT_NOW);
	zone_events_cancel(zone, ZONE_EVENT_EXPIRE);
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
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

int event_update(zone_t *zone)
{
	assert(zone);

	/* Process update list - forward if zone has master, or execute. */
	updates_execute(zone);

	/* Trim extra heap. */
	mem_trim();

	/* Replan event if next update waiting. */
	pthread_mutex_lock(&zone->ddns_lock);

	const bool empty = EMPTY_LIST(zone->ddns_queue);

	pthread_mutex_unlock(&zone->ddns_lock);

	if (!empty) {
		zone_events_schedule(zone, ZONE_EVENT_UPDATE, ZONE_EVENT_NOW);
	}

	return KNOT_EOK;
}

int event_expire(zone_t *zone)
{
	assert(zone);

	zone_contents_t *expired = zone_switch_contents(zone, NULL);
	synchronize_rcu();

	/* Expire zonefile information. */
	zone->zonefile_mtime = 0;
	zone->zonefile_serial = 0;
	zone->flags |= ZONE_EXPIRED;
	zone_contents_deep_free(&expired);

	log_zone_info(zone->name, "zone expired");

	/* Trim extra heap. */
	mem_trim();

	return KNOT_EOK;
}

int event_flush(zone_t *zone)
{
	assert(zone);

	/* Reschedule. */
	conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
	int64_t sync_timeout = conf_int(&val);
	if (sync_timeout > 0) {
		zone_events_schedule(zone, ZONE_EVENT_FLUSH, sync_timeout);
	}

	/* Check zone contents. */
	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	return zone_flush_journal(zone);
}

int event_notify(zone_t *zone)
{
	assert(zone);

	/* Check zone contents. */
	if (zone_contents_is_empty(zone->contents)) {
		return KNOT_EOK;
	}

	/* Walk through configured remotes and send messages. */
	conf_val_t notify = conf_zone_get(conf(), C_NOTIFY, zone->name);
	while (notify.code == KNOT_EOK) {
		conf_val_t addr = conf_id_get(conf(), C_RMT, C_ADDR, &notify);
		size_t addr_count = conf_val_count(&addr);

		for (int i = 0; i < addr_count; i++) {
			conf_remote_t slave = conf_remote(conf(), &notify, i);
			int ret = zone_query_execute(zone, KNOT_QUERY_NOTIFY, &slave);
			if (ret == KNOT_EOK) {
				ZONE_QUERY_LOG(LOG_INFO, zone, &slave,
				               "NOTIFY, outgoing", "serial %u",
				               zone_contents_serial(zone->contents));
				break;
			} else {
				ZONE_QUERY_LOG(LOG_WARNING, zone, &slave,
				               "NOTIFY, outgoing", "failed (%s)",
				               knot_strerror(ret));
			}
		}

		conf_val_next(&notify);
	}

	return KNOT_EOK;
}

int event_dnssec(zone_t *zone)
{
	assert(zone);

	changeset_t ch;
	int ret = changeset_init(&ch, zone->name);
	if (ret != KNOT_EOK) {
		goto done;
	}

	uint32_t refresh_at = time(NULL);
	int sign_flags = 0;

	if (zone->flags & ZONE_FORCE_RESIGN) {
		log_zone_info(zone->name, "DNSSEC, dropping previous "
		              "signatures, resigning zone");
		zone->flags &= ~ZONE_FORCE_RESIGN;
		sign_flags = ZONE_SIGN_DROP_SIGNATURES;
	} else {
		log_zone_info(zone->name, "DNSSEC, signing zone");
		sign_flags = 0;
	}

	ret = knot_dnssec_zone_sign(zone->contents, &ch, sign_flags, &refresh_at);
	if (ret != KNOT_EOK) {
		goto done;
	}

	bool zone_changed = !changeset_empty(&ch);
	if (zone_changed) {
		/* Apply change. */
		zone_contents_t *new_contents = NULL;
		int ret = apply_changeset(zone, &ch, &new_contents);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "DNSSEC, failed to sign zone (%s)",
				       knot_strerror(ret));
			goto done;
		}

		/* Write change to journal. */
		ret = zone_change_store(zone, &ch);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "DNSSEC, failed to sign zone (%s)",
				       knot_strerror(ret));
			update_rollback(&ch);
			update_free_zone(&new_contents);
			goto done;
		}

		/* Switch zone contents. */
		zone_contents_t *old_contents = zone_switch_contents(zone, new_contents);
		zone->flags &= ~ZONE_EXPIRED;
		synchronize_rcu();
		update_free_zone(&old_contents);

		update_cleanup(&ch);
	}

	// Schedule dependent events.

	schedule_dnssec(zone, refresh_at);
	if (zone_changed) {
		zone_events_schedule(zone, ZONE_EVENT_NOTIFY, ZONE_EVENT_NOW);
		conf_val_t val = conf_zone_get(conf(), C_ZONEFILE_SYNC, zone->name);
		if (conf_int(&val) == 0) {
			zone_events_schedule(zone, ZONE_EVENT_FLUSH, ZONE_EVENT_NOW);
		}
	}

done:
	changeset_clear(&ch);
	return ret;
}

#undef ZONE_QUERY_LOG

/*! \brief Progressive bootstrap retry timer. */
uint32_t bootstrap_next(uint32_t timer)
{
	timer *= 2;
	timer += dnssec_random_uint32_t() % BOOTSTRAP_RETRY;
	if (timer > BOOTSTRAP_MAXTIME) {
		timer = BOOTSTRAP_MAXTIME;
	}
	return timer;
}

