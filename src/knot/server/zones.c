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

#include <config.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common/lists.h"
#include "common/prng.h"
#include "libknot/dname.h"
#include "libknot/util/wire.h"
#include "knot/zone/zone-dump.h"
#include "knot/zone/zone-load.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/zonedb.h"
#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "common/log.h"
#include "knot/server/notify.h"
#include "knot/server/server.h"
#include "knot/server/xfr-handler.h"
#include "libknot/updates/xfr-in.h"
#include "knot/server/zones.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/nameserver/chaos.h"
#include "libknot/updates/changesets.h"
#include "libknot/tsig-op.h"
#include "common/descriptor.h"
#include "libknot/packet/response.h"
#include "libknot/zone/zone-diff.h"
#include "libknot/updates/ddns.h"

static const size_t XFRIN_CHANGESET_BINARY_SIZE = 100;
static const size_t XFRIN_CHANGESET_BINARY_STEP = 100;
static const size_t XFRIN_BOOTSTRAP_DELAY = 2000; /*!< AXFR bootstrap avg. delay */

/* Forward declarations. */
static int zones_dump_zone_text(knot_zone_contents_t *zone,  const char *zf);

/*! \brief Zone data destructor function. */
static int zonedata_destroy(knot_zone_t *zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	dbg_zones_verb("zones: zonedata_destroy(%p) called\n", zone);

	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd) {
		return KNOT_EINVAL;
	}

	/* Cancel REFRESH timer. */
	if (zd->xfr_in.timer) {
		evsched_t *sch = zd->xfr_in.timer->parent;
		evsched_cancel(sch, zd->xfr_in.timer);
		evsched_event_free(sch, zd->xfr_in.timer);
		zd->xfr_in.timer = 0;
	}

	/* Cancel EXPIRE timer. */
	if (zd->xfr_in.expire) {
		evsched_t *sch = zd->xfr_in.expire->parent;
		evsched_cancel(sch, zd->xfr_in.expire);
		evsched_event_free(sch, zd->xfr_in.expire);
		zd->xfr_in.expire = 0;
	}

	/* Cancel IXFR DB sync timer. */
	if (zd->ixfr_dbsync) {
		evsched_t *sch = zd->ixfr_dbsync->parent;
		evsched_cancel(sch, zd->ixfr_dbsync);
		evsched_event_free(sch, zd->ixfr_dbsync);
		zd->ixfr_dbsync = 0;
	}

	acl_delete(&zd->xfr_in.acl);
	acl_delete(&zd->xfr_out);
	acl_delete(&zd->notify_in);
	acl_delete(&zd->notify_out);
	acl_delete(&zd->update_in);
	pthread_mutex_destroy(&zd->lock);

	/* Close IXFR db. */
	journal_release(zd->ixfr_db);

	/* Free assigned config. */
	conf_free_zone(zd->conf);

	free(zd);
	zone->data = 0;
	return KNOT_EOK;
}

/*! \brief Zone data constructor function. */
static int zonedata_init(conf_zone_t *cfg, knot_zone_t *zone)
{
	if (cfg == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}
	zonedata_t *zd = malloc(sizeof(zonedata_t));
	if (!zd) {
		return KNOT_ENOMEM;
	}
	memset(zd, 0, sizeof(zonedata_t));

	/* Link to config. */
	zd->conf = cfg;
	zd->server = 0;

	/* Initialize mutex. */
	pthread_mutex_init(&zd->lock, 0);

	/* Initialize ACLs. */
	zd->xfr_out = NULL;
	zd->notify_in = NULL;
	zd->notify_out = NULL;
	zd->update_in = NULL;

	/* Initialize XFR-IN. */
	sockaddr_init(&zd->xfr_in.master, -1);
	zd->xfr_in.timer = 0;
	zd->xfr_in.expire = 0;
	zd->xfr_in.acl = 0;
	zd->xfr_in.bootstrap_retry = (XFRIN_BOOTSTRAP_DELAY * tls_rand());

	/* Initialize IXFR database. */
	zd->ixfr_db = journal_open(cfg->ixfr_db, cfg->ixfr_fslimit,
	                           JOURNAL_LAZY, JOURNAL_DIRTY);

	if (zd->ixfr_db == NULL) {
		char ebuf[256] = {0};
		if (strerror_r(errno, ebuf, sizeof(ebuf)) == 0) {
			log_server_warning("Couldn't open journal file for "
			                   "zone '%s', disabling incoming "
			                   "IXFR. (%s)\n", cfg->name, ebuf);
		}
	}

	/* Initialize IXFR database syncing event. */
	zd->ixfr_dbsync = 0;

	/* Set and install destructor. */
	zone->data = zd;
	knot_zone_set_dtor(zone, zonedata_destroy);

	/* Set zonefile SOA serial. */
	const knot_rrset_t *soa_rrs = 0;

	/* Load serial. */
	zd->zonefile_serial = 0;
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (contents) {
		soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
					  KNOT_RRTYPE_SOA);
		assert(soa_rrs != NULL);
		int64_t serial = knot_rrset_rdata_soa_serial(soa_rrs);
		zd->zonefile_serial = (uint32_t)serial;
		if (serial < 0) {
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
}

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
	return (interval * (100 - (tls_rand() * ZONES_JITTER_PCT))) / 100;
}

/*!
 * \brief Return SOA timer value.
 *
 * \param zone Pointer to zone.
 * \param rr_func RDATA specificator.
 * \return Timer in miliseconds.
 */
static uint32_t zones_soa_timer(knot_zone_t *zone,
                                uint32_t (*rr_func)(const knot_rrset_t*))
{
	if (!zone) {
		dbg_zones_verb("zones: zones_soa_timer() called "
		               "with NULL zone\n");
	}

	uint32_t ret = 0;

	/* Retrieve SOA RDATA. */
	const knot_rrset_t *soa_rrs = 0;

	rcu_read_lock();

	knot_zone_contents_t * zc = knot_zone_get_contents((zone));
	if (!zc) {
		rcu_read_unlock();
		return 0;
	}

	soa_rrs = knot_node_rrset(knot_zone_contents_apex(zc),
	                            KNOT_RRTYPE_SOA);
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
static uint32_t zones_soa_refresh(knot_zone_t *zone)
{
	return zones_soa_timer(zone, knot_rrset_rdata_soa_refresh);
}

/*!
 * \brief Return SOA RETRY timer value.
 *
 * \param zone Pointer to zone.
 * \return RETRY timer in miliseconds.
 */
static uint32_t zones_soa_retry(knot_zone_t *zone)
{
	return zones_soa_timer(zone, knot_rrset_rdata_soa_retry);
}

/*!
 * \brief Return SOA EXPIRE timer value.
 *
 * \param zone Pointer to zone.
 * \return EXPIRE timer in miliseconds.
 */
static uint32_t zones_soa_expire(knot_zone_t *zone)
{
	return zones_soa_timer(zone, knot_rrset_rdata_soa_expire);
}

/*!
 * \brief XFR/IN expire event handler.
 */
static int zones_expire_ev(event_t *e)
{
	dbg_zones("zones: EXPIRE timer event\n");
	if (e->data == NULL) {
		return KNOT_EINVAL;
	}

	rcu_read_lock();
	knot_zone_t *zone = (knot_zone_t *)e->data;
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Check if zone is not discarded. */
	if (knot_zone_flags(zone) & KNOT_ZONE_DISCARDED) {
		rcu_read_unlock();
		return KNOT_EOK;
	}

	knot_zone_retain(zone); /* Keep a reference. */
	rcu_read_unlock();
	
	/* Mark the zone as expired. This will remove the zone contents. */
	knot_zone_contents_t *contents = knot_zonedb_expire_zone(
			zd->server->nameserver->zone_db, zone->name);

	/* Early finish this event to prevent lockup during cancellation. */
	dbg_zones("zones: zone expired, removing from database\n");
	evsched_event_finished(e->parent);
	
	/* Publish expired zone, must be after evsched_event_finished.
	 * This is because some other thread may hold rcu_read_lock and
	 * wait for event cancellation. */
	synchronize_rcu();

	/* Log event. */
	log_server_info("Zone '%s' expired.\n", zd->conf->name);

	/* Cancel REFRESH timer. */
	if (zd->xfr_in.timer) {
		evsched_cancel(e->parent, zd->xfr_in.timer);
		evsched_event_free(e->parent, zd->xfr_in.timer);
		zd->xfr_in.timer = 0;
	}

	/* Free EXPIRE timer. */
	if (zd->xfr_in.expire) {
		evsched_event_free(e->parent, zd->xfr_in.expire);
		zd->xfr_in.expire = 0;
	}

	knot_zone_contents_deep_free(&contents);

	/* Release holding reference. */
	knot_zone_release(zone);
	return KNOT_EOK;
}

/*!
 * \brief Zone REFRESH or RETRY event.
 */
static int zones_refresh_ev(event_t *e)
{
	dbg_zones("zones: REFRESH or RETRY timer event\n");
	rcu_read_lock();
	knot_zone_t *zone = (knot_zone_t *)e->data;
	if (zone == NULL || zone->data == NULL) {
		rcu_read_unlock();
		return KNOT_EINVAL;
	}

	/* Check if zone is not discarded. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (knot_zone_flags(zone) & KNOT_ZONE_DISCARDED) {
		rcu_read_unlock();
		return KNOT_EOK;
	}

	/* Create XFR request. */
	knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_SOA, XFR_FLAG_TCP);
	rcu_read_unlock(); /* rq now holds a reference to zone */
	if (!rq) {
		return KNOT_EINVAL;
	}
	xfr_task_setaddr(rq, &zd->xfr_in.master, &zd->xfr_in.via);
	if (zd->xfr_in.tsig_key.name) {
		rq->tsig_key = &zd->xfr_in.tsig_key;
	}

	/* Check for contents. */
	int ret = KNOT_EOK;
	if (!knot_zone_contents(zone)) {

		/* Bootstrap over TCP. */
		rq->type = XFR_TYPE_AIN;
		rq->flags = XFR_FLAG_TCP;
		evsched_event_finished(e->parent);

		/* Check transfer state. */
		pthread_mutex_lock(&zd->lock);
		if (zd->xfr_in.state == XFR_PENDING) {
			pthread_mutex_unlock(&zd->lock);
			xfr_task_free(rq);
			return KNOT_EOK;
		} else {
			zd->xfr_in.state = XFR_PENDING;
		}

		/* Issue request. */
		ret = xfr_enqueue(zd->server->xfr, rq);
		if (ret != KNOT_EOK) {
			xfr_task_free(rq);
			zd->xfr_in.state = XFR_SCHED; /* Revert state. */
		}
		pthread_mutex_unlock(&zd->lock);
		return ret;

	}

	/* Schedule EXPIRE timer on first attempt. */
	if (!zd->xfr_in.expire) {
		uint32_t expire_tmr = zones_jitter(zones_soa_expire(zone));
		zd->xfr_in.expire = evsched_schedule_cb(
					      e->parent,
					      zones_expire_ev,
					      zone, expire_tmr);
		dbg_zones("zones: EXPIRE of '%s' after %u seconds\n",
		          zd->conf->name, expire_tmr / 1000);
	}

	/* Reschedule as RETRY timer. */
	uint32_t retry_tmr = zones_jitter(zones_soa_retry(zone));
	evsched_schedule(e->parent, e, retry_tmr);
	dbg_zones("zones: RETRY of '%s' after %u seconds\n",
	          zd->conf->name, retry_tmr / 1000);


	/* Issue request. */
	evsched_event_finished(e->parent);
	ret = xfr_enqueue(zd->server->xfr, rq);
	if (ret != KNOT_EOK) {
		xfr_task_free(rq);
	}




	return ret;
}

/*! \brief Function for marking nodes as synced and updated. */
static int zones_ixfrdb_sync_apply(journal_t *j, journal_node_t *n)
{
	/* Check for dirty bit (not synced to permanent storage). */
	if (n->flags & JOURNAL_DIRTY) {

		/* Remove dirty bit. */
		n->flags = n->flags & ~JOURNAL_DIRTY;

		/* Sync. */
		journal_update(j, n);
	}

	return KNOT_EOK;
}

/*!
 * \brief Sync chagnes in zone to zonefile.
 */
static int zones_zonefile_sync_ev(event_t *e)
{
	dbg_zones("zones: IXFR database SYNC timer event\n");

	/* Fetch zone. */
	knot_zone_t *zone = (knot_zone_t *)e->data;
	if (!zone) {
		return KNOT_EINVAL;
	}

	/* Fetch zone data. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd) {
		return KNOT_EINVAL;
	}

	/* Only on zones with valid contents (non empty). */
	int ret = KNOT_EOK;
	if (knot_zone_contents(zone)) {
		/* Synchronize journal. */
		journal_t *j = journal_retain(zd->ixfr_db);
		ret = zones_zonefile_sync(zone, j);
		journal_release(j);

		rcu_read_lock();
		if (ret == KNOT_EOK) {
			log_zone_info("Applied differences of '%s' to zonefile.\n",
			              zd->conf->name);
		} else if (ret != KNOT_ERANGE) {
			log_zone_warning("Failed to apply differences of '%s' "
			                 "to zonefile.\n", zd->conf->name);
		}
		rcu_read_unlock();
	}

	/* Reschedule. */
	rcu_read_lock();
	int next_timeout = zd->conf->dbsync_timeout * 1000;
	dbg_zones("zones: next IXFR database SYNC of '%s' in %d seconds\n",
	          zd->conf->name, next_timeout / 1000);
	rcu_read_unlock();

	evsched_schedule(e->parent, e, next_timeout);
	return ret;
}

/*!
 * \brief Update ACL list from configuration.
 *
 * \param acl Pointer to existing or NULL ACL.
 * \param acl_list List of remotes from configuration.
 *
 * \retval KNOT_EOK on success.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOMEM on failed memory allocation.
 */
static int zones_set_acl(acl_t **acl, list* acl_list)
{
	if (!acl || !acl_list) {
		return KNOT_EINVAL;
	}

	/* Truncate old ACL. */
	acl_delete(acl);

	/* Create new ACL. */
	*acl = acl_new();
	if (*acl == NULL) {
		return KNOT_ENOMEM;
	}

	/* Load ACL rules. */
	sockaddr_t addr;
	conf_remote_t *r = 0;
	WALK_LIST(r, *acl_list) {

		/* Initialize address. */
		/*! Port matching disabled, port = 0. */
		sockaddr_init(&addr, -1);
		conf_iface_t *cfg_if = r->remote;
		int ret = sockaddr_set(&addr, cfg_if->family,
		                       cfg_if->address, 0);
		sockaddr_setprefix(&addr, cfg_if->prefix);

		/* Load rule. */
		if (ret > 0) {
			acl_insert(*acl, &addr, cfg_if);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Load zone to zone database.
 *
 * \param dst Loaded zone will be returned in this parameter.
 * \param zone_name Zone name (owner of the apex node).
 * \param source Path to zone file source.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_EZONEINVAL
 */
static int zones_load_zone(knot_zone_t **dst, const char *zone_name,
			   const char *source, int enable_checks)
{
	if (dst == NULL || zone_name == NULL || source == NULL) {
		return KNOT_EINVAL;
	}


	int ret = KNOT_EOK;
	zloader_t *zl = NULL;
	*dst = NULL;

	/* Open zone file for parsing. */
	switch(knot_zload_open(&zl, source, zone_name, enable_checks)) {
	case KNOT_EOK: /* OK */
		break;
	case KNOT_EACCES:
		log_server_error("No access/permission to zone file '%s'.\n",
		                 source);
		knot_zload_close(zl);
		return KNOT_EZONEINVAL;
	default:
		log_server_error("Failed to load zone file '%s'\n", source);
		knot_zload_close(zl);
		return KNOT_EZONEINVAL;
	}

	/* Check the source file */
	assert(zl != NULL);
	*dst = knot_zload_load(zl);
	if (*dst == NULL) {
		log_zone_error("Zone %s could not be loaded.\n", zone_name);
		knot_zload_close(zl);
		return KNOT_ERROR;
	}

	/* Check if loaded origin matches. */
	const knot_dname_t *dname = knot_zone_name(*dst);
	knot_dname_t *dname_req = NULL;
	dname_req = knot_dname_new_from_str(zone_name, strlen(zone_name), 0);
	if (knot_dname_compare(dname, dname_req) != 0) {
		log_server_error("Origin of the zone db file is "
				 "different than '%s'\n",
				 zone_name);
		knot_zone_deep_free(dst);
		ret = KNOT_EZONEINVAL;
	} else {
		/* Save the timestamp from the zone db file. */
		struct stat st;
		if (stat(source, &st) < 0) {
			dbg_zones("zones: failed to stat() zone db, "
				  "something is seriously wrong\n");
			knot_zone_deep_free(dst);
			ret = KNOT_EZONEINVAL;
		} else {
			knot_zone_set_version(*dst, st.st_mtime);
		}
	}
	knot_dname_free(&dname_req);
	knot_zload_close(zl);
	return ret;
}

/*----------------------------------------------------------------------------*/

/*! \brief Return 'serial_from' part of the key. */
static inline uint32_t ixfrdb_key_from(uint64_t k)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Least significant 32 bits.
	 */
	return (uint32_t)(k & ((uint64_t)0x00000000ffffffff));
}

/*----------------------------------------------------------------------------*/

/*! \brief Return 'serial_to' part of the key. */
static inline uint32_t ixfrdb_key_to(uint64_t k)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Most significant 32 bits.
	 */
	return (uint32_t)(k >> (uint64_t)32);
}

/*----------------------------------------------------------------------------*/

/*! \brief Compare function to match entries with target serial. */
static inline int ixfrdb_key_to_cmp(uint64_t k, uint64_t to)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Most significant 32 bits.
	 */
	return ((uint64_t)ixfrdb_key_to(k)) - to;
}

/*----------------------------------------------------------------------------*/

/*! \brief Compare function to match entries with starting serial. */
static inline int ixfrdb_key_from_cmp(uint64_t k, uint64_t from)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 * Need: Least significant 32 bits.
	 */
	return ((uint64_t)ixfrdb_key_from(k)) - from;
}

/*----------------------------------------------------------------------------*/

/*! \brief Make key for journal from serials. */
static inline uint64_t ixfrdb_key_make(uint32_t from, uint32_t to)
{
	/*      64    32       0
	 * key = [TO   |   FROM]
	 */
	return (((uint64_t)to) << ((uint64_t)32)) | ((uint64_t)from);
}

/*----------------------------------------------------------------------------*/

int zones_changesets_from_binary(knot_changesets_t *chgsets)
{
	/*! \todo #1291 Why doesn't this just increment stream ptr? */

	assert(chgsets != NULL);
	assert(chgsets->allocated >= chgsets->count);
	/*
	 * Parses changesets from the binary format stored in chgsets->data
	 * into the changeset_t structures.
	 */
	knot_rrset_t *rrset = 0;
	int ret = 0;

	for (int i = 0; i < chgsets->count; ++i) {

		/* Read changeset flags. */
		knot_changeset_t* chs = chgsets->sets + i;
		size_t remaining = chs->size;
		memcpy(&chs->flags, chs->data, sizeof(uint32_t));
		remaining -= sizeof(uint32_t);

		/* Read initial changeset RRSet - SOA. */
		uint8_t *stream = chs->data + (chs->size - remaining);
		ret = rrset_deserialize(stream, &remaining, &rrset);
		if (ret != KNOT_EOK) {
			dbg_xfr("xfr: SOA: failed to deserialize data "
			        "from changeset, %s\n", knot_strerror(ret));
			return KNOT_EMALF;
		}

		/* in this special case (changesets loaded
		 * from journal) the SOA serial should already
		 * be set, check it.
		 */
		dbg_xfr_verb("xfr: reading RRSets to REMOVE, first RR is %hu\n",
		             knot_rrset_type(rrset));
		assert(knot_rrset_type(rrset) == KNOT_RRTYPE_SOA);
		assert(chs->serial_from ==
		       knot_rrset_rdata_soa_serial(rrset));
		knot_changeset_store_soa(&chs->soa_from, &chs->serial_from,
					 rrset);

		/* Read remaining RRSets */
		int in_remove_section = 1;
		while (remaining > 0) {

			/* Parse next RRSet. */
			rrset = 0;
			stream = chs->data + (chs->size - remaining);
			ret = rrset_deserialize(stream, &remaining, &rrset);
			if (ret != KNOT_EOK) {
				dbg_xfr("xfr: failed to deserialize data "
				        "from changeset, %s\n",
				        knot_strerror(ret));
				return KNOT_EMALF;
			}

			/* Check for next SOA. */
			if (knot_rrset_type(rrset) == KNOT_RRTYPE_SOA) {

				/* Move to ADD section if in REMOVE. */
				if (in_remove_section) {
					knot_changeset_store_soa(
						&chgsets->sets[i].soa_to,
						&chgsets->sets[i].serial_to,
						rrset);
					dbg_xfr_verb("xfr: reading RRSets"
					             " to ADD\n");
					in_remove_section = 0;
				} else {
					/* Final SOA. */
					dbg_xfr_verb("xfr: extra SOA\n");
					knot_rrset_deep_free(&rrset, 1, 1);
					break;
				}
			} else {
				/* Remove RRSets. */
				if (in_remove_section) {
					ret = knot_changeset_add_rrset(
						&chgsets->sets[i].remove,
						&chgsets->sets[i].remove_count,
						&chgsets->sets[i]
						    .remove_allocated,
						rrset);
				} else {
				/* Add RRSets. */
					ret = knot_changeset_add_rrset(
						&chgsets->sets[i].add,
						&chgsets->sets[i].add_count,
						&chgsets->sets[i].add_allocated,
						rrset);
				}

				/* Check result. */
				if (ret != KNOT_EOK) {
					dbg_xfr("xfr: failed to add/remove "
					        "RRSet to changeset: %s\n",
					        knot_strerror(ret));
					return KNOT_ERROR;
				}
			}
		}

		dbg_xfr_verb("xfr: read all RRSets in changeset\n");
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_load_changesets(const knot_zone_t *zone,
                                 knot_changesets_t *dst,
                                 uint32_t from, uint32_t to)
{
	if (!zone || !dst) {
		dbg_zones_detail("Bad arguments: zone=%p, dst=%p\n", zone, dst);
		return KNOT_EINVAL;
	}
	if (!zone->data) {
		dbg_zones_detail("Bad arguments: zone->data=%p\n", zone->data);
		return KNOT_EINVAL;
	}

	/* Fetch zone-specific data. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd->ixfr_db) {
		dbg_zones_detail("Bad arguments: zd->ixfr_db=%p\n", zone->data);
		return KNOT_EINVAL;
	}

	rcu_read_lock();
	/* Check journal file existence. */
	struct stat st;
	if (stat(zd->conf->ixfr_db, &st) == -1) {
		rcu_read_unlock();
		return KNOT_ERANGE; /* Not existent, no changesets available. */
	}
	dbg_xfr("xfr: loading changesets for zone '%s' from serial %u to %u\n",
	        zd->conf->name, from, to);
	rcu_read_unlock();

	/* Retain journal for changeset loading. */
	journal_t *j = journal_retain(zd->ixfr_db);
	if (j == NULL) {
		return KNOT_EBUSY;
	}

	/* Read entries from starting serial until finished. */
	uint32_t found_to = from;
	journal_node_t *n = 0;
	int ret = journal_fetch(j, from, ixfrdb_key_from_cmp, &n);
	if (ret != KNOT_EOK) {
		dbg_xfr("xfr: failed to fetch starting changeset: %s\n",
		        knot_strerror(ret));
		journal_release(j);
		return ret;
	}

	while (n != 0 && n != journal_end(j)) {

		/* Check for history end. */
		if (to == found_to) {
			break;
		}

		/*! \todo Increment and decrement to reserve +1,
		 *        but not incremented counter.*/
		/* Check changesets size if needed. */
		++dst->count;
		ret = knot_changesets_check_size(dst);
		--dst->count;
		if (ret != KNOT_EOK) {
			//--dst->count;
			dbg_xfr("xfr: failed to check changesets size: %s\n",
			        knot_strerror(ret));
			journal_release(j);
			return KNOT_ERROR;
		}

		/* Skip wrong changesets. */
		if (!(n->flags & JOURNAL_VALID) || n->flags & JOURNAL_TRANS) {
			++n;
			continue;
		}

		/* Initialize changeset. */
		dbg_xfr_detail("xfr: reading entry #%zu id=%llu\n",
		               dst->count, (unsigned long long)n->id);
		knot_changeset_t *chs = dst->sets + dst->count;
		chs->serial_from = ixfrdb_key_from(n->id);
		chs->serial_to = ixfrdb_key_to(n->id);
		chs->data = malloc(n->len);
		if (!chs->data) {
			journal_release(j);
			return KNOT_ENOMEM;
		}

		/* Read journal entry. */
		ret = journal_read_node(j, n, (char*)chs->data);
		if (ret != KNOT_EOK) {
			dbg_xfr("xfr: failed to read data from journal\n");
			free(chs->data);
			journal_release(j);
			return KNOT_ERROR;
		}

		/* Update changeset binary size. */
		chs->size = chs->allocated = n->len;

		/* Next node. */
		found_to = chs->serial_to;
		++dst->count;
		++n;

		/*! \todo Check consistency. */
	}

	dbg_xfr_detail("xfr: finished reading journal entries\n");
	journal_release(j);

	/* Unpack binary data. */
	int unpack_ret = zones_changesets_from_binary(dst);
	if (unpack_ret != KNOT_EOK) {
		dbg_xfr("xfr: failed to unpack changesets "
		        "from binary, %s\n", knot_strerror(unpack_ret));
		return unpack_ret;
	}

	/* Check for complete history. */
	if (to != found_to) {
		dbg_xfr_detail("xfr: load changesets finished, ERANGE\n");
		return KNOT_ERANGE;
	}

	/* History reconstructed. */
	dbg_xfr_detail("xfr: load changesets finished, EOK\n");
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Apply changesets to zone from journal.
 *
 * \param zone Specified zone.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOENT if zone has no contents.
 * \retval KNOT_ERROR on unspecified error.
 */
static int zones_journal_apply(knot_zone_t *zone)
{
	/* Fetch zone. */
	if (!zone) {
		return KNOT_EINVAL;
	}

	rcu_read_lock();

	knot_zone_contents_t *contents = knot_zone_get_contents(zone);
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!contents || !zd) {
		rcu_read_unlock();
		return KNOT_ENOENT;
	}

	/* Fetch SOA serial. */
	const knot_rrset_t *soa_rrs = 0;
	soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
	                            KNOT_RRTYPE_SOA);
	assert(soa_rrs != NULL);
	int64_t serial_ret = knot_rrset_rdata_soa_serial(soa_rrs);
	if (serial_ret < 0) {
		rcu_read_unlock();
		return KNOT_EINVAL;
	}
	uint32_t serial = (uint32_t)serial_ret;

	/* Load all pending changesets. */
	dbg_zones_verb("zones: loading all changesets of '%s' from SERIAL %u\n",
	               zd->conf->name, serial);
	knot_changesets_t* chsets = malloc(sizeof(knot_changesets_t));
	memset(chsets, 0, sizeof(knot_changesets_t));
	/*! \todo Check what should be the upper bound. */
	int ret = zones_load_changesets(zone, chsets, serial, serial - 1);
	if (ret == KNOT_EOK || ret == KNOT_ERANGE) {
		if (chsets->count > 0) {
			/* Apply changesets. */
			log_server_info("Applying '%zu' changesets from journal "
			                "to zone '%s'.\n",
			                chsets->count, zd->conf->name);
			knot_zone_contents_t *contents = NULL;
			int apply_ret = xfrin_apply_changesets(zone, chsets,
			                                       &contents);
			if (apply_ret != KNOT_EOK) {
				log_server_error("Failed to apply changesets to"
				                 " '%s' - Apply failed: %s\n",
				                 zd->conf->name,
				                 knot_strerror(apply_ret));
				ret = KNOT_ERROR;

				// Cleanup old and new contents
				xfrin_rollback_update(zone->contents,
				                      &contents,
				                      &chsets->changes);
			} else {
				/* Switch zone immediately. */
				log_server_info("Zone '%s' serial %u -> %u.\n",
				                zd->conf->name,
				                serial, knot_zone_serial(contents));
				rcu_read_unlock();
				apply_ret = xfrin_switch_zone(zone, contents,
							      XFR_TYPE_IIN);
				rcu_read_lock();
				if (apply_ret == KNOT_EOK) {
					xfrin_cleanup_successful_update(
							&chsets->changes);
				} else {
					log_server_error("Failed to apply "
					  "changesets to '%s' - Switch failed: "
					  "%s\n", zd->conf->name,
					  knot_strerror(apply_ret));
					ret = KNOT_ERROR;

					// Cleanup old and new contents
					xfrin_rollback_update(zone->contents,
					                      &contents,
					                      &chsets->changes);
				}
			}
		}
	} else {
		dbg_zones("zones: failed to load changesets - %s\n",
		          knot_strerror(ret));
	}

	/* Free changesets and return. */
	rcu_read_unlock();
	knot_free_changesets(&chsets);
	return ret;
}

/*!
 * \brief Insert new zone to the database.
 *
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param z Zone configuration.
 * \param dst Used for returning new/updated zone.
 * \param ns Name server instance.
 * \param db_old Old zone database.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_ENOENT if zone has no contents.
 * \retval KNOT_ERROR on unspecified error.
 */
static int zones_insert_zone(conf_zone_t *z, knot_zone_t **dst,
                             knot_nameserver_t *ns)
{
	if (z == NULL || dst == NULL || ns == NULL) {
		return KNOT_EINVAL;
	}

	/* Convert the zone name into a domain name. */
	/* Local allocation, will be discarded. */
	knot_dname_t *dname = knot_dname_new_from_str(z->name, strlen(z->name),
	                                              NULL);
	if (dname == NULL) {
		log_server_error("Error creating domain name from zone"
		                 " name\n");
		return KNOT_EINVAL;
	}

	/* Try to find the zone in the current zone db, doesn't need RCU. */
	knot_zone_t *zone = knot_zonedb_find_zone(ns->zone_db, dname);

	/* Attempt to bootstrap if db or source does not exist. */
	int ret = KNOT_ERROR;
	int zone_changed = 0;
	struct stat st_zone;
	int stat_ret = stat(z->file, &st_zone);
	if (zone != NULL) {
		if (stat_ret == 0 && knot_zone_version(zone) < st_zone.st_mtime) {
			zone_changed = 1;
		}
	} else {
		zone_changed = 1;
	}

	/* Reload zone file. */
	if (zone_changed) {
		/* Zone file not exists and has master set. */
		if (stat_ret < 0 && !EMPTY_LIST(z->acl.xfr_in)) {

			/* Create stub database. */
			dbg_zones_verb("zones: loading stub zone '%s' "
			               "for bootstrap.\n",
			               z->name);
			knot_dname_t *owner = knot_dname_deep_copy(dname);
			zone = knot_zone_new_empty(owner);
			if (zone != NULL) {
				ret = KNOT_EOK;
			} else {
				dbg_zones("zones: failed to create "
				          "stub zone '%s'.\n", z->name);
				ret = KNOT_ERROR;
			}
		} else {
			dbg_zones_verb("zones: loading zone '%s'\n", z->name);
			ret = zones_load_zone(&zone, z->name, z->file,
			                      z->enable_checks);
			const knot_node_t *apex = NULL;
			const knot_rrset_t *soa = NULL;
			if (ret == KNOT_EOK) {
				apex = knot_zone_contents_apex(
					knot_zone_contents(zone));
				soa = knot_node_rrset(apex,
					KNOT_RRTYPE_SOA);
				int64_t sn = 0;
				if (apex && soa) {
					sn = knot_rrset_rdata_soa_serial(soa);
					if (sn < 0) sn = 0;
				}
				log_server_info("Loaded zone '%s' serial %u\n",
				                z->name, (uint32_t)sn);
			}
		}

		/* Evaluate. */
		if (ret == KNOT_EOK && zone != NULL) {
			dbg_zones_verb("zones: inserted '%s' into "
			               "database, initializing data\n",
			               z->name);

			/* Initialize zone-related data. */
			zonedata_init(z, zone);
			*dst = zone;
		}
	} else {
		dbg_zones_verb("zones: found '%s' in old database, "
		               "copying to new.\n", z->name);
		if (stat_ret == 0) {
			log_server_info("Zone '%s' is up-to-date, no need "
			                "for reload.\n", z->name);
		}
		*dst = zone;
		ret = KNOT_EOK;
	}

	/* Update zone data. */
	if (zone != NULL) {
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		assert(zd != NULL);

		/* Update refs. */
		if (zd->conf != z) {
			conf_free_zone(zd->conf);
			zd->conf = z;
		}

		/* Update ACLs. */
		dbg_zones("Updating zone ACLs.\n");
		zones_set_acl(&zd->xfr_in.acl, &z->acl.xfr_in);
		zones_set_acl(&zd->xfr_out, &z->acl.xfr_out);
		zones_set_acl(&zd->notify_in, &z->acl.notify_in);
		zones_set_acl(&zd->notify_out, &z->acl.notify_out);
		zones_set_acl(&zd->update_in, &z->acl.update_in);

		/* Update server pointer. */
		zd->server = (server_t *)knot_ns_get_data(ns);

		/* Update master server address. */
		zd->xfr_in.has_master = 0;
		memset(&zd->xfr_in.tsig_key, 0, sizeof(knot_tsig_key_t));
		sockaddr_init(&zd->xfr_in.master, -1);
		sockaddr_init(&zd->xfr_in.via, -1);
		if (!EMPTY_LIST(z->acl.xfr_in)) {
			conf_remote_t *r = HEAD(z->acl.xfr_in);
			conf_iface_t *cfg_if = r->remote;
			sockaddr_set(&zd->xfr_in.master,
				     cfg_if->family,
				     cfg_if->address,
				     cfg_if->port);
			if (sockaddr_isvalid(&cfg_if->via)) {
				sockaddr_copy(&zd->xfr_in.via,
				              &cfg_if->via);
			}
			zd->xfr_in.has_master = 1;

			if (cfg_if->key) {
				memcpy(&zd->xfr_in.tsig_key,
				       cfg_if->key,
				       sizeof(knot_tsig_key_t));
			}

			dbg_zones("zones: using '%s@%d' as XFR master "
			          "for '%s'\n",
			          cfg_if->address,
			          cfg_if->port,
			          z->name);
		}

		/* Apply changesets from journal. */
		int ar = zones_journal_apply(zone);
		if (ar != KNOT_EOK && ar != KNOT_ERANGE && ar != KNOT_ENOENT) {
			log_server_warning("Failed to apply changesets "
			                   "for zone '%s': %s\n",
			                   z->name, knot_strerror(ar));
		}

		/* Schedule IXFR database syncing. */
		/*! \note This has to remain separate as it must not be
		 *        triggered by a zone update or SOA response.
		 */
		/* Fetch zone data. */
		evsched_t *sch = ((server_t *)knot_ns_get_data(ns))->sched;
		int sync_tmr = z->dbsync_timeout * 1000; /* s -> ms. */
		if (zd->ixfr_dbsync != NULL) {
			evsched_cancel(sch, zd->ixfr_dbsync);
			evsched_event_free(sch, zd->ixfr_dbsync);
			zd->ixfr_dbsync = NULL;
		}
		if (zd->ixfr_db != NULL) {
			zd->ixfr_dbsync = evsched_schedule_cb(
			                    sch, zones_zonefile_sync_ev,
			                    zone, sync_tmr);
			dbg_zones("zone: journal sync of '%s' "
			          "set to %d\n", z->name, sync_tmr);
		}

		/* Update ANY queries policy */
		if (zd->conf->disable_any) {
			rcu_read_lock();
			knot_zone_contents_t *contents =
			                knot_zone_get_contents(zone);

			/*! \todo This is actually updating zone contents.
			 *        It should be done in thread-safe way.
			 */
			if (contents) {
				knot_zone_contents_disable_any(contents);
			}

			rcu_read_unlock();
		}

		/* Calculate differences. */
		rcu_read_lock();
		knot_zone_t *z_old = knot_zonedb_find_zone(ns->zone_db,
		                                              dname);
		/* Ensure both new and old have zone contents. */
		knot_zone_contents_t *zc = knot_zone_get_contents(zone);
		knot_zone_contents_t *zc_old = knot_zone_get_contents(z_old);
		if (z->build_diffs && zc != NULL && zc_old != NULL && zone_changed) {
			int bd = zones_create_and_save_changesets(z_old, zone);
			if (bd == KNOT_ENODIFF) {
				log_zone_warning("Zone file for '%s' changed, "
				                 "but serial didn't - "
				                 "won't create changesets.\n",
				                 z->name);
			} else if (bd != KNOT_EOK) {
				log_zone_warning("Failed to calculate differences"
				                 " from the zone file update: "
				                 "%s\n", knot_strerror(bd));
			}
		}
		rcu_read_unlock();
	}

	/* CLEANUP */
//	knot_zone_contents_dump(knot_zone_get_contents(zone), 1);

	/* Directly discard zone. */
	knot_dname_free(&dname);
	return ret;
}

/*! \brief Structure for multithreaded zone loading. */
struct zonewalk_t {
	knot_nameserver_t *ns;
	knot_zonedb_t *db_new;
	pthread_mutex_t lock;
	int inserted;
	unsigned qhead;
	unsigned qtail;
	conf_zone_t *q[];

};

/*! Thread entrypoint for loading zones. */
static int zonewalker(dthread_t *thread)
{
	if (thread == NULL) {
		return KNOT_ERROR;
	}

	struct zonewalk_t *zw = (struct zonewalk_t *)thread->data;
	if (zw == NULL) {
		return KNOT_ERROR;
	}

	unsigned i = 0;
	int inserted = 0;
	knot_zone_t **zones = NULL;
	size_t allocd = 0;
	for(;;) {
		/* Fetch queue head. */
		pthread_mutex_lock(&zw->lock);
		i = zw->qhead++;
		pthread_mutex_unlock(&zw->lock);
		if (i >= zw->qtail) {
			break;
		}

		if (mreserve((char **)&zones, sizeof(knot_zone_t*),
		             inserted + 1, 32, &allocd) < 0) {
			dbg_zones("zones: failed to reserve space for "
			          "loading zones\n");
			continue;
		}

		int ret = zones_insert_zone(zw->q[i], zones + inserted, zw->ns);
		if (ret == KNOT_EOK) {
			++inserted;
		}
	}

	/* Collect results. */
	pthread_mutex_lock(&zw->lock);
	zw->inserted += inserted;
	for (int i = 0; i < inserted; ++i) {
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zones[i]);
		if (knot_zonedb_add_zone(zw->db_new, zones[i]) != KNOT_EOK) {
			log_server_error("Failed to insert zone '%s' "
			                 "into database.\n", zd->conf->name);
			/* Not doing this here would result in memory errors. */
			rem_node(&zd->conf->n);
			knot_zone_deep_free(zones + i);
		} else {
			/* Unlink zone config from conf(),
			 * transferring ownership to zonedata. */
			rem_node(&zd->conf->n);
		}
	}
	pthread_mutex_unlock(&zw->lock);
	free(zones);

	return KNOT_EOK;
}

/*!
 * \brief Fill the new database with zones.
 *
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param ns Name server instance.
 * \param zone_conf Zone configuration.
 * \param db_new New zone database.
 *
 * \return Number of inserted zones.
 */
static int zones_insert_zones(knot_nameserver_t *ns,
                              const list *zone_conf,
                              knot_zonedb_t *db_new)
{
	int ret = 0;
	size_t zcount = 0;
	conf_zone_t *z = NULL;
	WALK_LIST(z, *zone_conf) {
		++zcount;
	}
	if (zcount == 0)
		return 0;

	/* Initialize zonewalker. */
	size_t zwlen = sizeof(struct zonewalk_t) + zcount * sizeof(conf_zone_t*);
	struct zonewalk_t *zw = malloc(zwlen);
	if (zw == NULL) {
		return KNOT_ENOMEM;
	}
	memset(zw, 0, zwlen);
	zw->ns = ns;
	zw->db_new = db_new;
	zw->inserted = 0;
	if (pthread_mutex_init(&zw->lock, NULL) < 0) {
		free(zw);
		return KNOT_ENOMEM;
	}
	unsigned i = 0;
	WALK_LIST(z, *zone_conf) {
		zw->q[i++] = z;
	}
	zw->qhead = 0;
	zw->qtail = zcount;

	/* Initialize threads. */
	size_t thrs = dt_optimal_size();
	if (thrs > zcount) thrs = zcount;
	dt_unit_t *unit =  dt_create_coherent(thrs, &zonewalker, zw);
	if (unit != NULL) {
		/* Start loading. */
		dt_start(unit);
		dt_join(unit);
		dt_delete(&unit);

		/* Collect counts. */
		ret = zw->inserted;
	} else {
		ret = KNOT_ENOMEM;
	}

	pthread_mutex_destroy(&zw->lock);
	free(zw);
	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Remove zones present in the configuration from the old database.
 *
 * After calling this function, the old zone database should contain only zones
 * that should be completely deleted.
 *
 * \param zone_conf Zone configuration.
 * \param db_old Old zone database to remove zones from.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
static int zones_remove_zones(const knot_zonedb_t *db_new,
                              knot_zonedb_t *db_old)
{
	hattrie_iter_t *i = hattrie_iter_begin(db_new->zone_tree, 0);
	while(!hattrie_iter_finished(i)) {

		/* try to find the new zone in the old DB
		 * if the pointers match, remove the zone from old DB
		 */
		/*! \todo Find better way of removing zone with given pointer.*/
		knot_zone_t *new_zone = (knot_zone_t *)(*hattrie_iter_val(i));
		knot_zone_t *old_zone = knot_zonedb_find_zone(
		                        db_old, knot_zone_name(new_zone));
		if (old_zone == new_zone) {
dbg_zones_exec(
			char *name = knot_dname_to_str(knot_zone_name(old_zone));
			dbg_zones_verb("zones: zone pointers match, removing zone %s "
                                       "from database.\n", name);
			free(name);
);

			/* Remove from zone db. */
			knot_zone_t * rm = knot_zonedb_remove_zone(db_old,
			                              knot_zone_name(old_zone));
			assert(rm == old_zone);
		}
		hattrie_iter_next(i);
	}

	hattrie_iter_free(i);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_check_tsig_query(const knot_zone_t *zone,
                                  knot_packet_t *query,
                                  const sockaddr_t *addr,
                                  knot_rcode_t *rcode,
                                  uint16_t *tsig_rcode,
                                  knot_tsig_key_t **tsig_key_zone,
                                  uint64_t *tsig_prev_time_signed)
{
	assert(zone != NULL);
	assert(query != NULL);
	assert(rcode != NULL);
	assert(tsig_key_zone != NULL);

	// if there is some TSIG in the query, find the TSIG associated with
	// the zone
	dbg_zones_verb("Checking zone and ACL.\n");
	int ret = zones_query_check_zone(zone, knot_packet_opcode(query),
	                                 addr, tsig_key_zone, rcode);


	/* Accept found OR unknown key results. */
	if (ret == KNOT_EOK || ret == KNOT_EACCES) {
		if (*tsig_key_zone != NULL) {
			// everything OK, so check TSIG
			dbg_zones_verb("Verifying TSIG.\n");
			ret = zones_verify_tsig_query(query, *tsig_key_zone,
			                              rcode, tsig_rcode,
			                              tsig_prev_time_signed);
		} else {
			dbg_zones_verb("No key configured for zone.\n");
			if (knot_packet_tsig(query)) {
				// no key configured for zone, return BADKEY
				dbg_zones_verb("TSIG used, but not configured "
				               "for this zone, ret=BADKEY.\n");
				*tsig_rcode = KNOT_RCODE_BADKEY;
				*rcode = KNOT_RCODE_NOTAUTH;
				ret = KNOT_TSIG_EBADKEY;
			}
		}
	}

	// save TSIG RR to query structure
//	knot_packet_set_tsig(query, tsig);

	return ret;
}

static int zones_update_forward(int fd, knot_ns_transport_t ttype,
                                knot_zone_t *zone, const sockaddr_t *from,
                                knot_packet_t *query, size_t qsize)
{
	rcu_read_lock();

	/* Check transport type. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	unsigned flags = XFR_FLAG_UDP;
	if (ttype == NS_TRANSPORT_TCP) {
		flags = XFR_FLAG_TCP;
	}

	/* Prepare task. */
	knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_FORWARD, flags);
	if (!rq) {
		rcu_read_unlock();
		return KNOT_ENOMEM;
	}
	xfr_task_setaddr(rq, &zd->xfr_in.master, &zd->xfr_in.via);

	/* Copy query originator data. */
	rq->fwd_src_fd = fd;
	memcpy(&rq->fwd_addr, from, sizeof(sockaddr_t));
	rq->packet_nr = (int)knot_packet_id(query);

	/* Duplicate query to keep it in memory during forwarding. */
	rq->query = knot_packet_new(KNOT_PACKET_PREALLOC_QUERY);
	if (!rq->query) {
		xfr_task_free(rq);
		rcu_read_unlock();
		return KNOT_ENOMEM;
	}
	rq->query->size = knot_packet_size(query);
	rq->query->wireformat = malloc(rq->query->size);
	if (!rq->query->wireformat) {
		knot_packet_free(&rq->query);
		xfr_task_free(rq);
		rcu_read_unlock();
		return KNOT_ENOMEM;
	}
	rq->query->free_wireformat = 1;
	memcpy(rq->query->wireformat, query->wireformat, knot_packet_size(query));

	/* Retain pointer to zone and issue. */
	rcu_read_unlock();
	int ret = xfr_enqueue(zd->server->xfr, rq);
	if (ret != KNOT_EOK) {
		xfr_task_free(rq);
	}

	return KNOT_EOK;
}



/*----------------------------------------------------------------------------*/

static int zones_store_changesets_to_disk(knot_zone_t *zone,
                                          knot_changesets_t *chgsets)
{
	journal_t *journal = zones_store_changesets_begin(zone);
	if (journal == NULL) {
		dbg_zones("zones: create_changesets: "
		          "Could not start journal operation.\n");
		return KNOT_ERROR;
	}

	int ret = zones_store_changesets(zone, chgsets, journal);
	if (ret != KNOT_EOK) {
		zones_store_changesets_rollback(journal);
		dbg_zones("zones: create_changesets: "
		          "Could not store in the journal. Reason: %s.\n",
		          knot_strerror(ret));

		return ret;
	}

	ret = zones_store_changesets_commit(journal);
	if (ret != KNOT_EOK) {
		dbg_zones("zones: create_changesets: "
		          "Could not commit to journal. Reason: %s.\n",
		          knot_strerror(ret));

		return ret;
	}

	return KNOT_EOK;
}

/*! \brief Process UPDATE query.
 *
 * Functions expects that the query is already authenticated
 * and TSIG signature is verified.
 *
 * \note Set parameter 'rcode' according to answering procedure.
 * \note Function expects RCU to be locked.
 *
 * \retval KNOT_EOK if successful.
 * \retval error if not.
 */
static int zones_process_update_auth(knot_zone_t *zone,
                                     knot_packet_t *resp,
                                     uint8_t *resp_wire, size_t *rsize,
                                     knot_rcode_t *rcode,
                                     const sockaddr_t *addr,
                                     knot_tsig_key_t *tsig_key)
{
	int ret = KNOT_EOK;
	dbg_zones_verb("TSIG check successful. Answering query.\n");

	/* Create log message prefix. */
	char *keytag = NULL;
	if (tsig_key) {
		keytag = knot_dname_to_str(tsig_key->name);
	}
	char *r_str = xfr_remote_str(addr, keytag);
	const char *zone_name = ((zonedata_t*)knot_zone_data(zone))->conf->name;
	char *msg  = sprintf_alloc("UPDATE of '%s' from %s",
	                           zone_name, r_str ? r_str : "'unknown'");
	free(r_str);
	free(keytag);
	log_zone_info("%s Started.\n", msg);


	/* Reserve place for the TSIG */
	if (tsig_key != NULL) {
		size_t tsig_max_size = tsig_wire_maxsize(tsig_key);
		knot_packet_set_tsig_size(resp, tsig_max_size);
	}

	/* We must prepare a changesets_t structure even if
	 * there is only one changeset - because of the API. */
	knot_changesets_t *chgsets = NULL;
	ret = knot_changeset_allocate(&chgsets, KNOT_CHANGESET_TYPE_DDNS);
	if (ret != KNOT_EOK) {
		*rcode = KNOT_RCODE_SERVFAIL;
		log_zone_error("%s %s\n", msg, knot_strerror(ret));
		free(msg);
		return ret;
	}

	assert(chgsets->allocated >= 1);

	/*
	 * NEW DDNS PROCESSING -------------------------------------------------
	 */
	/* 1) Process the UPDATE packet, apply to zone, create changesets. */

	dbg_zones_verb("Processing UPDATE packet.\n");
	chgsets->count = 1; /* DU is represented by a single chset. */
	*rcode = KNOT_RCODE_SERVFAIL; /* SERVFAIL unless it applies correctly. */

	knot_zone_contents_t *new_contents = NULL;
	ret = knot_ns_process_update2(knot_packet_query(resp),
	                              knot_zone_get_contents(zone),
	                              &new_contents,
	                              chgsets, rcode);

	if (ret != KNOT_EOK) {
		if (ret < 0) {
			log_zone_error("%s %s\n", msg, knot_strerror(ret));
		} else {
			log_zone_notice("%s No change to zone made.\n", msg);
			knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
			uint8_t *tmp_wire = NULL;
			ret = knot_packet_to_wire(resp, &tmp_wire, rsize);
			if (ret == KNOT_EOK) {
				memcpy(resp_wire, tmp_wire, *rsize);
				*rcode = KNOT_RCODE_NOERROR;
			}
		}

		knot_free_changesets(&chgsets);
		free(msg);
		return (ret < 0) ? ret : KNOT_EOK;
	}

	/* 2) Store changesets, (TODO: but do not commit???). */
	ret = zones_store_changesets_to_disk(zone, chgsets);
	if (ret != KNOT_EOK) {
		log_zone_error("%s %s\n", msg, knot_strerror(ret));
		xfrin_rollback_update(zone->contents, &new_contents,
		                      &chgsets->changes);
		knot_free_changesets(&chgsets);
		free(msg);
		return ret;
	}

	/* 3) Switch zone contents. */
	knot_zone_retain(zone); /* Retain pointer for safe RCU unlock. */
	rcu_read_unlock();      /* Unlock for switch. */
	ret = xfrin_switch_zone(zone, new_contents, XFR_TYPE_UPDATE);
	rcu_read_lock();        /* Relock */
	knot_zone_release(zone);/* Release held pointer. */

	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to replace current zone - %s\n",
		               msg, knot_strerror(ret));
		// Cleanup old and new contents
		xfrin_rollback_update(zone->contents, &new_contents,
		                      &chgsets->changes);

		/* Free changesets, but not the data. */
		knot_free_changesets(&chgsets);
		return KNOT_ERROR;
	}

	/* 4) Cleanup. */

	xfrin_cleanup_successful_update(&chgsets->changes);

	/* Free changesets, but not the data. */
	knot_free_changesets(&chgsets);
	assert(ret == KNOT_EOK);
	*rcode = KNOT_RCODE_NOERROR; /* Mark as successful. */
	log_zone_info("%s Finished.\n", msg);

	free(msg);
	msg = NULL;

	/*
	 * \NEW DDNS PROCESSING ------------------------------------------------
	 */


//	/* 1) Process the incoming packet, prepare
//	 *    prerequisities and changeset.
//	 */
//	dbg_zones_verb("Processing UPDATE packet.\n");
//	chgsets->count = 1; /* DU is represented by a single chset. */
//	ret = knot_ns_process_update(knot_packet_query(resp),
//				     knot_zone_contents(zone),
//				     &chgsets->sets[0], rcode);

//	if (ret != KNOT_EOK) {
//		log_zone_error("%s %s\n", msg, knot_strerror(ret));
//		knot_free_changesets(&chgsets);
//		free(msg);
//		return ret;
//	}

//	/* 2) Save changeset to journal.
//	 *    Apply changeset to zone.
//	 *    Commit changeset to journal.
//	 *    Switch the zone.
//	 */
//	knot_zone_contents_t *contents_new = NULL;
//	knot_zone_retain(zone); /* Retain pointer for safe RCU unlock. */
//	rcu_read_unlock();      /* Unlock for switch. */
//	dbg_zones_verb("Storing and applying changesets.\n");
//	ret = zones_store_and_apply_chgsets(chgsets, zone, &contents_new, msg,
//					    XFR_TYPE_UPDATE);
//	rcu_read_lock();        /* Relock */
//	knot_zone_release(zone);/* Release held pointer. */
//	free(msg);
//	msg = NULL;

//	/* Changesets should be freed by now. */
//	if (ret != KNOT_EOK) {
//		dbg_zones_verb("Storing and applying changesets failed: %s.\n",
//			       knot_strerror(ret));
//		*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
//		                             : KNOT_RCODE_SERVFAIL;
//		return ret;
//	}

	/* 3) Prepare DDNS response. */
	assert(*rcode == KNOT_RCODE_NOERROR);
	dbg_zones_verb("Preparing NOERROR UPDATE response RCODE=%u "
		       "pkt=%p resp_wire=%p\n", *rcode, resp, resp_wire);
	knot_response_set_rcode(resp, KNOT_RCODE_NOERROR);
	uint8_t *tmp_wire = NULL;
	ret = knot_packet_to_wire(resp, &tmp_wire, rsize);
	if (ret != KNOT_EOK) {
		dbg_zones("DDNS failed to write pkt to wire (%s). Size %zu\n",
			  knot_strerror(ret), *rsize);
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	} else {
		/* This is strange, but the knot_packet_to_wire() can't write
		 * to already existing buffer. */
		memcpy(resp_wire, tmp_wire, *rsize);
	}

	dbg_zones("DDNS reply rsize = %zu\n", *rsize);


	return ret;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int zones_update_db_from_config(const conf_t *conf, knot_nameserver_t *ns,
                               knot_zonedb_t **db_old)
{
	/* Check parameters */
	if (conf == NULL || ns == NULL) {
		return KNOT_EINVAL;
	}

	/* Lock RCU to ensure none will deallocate any data under our hands. */
	rcu_read_lock();

	/* Grab a pointer to the old database */
	if (ns->zone_db == NULL) {
		rcu_read_unlock();
		log_server_error("Missing zone database in nameserver structure"
		                 ".\n");
		return KNOT_ERROR;
	}
	rcu_read_unlock();

	/* Create new zone DB */
	knot_zonedb_t *db_new = knot_zonedb_new();
	if (db_new == NULL) {
		return KNOT_ERROR;
	}

	log_server_info("Loading %d zones...\n", conf->zones_count);

	/* Insert all required zones to the new zone DB. */
	/*! \warning RCU must not be locked as some contents switching will
	             be required. */
	int inserted = zones_insert_zones(ns, &conf->zones, db_new);
	if (inserted < 0) {
		log_server_warning("Failed to load zones - %s\n",
		                   knot_strerror(inserted));
		inserted = 0;
	}
	log_server_info("Loaded %d out of %d zones.\n", inserted,
	                conf->zones_count);

	if (inserted != conf->zones_count) {
		log_server_warning("Not all the zones were loaded.\n");
	}

	/* Lock RCU to ensure none will deallocate any data under our hands. */
	rcu_read_lock();
	*db_old = ns->zone_db;

	dbg_zones_detail("zones: old db in nameserver: %p, old db stored: %p, "
	                 "new db: %p\n", ns->zone_db, *db_old, db_new);

	/* Switch the databases. */
	UNUSED(rcu_xchg_pointer(&ns->zone_db, db_new));

	dbg_zones_detail("db in nameserver: %p, old db stored: %p, new db: %p\n",
	                 ns->zone_db, *db_old, db_new);

	/*
	 * Remove all zones present in the new DB from the old DB.
	 * No new thread can access these zones in the old DB, as the
	 * databases are already switched.
	 *
	 * Beware - only the exact same zones (same pointer) may be removed.
	 * All other have been loaded again so that the old must be destroyed.
	 */
	int ret = zones_remove_zones(db_new, *db_old);

	/* Heal zonedb index. */
	hattrie_build_index(db_new->zone_tree);

	/* Unlock RCU, messing with any data will not affect us now */
	rcu_read_unlock();

	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

int zones_zonefile_sync(knot_zone_t *zone, journal_t *journal)
{
	if (!zone) {
		return KNOT_EINVAL;
	}
	if (!zone->data) {
		return KNOT_EINVAL;
	}
	if (journal == NULL) {
		return KNOT_EINVAL;
	}

	/* Fetch zone data. */
	int ret = KNOT_EOK;
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Lock zone data. */
	pthread_mutex_lock(&zd->lock);

	/* Lock RCU for zone contents. */
	rcu_read_lock();

	knot_zone_contents_t *contents = knot_zone_get_contents(zone);
	if (!contents) {
		rcu_read_unlock();
		pthread_mutex_unlock(&zd->lock);
		return KNOT_EINVAL;
	}

	/* Latest zone serial. */
	const knot_rrset_t *soa_rrs = 0;
	soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
	                            KNOT_RRTYPE_SOA);
	assert(soa_rrs != NULL);

	int64_t serial_ret = knot_rrset_rdata_soa_serial(soa_rrs);
	if (serial_ret < 0) {
		rcu_read_unlock();
		pthread_mutex_unlock(&zd->lock);
		return KNOT_EINVAL;
	}
	uint32_t serial_to = (uint32_t)serial_ret;

	/* Check for difference against zonefile serial. */
	if (zd->zonefile_serial != serial_to) {

		/* Save zone to zonefile. */
		dbg_zones("zones: syncing '%s' differences to '%s' "
		          "(SOA serial %u)\n",
		          zd->conf->name, zd->conf->file, serial_to);
		ret = zones_dump_zone_text(contents, zd->conf->file);
		if (ret != KNOT_EOK) {
			log_zone_warning("Failed to apply differences "
			                 "'%s' to '%s'\n",
			                 zd->conf->name, zd->conf->file);
			rcu_read_unlock();
			pthread_mutex_unlock(&zd->lock);
			return ret;
		}

		/* Update journal entries. */
		dbg_zones_verb("zones: unmarking all dirty nodes "
		               "in '%s' journal\n",
		               zd->conf->name);
		journal_walk(journal, zones_ixfrdb_sync_apply);

		/* Update zone file serial. */
		dbg_zones("zones: new '%s' zonefile serial is %u\n",
		          zd->conf->name, serial_to);
		zd->zonefile_serial = serial_to;
	} else {
		dbg_zones("zones: '%s' zonefile is in sync "
		          "with differences\n", zd->conf->name);
		ret = KNOT_ERANGE;
	}

	/* Unlock RCU. */
	rcu_read_unlock();

	/* Unlock zone data. */
	pthread_mutex_unlock(&zd->lock);

	return ret;
}

/*----------------------------------------------------------------------------*/

int zones_query_check_zone(const knot_zone_t *zone, uint8_t q_opcode,
                           const sockaddr_t *addr, knot_tsig_key_t **tsig_key,
                           knot_rcode_t *rcode)
{
	if (addr == NULL || tsig_key == NULL || rcode == NULL) {
		dbg_zones_verb("Wrong arguments.\n");

		if (rcode != NULL) {
			*rcode = KNOT_RCODE_SERVFAIL;
		}
		return KNOT_EINVAL;
	}

	/* Check zone data. */
	const zonedata_t *zd = (const zonedata_t *)knot_zone_data(zone);
	if (zd == NULL) {
		dbg_zones("zones: invalid zone data for zone %p\n", zone);
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_ERROR;
	}

	/* Check ACL (xfr-out for xfers, update-in for DDNS) */
	acl_t *acl_used = zd->xfr_out;
	if (q_opcode == KNOT_OPCODE_UPDATE) {
		acl_used = zd->update_in;
	}
	acl_match_t *match = NULL;
	if ((match = acl_find(acl_used, addr)) == NULL) {
		*rcode = KNOT_RCODE_REFUSED;
		return KNOT_EACCES;
	} else {
		dbg_zones("zones: authorized query or request for "
		          "'%s %s'. match=%p\n", zd->conf->name,
		          q_opcode == KNOT_OPCODE_UPDATE ? "UPDATE":"XFR/OUT",
			  match);
		if (match->val) {
			/* Save configured TSIG key for comparison. */
			*tsig_key = ((conf_iface_t*)(match->val))->key;
		}
	}
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_xfr_check_zone(knot_ns_xfr_t *xfr, knot_rcode_t *rcode)
{
	if (xfr == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}

	/* Check if the zone is found. */
	if (xfr->zone == NULL) {
		*rcode = KNOT_RCODE_REFUSED;
		return KNOT_EACCES;
	}

	/* Check zone contents. */
	if (knot_zone_contents(xfr->zone) == NULL) {
		dbg_zones("zones: invalid zone contents for zone %p\n",
		          xfr->zone);
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_EEXPIRED;
	}

	return zones_query_check_zone(xfr->zone, KNOT_OPCODE_QUERY,
	                              &xfr->addr, &xfr->tsig_key,
	                              rcode);
}

/*----------------------------------------------------------------------------*/
/*! \todo This function is here only because TSIG key is associated with the
 *        zone via zonedata. If it was in the zone structure (which would be
 *        IMHO ok, this whole function could be moved to nameserver.c.
 */
int zones_normal_query_answer(knot_nameserver_t *nameserver,
                              knot_packet_t *query, const sockaddr_t *addr,
                              uint8_t *resp_wire, size_t *rsize,
                              knot_ns_transport_t transport)
{
	rcu_read_lock();

	knot_rcode_t rcode = 0;
	knot_packet_t *resp = NULL;
	const knot_zone_t *zone = NULL;
	const uint16_t qclass = knot_packet_qclass(query);

	dbg_zones_verb("Preparing response structure.\n");
	int ret = knot_ns_prep_normal_response(nameserver, query, &resp, &zone,
	                                       (transport == NS_TRANSPORT_TCP)
	                                       ? *rsize : 0);
	query->zone = zone;

	switch (ret) {
	case KNOT_EOK:
		rcode = KNOT_RCODE_NOERROR;
		break;
	case KNOT_EMALF:
		// no TSIG signing in this case
		rcode = KNOT_RCODE_FORMERR;
		break;
	default:
		// no TSIG signing in this case
		rcode = KNOT_RCODE_SERVFAIL;
		break;
	}

	if (rcode == KNOT_RCODE_NOERROR) {
		switch (qclass) {
		case KNOT_CLASS_IN:
		case KNOT_CLASS_CH:
		case KNOT_CLASS_ANY:
			break;
		default:
			rcode = KNOT_RCODE_REFUSED;
		}
	}

	if (rcode != KNOT_RCODE_NOERROR) {
		dbg_zones_verb("Failed preparing response structure: %s.\n",
		               knot_strerror(rcode));
		if (resp == NULL) {
			knot_ns_error_response_from_query(nameserver, query,
			                                  rcode, resp_wire,
			                                  rsize);
			rcu_read_unlock();
			return KNOT_EOK;
		}
		knot_ns_error_response_full(nameserver, resp, rcode, resp_wire,
		                            rsize);
	} else {
		/*
		 * Now we have zone. Verify TSIG if it is in the packet.
		 */
		assert(resp != NULL);
		assert(rcode == KNOT_RCODE_NOERROR);
		uint16_t tsig_rcode = 0;
		knot_tsig_key_t *tsig_key_zone = NULL;
		uint64_t tsig_prev_time_signed = 0;
		/*! \todo Verify, as it was uninitialized! */

		size_t answer_size = *rsize;
		int ret = KNOT_EOK;

		const knot_rrset_t *tsig = knot_packet_tsig(query);
		if (tsig != NULL) {
			dbg_zones_verb("Checking TSIG in query.\n");
			if (zone == NULL) {
				// treat as BADKEY error
				/*! \todo Is this OK?? */
				rcode = KNOT_RCODE_NOTAUTH;
				tsig_rcode = KNOT_RCODE_BADKEY;
				ret = KNOT_TSIG_EBADKEY;
			} else {
				ret = zones_check_tsig_query(zone, query, addr,
				      &rcode, &tsig_rcode, &tsig_key_zone,
				      &tsig_prev_time_signed);
			}
		}

		if (ret == KNOT_EOK) {
			dbg_zones_verb("TSIG check successful. Answering "
			               "query.\n");
			assert(tsig_rcode == 0);

			// reserve place for the TSIG
			if (tsig_key_zone != NULL) {
				size_t tsig_max_size =
				         tsig_wire_maxsize(tsig_key_zone);
				knot_packet_set_tsig_size(resp, tsig_max_size);
			}

			// handle IXFR queries
			if (knot_packet_qtype(query) == KNOT_RRTYPE_IXFR) {
				assert(transport == NS_TRANSPORT_UDP);
				ret = knot_ns_answer_ixfr_udp(nameserver, zone,
				                              resp, resp_wire,
				                              &answer_size);
			} else {
				if (qclass == KNOT_CLASS_CH) {
					ret = knot_ns_answer_chaos(nameserver,
					      resp, resp_wire, &answer_size);
				} else {
					ret = knot_ns_answer_normal(nameserver,
					      zone, resp, resp_wire, &answer_size,
					      transport == NS_TRANSPORT_UDP);
				}
				query->flags = resp->flags; /* Copy markers. */
			}

			dbg_zones_detail("rsize = %zu\n", *rsize);
			dbg_zones_detail("answer_size = %zu\n", answer_size);

			assert(ret == KNOT_EOK);

			// sign the message
			if (tsig_key_zone != NULL) {
				dbg_zones_verb("Signing message with TSIG.\n");
				// TODO check
				//*rsize = answer_size;

				const knot_rrset_t *tsig =
				      knot_packet_tsig(knot_packet_query(resp));

				size_t digest_max_size =
				                knot_tsig_digest_length(
				                      tsig_key_zone->algorithm);
				uint8_t *digest = (uint8_t *)malloc(
				                        digest_max_size);
				if (digest == NULL) {
					knot_packet_free(&resp);
					rcu_read_unlock();
					return KNOT_ENOMEM;
				}
				size_t digest_size = digest_max_size;

				ret = knot_tsig_sign(resp_wire, &answer_size,
				               *rsize, tsig_rdata_mac(tsig),
				               tsig_rdata_mac_length(tsig),
				               digest, &digest_size,
				               tsig_key_zone, tsig_rcode,
				               tsig_prev_time_signed);

				free(digest);

				dbg_zones_detail("answer_size = %zu\n",
				                 answer_size);

				if (ret != KNOT_EOK) {
					dbg_zones_verb("Failed to sign message:"
					            "%s\n", knot_strerror(ret));
					rcode = KNOT_RCODE_SERVFAIL;
				} else {
					*rsize = answer_size;
				}
			} else {
				*rsize = answer_size;
			}
		} else {
			dbg_zones_verb("Failed TSIG check: %s, TSIG err: %u.\n",
			               knot_strerror(ret), tsig_rcode);

			if (tsig_rcode != 0) {
				dbg_zones_verb("Sending TSIG error.\n");
				// first, convert the response to wire format
				answer_size = *rsize;
				knot_response_set_rcode(resp, rcode);

				ret = ns_response_to_wire(resp, resp_wire,
				                          &answer_size);

				dbg_zones_detail("Packet to wire returned %d\n",
				                 ret);

				// then add the TSIG to the wire format
				if (ret == KNOT_EOK &&
				    tsig_rcode != KNOT_RCODE_BADTIME) {
					dbg_zones_verb("Adding TSIG.\n");
					ret = knot_tsig_add(resp_wire,
					                    &answer_size,
					                    *rsize, tsig_rcode,
					                     knot_packet_tsig(
					                            query));

					*rsize = answer_size;

				} else if (tsig_rcode
				           == KNOT_RCODE_BADTIME) {
					dbg_zones_verb("Signing error resp.\n");
					//*rsize = answer_size;

					const knot_rrset_t *tsig =
					      knot_packet_tsig(
					          knot_packet_query(resp));

					size_t digest_max_size =
					           knot_tsig_digest_length(
					              tsig_key_zone->algorithm);
					uint8_t *digest = (uint8_t *)malloc(
					                       digest_max_size);
					if (digest == NULL) {
						knot_packet_free(&resp);
						rcu_read_unlock();
						return KNOT_ENOMEM;
					}
					size_t digest_size = digest_max_size;

					ret = knot_tsig_sign(resp_wire,
					    &answer_size, *rsize,
					    tsig_rdata_mac(tsig),
					    tsig_rdata_mac_length(tsig),
					    digest, &digest_size, tsig_key_zone,
					    tsig_rcode, tsig_prev_time_signed);

					// no need to keep the digest
					free(digest);

					*rsize = answer_size;
				} else {
					dbg_zones_verb("Failed.\n");
					rcode = KNOT_RCODE_SERVFAIL;
				}
			}
			// in other case the RCODE is set and ret != KNOT_EOK
			// and a normal error is returned below
		}

		if (ret != KNOT_EOK) {
			knot_ns_error_response_full(nameserver, resp,
			                            rcode, resp_wire,
			                            rsize);
		}
	}

	knot_packet_free(&resp);
	rcu_read_unlock();

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_process_update(knot_nameserver_t *nameserver,
                         knot_packet_t *query, const sockaddr_t *addr,
                         uint8_t *resp_wire, size_t *rsize,
                         int fd, knot_ns_transport_t transport)
{
	rcu_read_lock();

	knot_packet_t *resp = NULL;
	knot_zone_t *zone = NULL;
	knot_rcode_t rcode = KNOT_RCODE_NOERROR;
	size_t rsize_max = *rsize;
	knot_tsig_key_t *tsig_key_zone = NULL;
	uint16_t tsig_rcode = 0;
	uint64_t tsig_prev_time_signed = 0;
	const knot_rrset_t *tsig_rr = NULL;

	// Parse rest of the query, prepare response, find zone
	int ret = knot_ns_prep_update_response(nameserver, query, &resp, &zone,
	                                       (transport == NS_TRANSPORT_TCP)
	                                       ? *rsize : 0);
	dbg_zones_verb("Preparing response structure = %s\n", knot_strerror(ret));
	switch (ret) {
	case KNOT_EOK: break;
	case KNOT_EMALF: /* No TSIG signing in this case. */
		rcode = KNOT_RCODE_FORMERR;
		break;
	default:
		rcode = KNOT_RCODE_SERVFAIL;
		break;
	}

	/* Check if zone is valid. */
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (zone && (knot_zone_flags(zone) & KNOT_ZONE_DISCARDED)) {
		rcode = KNOT_RCODE_SERVFAIL; /* It's ok, temporarily. */
		tsig_rcode = KNOT_RCODE_BADKEY;
		ret = KNOT_ENOZONE;
	} else if (!zone || !contents) {     /* Treat as BADKEY. */
		rcode = KNOT_RCODE_NOTAUTH;
		tsig_rcode = KNOT_RCODE_BADKEY;
		ret = KNOT_TSIG_EBADKEY;
		dbg_zones_verb("No zone or empty, refusing UPDATE.\n");
	}

	/* Verify TSIG if it is in the packet. */
	tsig_rr = knot_packet_tsig(query);
	if (ret == KNOT_EOK) { /* Have valid zone to check ACLs against. */
		dbg_zones_verb("Checking TSIG in query.\n");
		ret = zones_check_tsig_query(zone, query, addr,
					     &rcode, &tsig_rcode,
					     &tsig_key_zone,
					     &tsig_prev_time_signed);
	}

	/* Allow pass-through of an unknown TSIG in DDNS forwarding (must have zone). */
	if (zone && (ret == KNOT_EOK || (ret == KNOT_TSIG_EBADKEY && !tsig_key_zone))) {
		/* Transaction is authenticated (or unprotected)
		 * and zone has primary master set,
		 * proceed to forward the query to the next hop.
		 */
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		if (zd->xfr_in.has_master) {
			ret = zones_update_forward(fd, transport, zone, addr,
			                           query, *rsize);
			*rsize = 0; /* Do not send reply immediately. */
			knot_packet_free(&resp);
			rcu_read_unlock();
			return ret;
		}
	}

	/*
	 * 1) DDNS Zone Section check (RFC2136, Section 3.1).
	 */
	if (ret == KNOT_EOK) {
		ret = knot_ddns_check_zone(contents, query, &rcode);
		dbg_zones_verb("Checking zone = %s\n", knot_strerror(ret));
	}

	/*
	 * 2) DDNS Prerequisities Section processing (RFC2136, Section 3.2).
	 *
	 * \note Permissions section means probably policies and fine grained
	 *       access control, not transaction security.
	 */
	knot_ddns_prereq_t *prereqs = NULL;
	if (ret == KNOT_EOK) {
		ret = knot_ddns_process_prereqs(query, &prereqs, &rcode);
		dbg_zones_verb("Processing prereq = %s\n", knot_strerror(ret));
	}
	if (ret == KNOT_EOK) {
		assert(prereqs != NULL);
		ret = knot_ddns_check_prereqs(contents, &prereqs, &rcode);
		dbg_zones_verb("Checking prereq = %s\n", knot_strerror(ret));
		knot_ddns_prereqs_free(&prereqs);
	}

	/*
	 * 3) Process query.
	 */
	if (ret == KNOT_EOK) {
		/*! \note This function expects RCU locked. */
		ret = zones_process_update_auth(zone, resp, resp_wire, rsize,
		                                &rcode, addr, tsig_key_zone);
		dbg_zones_verb("Auth, update_proc = %s\n", knot_strerror(ret));
	}

	/* Create error query if processing failed. */
	if (ret != KNOT_EOK) {
		ret = knot_ns_error_response_from_query(nameserver,
		                                        query, rcode,
		                                        resp_wire, rsize);
	}

	/* No response, no signing required or FORMERR. */
	if (*rsize == 0 || !tsig_rr || rcode == KNOT_RCODE_FORMERR) {
		knot_packet_free(&resp);
		rcu_read_unlock();
		return ret;
	}

	/* Just add TSIG RR on most errors. */
	if (tsig_rcode != 0 && tsig_rcode != KNOT_RCODE_BADTIME) {
		ret = knot_tsig_add(resp_wire, rsize, rsize_max,
		                    tsig_rcode, tsig_rr);
		dbg_zones_verb("Adding TSIG = %s\n", knot_strerror(ret));
	} else if (tsig_key_zone) {
		dbg_zones_verb("Signing message with TSIG.\n");
		size_t digest_len = knot_tsig_digest_length(tsig_key_zone->algorithm);
		uint8_t *digest = (uint8_t *)malloc(digest_len);
		if (digest == NULL) {
			knot_packet_free(&resp);
			rcu_read_unlock();
			return KNOT_ENOMEM;
		}
		ret = knot_tsig_sign(resp_wire,
				     rsize, rsize_max,
				     tsig_rdata_mac(tsig_rr),
				     tsig_rdata_mac_length(tsig_rr),
				     digest, &digest_len, tsig_key_zone,
				     tsig_rcode, tsig_prev_time_signed);
		free(digest);
	}

	knot_packet_free(&resp);
	rcu_read_unlock();

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_process_response(knot_nameserver_t *nameserver,
                           int exp_msgid,
                           sockaddr_t *from,
                           knot_packet_t *packet, uint8_t *response_wire,
                           size_t *rsize)
{
	if (!packet || !rsize || nameserver == NULL || from == NULL ||
	    response_wire == NULL) {
		return KNOT_EINVAL;
	}

	/* Declare no response. */
	*rsize = 0;

	/* Handle SOA query response, cancel EXPIRE timer
	 * and start AXFR transfer if needed.
	 * Reset REFRESH timer on finish.
	 */
	if (knot_packet_qtype(packet) == KNOT_RRTYPE_SOA) {

		if (knot_packet_rcode(packet) != KNOT_RCODE_NOERROR) {
			/*! \todo Handle error response. */
			return KNOT_ERROR;
		}

		/* Find matching zone and ID. */
		rcu_read_lock();
		const knot_dname_t *zone_name = knot_packet_qname(packet);
		/*! \todo Change the access to the zone db. */
		knot_zone_t *zone = knot_zonedb_find_zone(
		                        nameserver->zone_db,
		                        zone_name);

		/* Get zone contents. */
		const knot_zone_contents_t *contents =
				knot_zone_contents(zone);

		if (!zone || !knot_zone_data(zone) || !contents) {
			rcu_read_unlock();
			return KNOT_EINVAL;
		}

		/* Match ID against awaited. */
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		uint16_t pkt_id = knot_packet_id(packet);
		if ((int)pkt_id != exp_msgid) {
			rcu_read_unlock();
			return KNOT_ERROR;
		}

		/* Check SOA SERIAL. */
		int ret = xfrin_transfer_needed(contents, packet);
		dbg_zones_verb("xfrin_transfer_needed() returned %s\n",
		               knot_strerror(ret));
		if (ret < 0) {
			/* RETRY/EXPIRE timers running, do not interfere. */
			rcu_read_unlock();
			return KNOT_ERROR;
		}

		/* No updates available. */
		if (ret == 0) {
			zones_schedule_refresh(zone, REFRESH_DEFAULT);
			rcu_read_unlock();
			return KNOT_EUPTODATE;
		}

		assert(ret > 0);

		/* Check zone transfer state. */
		pthread_mutex_lock(&zd->lock);
		if (zd->xfr_in.state == XFR_PENDING) {
			pthread_mutex_unlock(&zd->lock);
			rcu_read_unlock();
			return KNOT_EOK; /* Already pending. */
		} else {
			zd->xfr_in.state = XFR_PENDING;
		}

		/* Prepare XFR client transfer. */
		server_t *srv = (server_t *)knot_ns_get_data(nameserver);
		int rqtype = zones_transfer_to_use(zd);
		knot_ns_xfr_t *rq = xfr_task_create(zone, rqtype, XFR_FLAG_TCP);
		if (!rq) {
			pthread_mutex_unlock(&zd->lock);
			rcu_read_unlock();
			return KNOT_ENOMEM;
		}
		xfr_task_setaddr(rq, &zd->xfr_in.master, &zd->xfr_in.via);
		if (zd->xfr_in.tsig_key.name) {
			rq->tsig_key = &zd->xfr_in.tsig_key;
		}

		rcu_read_unlock();
		ret = xfr_enqueue(srv->xfr, rq);
		if (ret != KNOT_EOK) {
			xfr_task_free(rq);
			zd->xfr_in.state = XFR_SCHED; /* Revert state */
		}
		pthread_mutex_unlock(&zd->lock);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

knot_ns_xfr_type_t zones_transfer_to_use(zonedata_t *data)
{
	if (data == NULL || data->ixfr_db == NULL) {
		return XFR_TYPE_AIN;
	}

	return XFR_TYPE_IIN;
}

/*----------------------------------------------------------------------------*/

static int zones_open_free_filename(const char *old_name, char **new_name)
{
	/* find zone name not present on the disk */
	size_t name_size = strlen(old_name);
	*new_name = malloc(name_size + 7 + 1);
	if (*new_name == NULL) {
		return -1;
	}
	memcpy(*new_name, old_name, name_size + 1);
	strncat(*new_name, ".XXXXXX", 7);
	dbg_zones_verb("zones: creating temporary zone file\n");
	mode_t old_mode = umask(077);
	int fd = mkstemp(*new_name);
	UNUSED(umask(old_mode));
	if (fd < 0) {
		dbg_zones_verb("zones: couldn't create temporary zone file\n");
		free(*new_name);
		*new_name = NULL;
	}

	return fd;
}

/*----------------------------------------------------------------------------*/

static int zones_dump_zone_text(knot_zone_contents_t *zone, const char *fname)
{
	assert(zone != NULL && fname != NULL);

	char *new_fname = NULL;
	int fd = zones_open_free_filename(fname, &new_fname);
	if (fd < 0) {
		return FLOADER_EWRITABLE;
	}

	FILE *f = fdopen(fd, "w");
	if (f == NULL) {
		log_zone_warning("Failed to open file descriptor for text zone.\n");
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	if (zone_dump_text(zone, f) != KNOT_EOK) {
		log_zone_warning("Failed to save the transferred zone to '%s'.\n",
		                 new_fname);
		fclose(f);
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	/* Set zone file rights to 0640. */
	fchmod(fd, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);

	/* Swap temporary zonefile and new zonefile. */
	fclose(f);

	int ret = rename(new_fname, fname);
	if (ret < 0 && ret != EEXIST) {
		log_zone_warning("Failed to replace old zone file '%s'' with a "
		                 "new zone file '%s'.\n", fname, new_fname);
		unlink(new_fname);
		free(new_fname);
		return KNOT_ERROR;
	}

	free(new_fname);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_save_zone(const knot_ns_xfr_t *xfr)
{
	/* Zone is already referenced, no need for RCU locking. */

	if (xfr == NULL || xfr->new_contents == NULL || xfr->zone == NULL) {
		return KNOT_EINVAL;
	}

	dbg_xfr("xfr: %s Saving new zone file.\n", xfr->msg);

	zonedata_t *zd = (zonedata_t *)knot_zone_data(xfr->zone);
	knot_zone_contents_t *new_zone = xfr->new_contents;

	const char *zonefile = zd->conf->file;

	/* Check if the new zone apex dname matches zone name. */
	knot_dname_t *cur_name = knot_dname_new_from_str(zd->conf->name,
	                                                 strlen(zd->conf->name),
	                                                 NULL);
	const knot_dname_t *new_name = NULL;
	new_name = knot_node_owner(knot_zone_contents_apex(new_zone));
	int r = knot_dname_compare(cur_name, new_name);
	knot_dname_free(&cur_name);
	if (r != 0) {
		return KNOT_EINVAL;
	}

	assert(zonefile != NULL);

	/* dump the zone into text zone file */
	int ret = zones_dump_zone_text(new_zone, zonefile);
	return ret;
}

/*----------------------------------------------------------------------------*/

int zones_ns_conf_hook(const struct conf_t *conf, void *data)
{
	knot_nameserver_t *ns = (knot_nameserver_t *)data;
	dbg_zones_verb("zones: reconfiguring name server.\n");

	/* Create new OPT RR, old must be freed after RCU sync. */
	knot_opt_rr_t *opt_rr_old = ns->opt_rr;
	knot_opt_rr_t *opt_rr = knot_edns_new();
	if (opt_rr == NULL) {
		log_server_error("Couldn't create OPT RR, please restart.\n");
	} else {
		knot_edns_set_version(opt_rr, EDNS_VERSION);
		knot_edns_set_payload(opt_rr, conf->max_udp_payload);
		if (conf->nsid_len > 0) {
			knot_edns_add_option(opt_rr, EDNS_OPTION_NSID,
			                     conf->nsid_len,
			                     (const uint8_t *)conf->nsid);
		}
	}

	/* Swap pointers to OPT RR. */
	ns->opt_rr = opt_rr;

	/* Server identification, RFC 4892. */
	ns->identity = conf->identity;
	ns->version = conf->version;

	knot_zonedb_t *old_db = 0;

	int ret = zones_update_db_from_config(conf, ns, &old_db);
	if (ret != KNOT_EOK) {
		return ret;
	}
	/* Wait until all readers finish with reading the zones. */
	synchronize_rcu();

	/* Remove old OPT RR. */
	knot_edns_free(&opt_rr_old);

	dbg_zones_verb("zones: nameserver's zone db: %p, old db: %p\n",
	               ns->zone_db, old_db);

	/* Delete all deprecated zones and delete the old database. */
	knot_zonedb_deep_free(&old_db);

	/* Update events scheduled for zone. */
	rcu_read_lock();
	knot_zone_t **zones = (knot_zone_t **)knot_zonedb_zones(ns->zone_db);
	if (zones == NULL) {
		rcu_read_unlock();
		return KNOT_ENOMEM;
	}

	/* REFRESH zones. */
	for (unsigned i = 0; i < knot_zonedb_zone_count(ns->zone_db); ++i) {
		zones_schedule_refresh(zones[i], 0); /* Now. */
		zones_schedule_notify(zones[i]);
	}

	/* Unlock RCU. */
	rcu_read_unlock();
	free(zones);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* Counting size of changeset in serialized form.                             */
/*----------------------------------------------------------------------------*/

int zones_changeset_binary_size(const knot_changeset_t *chgset, size_t *size)
{
	if (chgset == NULL || size == NULL) {
		return KNOT_EINVAL;
	}

	size_t soa_from_size = rrset_binary_size(chgset->soa_from);
	size_t soa_to_size = rrset_binary_size(chgset->soa_to);

	size_t remove_size = 0;
	for (int i = 0; i < chgset->remove_count; ++i)
	{
		remove_size += rrset_binary_size(chgset->remove[i]);
	}

	size_t add_size = 0;
	for (int i = 0; i < chgset->add_count; ++i)
	{
		add_size += rrset_binary_size(chgset->add[i]);
	}

	/*! \todo How is the changeset serialized? Any other parts? */
	*size = soa_from_size + soa_to_size + remove_size + add_size;
	/* + Changeset flags. */
	*size += sizeof(uint32_t);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* Changeset serialization and storing (new)                                  */
/*----------------------------------------------------------------------------*/

static int zones_rrset_write_to_mem(const knot_rrset_t *rr, char **entry,
                                    size_t *remaining) {
	size_t written = 0;
	int ret = rrset_serialize(rr, *((uint8_t **)entry),
	                          &written);
	if (ret == KNOT_EOK) {
		assert(written <= *remaining);
		*remaining -= written;
		*entry += written;
	}

	return ret;
}

static int zones_serialize_and_store_chgset(const knot_changeset_t *chs,
                                            char *entry, size_t max_size)
{
	/* Write changeset flags. */
	memcpy(entry, (char*)&chs->flags, sizeof(uint32_t));
	entry += sizeof(uint32_t);
	max_size -= sizeof(uint32_t);

	/* Serialize SOA 'from'. */
	int ret = zones_rrset_write_to_mem(chs->soa_from, &entry, &max_size);
	if (ret != KNOT_EOK) {
		dbg_zones("%s:%d ret = %s\n", __func__, __LINE__, knot_strerror(ret));
		return KNOT_ERROR;  /*! \todo Other code? */
	}

	/* Serialize RRSets from the 'remove' section. */
	for (int i = 0; i < chs->remove_count; ++i) {
		ret = zones_rrset_write_to_mem(chs->remove[i], &entry, &max_size);
		if (ret != KNOT_EOK) {
			dbg_zones("%s:%d ret = %s\n", __func__, __LINE__, knot_strerror(ret));
			return KNOT_ERROR;  /*! \todo Other code? */
		}
	}

	/* Serialize SOA 'to'. */
	ret = zones_rrset_write_to_mem(chs->soa_to, &entry, &max_size);
	if (ret != KNOT_EOK) {
		dbg_zones("%s:%d ret = %s\n", __func__, __LINE__, knot_strerror(ret));
		return KNOT_ERROR;  /*! \todo Other code? */
	}

	/* Serialize RRSets from the 'add' section. */
	for (int i = 0; i < chs->add_count; ++i) {
		ret = zones_rrset_write_to_mem(chs->add[i], &entry, &max_size);
		if (ret != KNOT_EOK) {
			dbg_zones("%s:%d ret = %s\n", __func__, __LINE__, knot_strerror(ret));
			return KNOT_ERROR;  /*! \todo Other code? */
		}

	}


	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_store_changeset(const knot_changeset_t *chs, journal_t *j,
                                 knot_zone_t *zone, zonedata_t *zd)
{
	assert(chs != NULL);
	assert(j != NULL);

	dbg_xfr("Saving changeset from %u to %u.\n",
	        chs->serial_from, chs->serial_to);

	uint64_t k = ixfrdb_key_make(chs->serial_from, chs->serial_to);

	/* Count the size of the entire changeset in serialized form. */
	size_t entry_size = 0;

	int ret = zones_changeset_binary_size(chs, &entry_size);
	assert(ret == KNOT_EOK);

	dbg_xfr_verb("Size in serialized form: %zu\n", entry_size);

	/* Reserve space for the journal entry. */
	char *journal_entry = NULL;
	ret = journal_map(j, k, &journal_entry, entry_size);
	if (ret != KNOT_EOK) {
		dbg_xfr("Failed to map space for journal entry: %s.\n",
		        knot_strerror(ret));
		return ret;
	}

	assert(journal_entry != NULL);

	/* Serialize changeset, saving it bit by bit. */
	ret = zones_serialize_and_store_chgset(chs, journal_entry, entry_size);
	/* Unmap the journal entry.
	 * If successfuly written changeset to journal, validate the entry. */
	int unmap_ret = journal_unmap(j, k, journal_entry, ret == KNOT_EOK);
	if (ret == KNOT_EOK && unmap_ret != KNOT_EOK) {
		ret = unmap_ret; /* Propagate the result. */
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

journal_t *zones_store_changesets_begin(knot_zone_t *zone)
{
	if (zone == NULL) {
		return NULL;
	}

	/* Fetch zone-specific data. */
	//knot_zone_t *zone = xfr->zone;
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd->ixfr_db) {
		return NULL;
	}

	/* Begin transaction, will be release on commit/rollback. */
	journal_t *j = journal_retain(zd->ixfr_db);
	if (journal_trans_begin(j) != KNOT_EOK) {
		journal_release(j);
		j = NULL;
	}

	return j;
}

/*----------------------------------------------------------------------------*/

int zones_store_changesets_commit(journal_t *j)
{
	if (j == NULL) {
		return KNOT_EINVAL;
	}

	int ret = journal_trans_commit(j);
	journal_release(j);
	return ret;
}

/*----------------------------------------------------------------------------*/

int zones_store_changesets_rollback(journal_t *j)
{
	if (j == NULL) {
		return KNOT_EINVAL;
	}

	int ret = journal_trans_rollback(j);
	journal_release(j);
	return ret;
}

/*----------------------------------------------------------------------------*/

int zones_store_changesets(knot_zone_t *zone, knot_changesets_t *src, journal_t *j)
{
	if (zone == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* Fetch zone-specific data. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd->ixfr_db) {
		return KNOT_EINVAL;
	}

	/* Begin writing to journal. */
	for (unsigned i = 0; i < src->count; ++i) {
		/* Make key from serials. */
		knot_changeset_t* chs = src->sets + i;

		ret = zones_store_changeset(chs, j, zone, zd);
		if (ret != KNOT_EOK)
			break;
	}

	/* Flush if the journal is full. */
	event_t *tmr = zd->ixfr_dbsync;
	if (ret == KNOT_EBUSY && tmr) {
		log_server_notice("Journal for '%s' is full, flushing.\n",
		                  zd->conf->name);
		evsched_cancel(tmr->parent, tmr);
		evsched_schedule(tmr->parent, tmr, 0);
	}

	/* Written changesets to journal. */
	return ret;
}

/*----------------------------------------------------------------------------*/

int zones_xfr_load_changesets(knot_ns_xfr_t *xfr, uint32_t serial_from,
                              uint32_t serial_to)
{
	if (!xfr || !xfr->zone || !knot_zone_contents(xfr->zone)) {
		return KNOT_EINVAL;
	}

	knot_changesets_t *chgsets = (knot_changesets_t *)
	                               calloc(1, sizeof(knot_changesets_t));
	CHECK_ALLOC_LOG(chgsets, KNOT_ENOMEM);

	int ret = ns_serial_compare(serial_to, serial_from);
	dbg_zones_verb("Compared serials, result: %d\n", ret);

	/* if serial_to is not larger than serial_from, do not load anything */
	if (ret <= 0) {
		xfr->data = chgsets;
		return KNOT_EOK;
	}

	dbg_xfr_verb("xfr: loading changesets\n");
	ret = zones_load_changesets(xfr->zone, chgsets,
	                                serial_from, serial_to);
	if (ret != KNOT_EOK) {
		dbg_xfr("xfr: failed to load changesets: %s\n",
		        knot_strerror(ret));
		knot_free_changesets(&chgsets);
		return ret;
	}

	xfr->data = chgsets;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_create_and_save_changesets(const knot_zone_t *old_zone,
                                     const knot_zone_t *new_zone)
{
	if (old_zone == NULL || old_zone->contents == NULL
	    || new_zone == NULL || new_zone->contents == NULL) {
		dbg_zones("zones: create_changesets: "
		          "NULL arguments.\n");
		return KNOT_EINVAL;
	}

	knot_ns_xfr_t xfr;
	memset(&xfr, 0, sizeof(xfr));
	xfr.zone = (knot_zone_t *)old_zone;
	knot_changesets_t *changesets;
	int ret = knot_zone_diff_create_changesets(old_zone->contents,
	                                           new_zone->contents,
	                                           &changesets);
	if (ret != KNOT_EOK) {
		if (ret == KNOT_ERANGE) {
			dbg_zones_detail("zones: create_changesets: "
			                 "New serial was lower than the old "
			                 "one.\n");
			knot_free_changesets(&changesets);
			return KNOT_ERANGE;
		} else if (ret == KNOT_ENODIFF) {
			dbg_zones_detail("zones: create_changesets: "
			                 "New serial was the same as the old "
			                 "one.\n");
			knot_free_changesets(&changesets);
			return KNOT_ENODIFF;
		} else {
			dbg_zones("zones: create_changesets: "
			          "Could not create changesets. Reason: %s\n",
			          knot_strerror(ret));
			knot_free_changesets(&changesets);
			return KNOT_ERROR;
		}
	}

	xfr.data = changesets;
	journal_t *journal = zones_store_changesets_begin(xfr.zone);
	if (journal == NULL) {
		dbg_zones("zones: create_changesets: "
		          "Could not start journal operation.\n");
		return KNOT_ERROR;
	}

	ret = zones_store_changesets(xfr.zone, (knot_changesets_t *)xfr.data, journal);
	if (ret != KNOT_EOK) {
		zones_store_changesets_rollback(journal);
		dbg_zones("zones: create_changesets: "
		          "Could not store in the journal. Reason: %s.\n",
		          knot_strerror(ret));

		return ret;
	}

	ret = zones_store_changesets_commit(journal);
	if (ret != KNOT_EOK) {
		dbg_zones("zones: create_changesets: "
		          "Could not commit to journal. Reason: %s.\n",
		          knot_strerror(ret));

		return ret;
	}

	knot_free_changesets(&changesets);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_store_and_apply_chgsets(knot_changesets_t *chs,
                                  knot_zone_t *zone,
                                  knot_zone_contents_t **new_contents,
                                  const char *msgpref, int type)
{
	int ret = KNOT_EOK;
	int apply_ret = KNOT_EOK;
	int switch_ret = KNOT_EOK;

	/* Serialize and store changesets. */
	dbg_xfr("xfr: IXFR/IN serializing and saving changesets\n");
	journal_t *transaction = zones_store_changesets_begin(zone);
	if (transaction != NULL) {
		ret = zones_store_changesets(zone, chs, transaction);
	} else {
		ret = KNOT_ERROR;
	}
	if (ret != KNOT_EOK) {
		log_zone_error("%s Failed to serialize and store "
		               "changesets.\n", msgpref);
		/* Free changesets, but not the data. */
		zones_store_changesets_rollback(transaction);
		knot_free_changesets(&chs);
		return ret;
	}

	/* Now, try to apply the changesets to the zone. */
	apply_ret = xfrin_apply_changesets(zone, chs, new_contents);

	if (apply_ret != KNOT_EOK) {
		log_zone_error("%s Failed to apply changesets.\n", msgpref);

		/* Free changesets, but not the data. */
		zones_store_changesets_rollback(transaction);
		knot_free_changesets(&chs);
		return apply_ret;  // propagate the error above
	}

	/* Commit transaction. */
	ret = zones_store_changesets_commit(transaction);
	if (ret != KNOT_EOK) {
		/*! \todo THIS WILL LEAK!! xfrin_rollback_update() needed. */
		log_zone_error("%s Failed to commit stored changesets.\n", msgpref);
		knot_free_changesets(&chs);
		return ret;
	}

	/* Switch zone contents. */
	switch_ret = xfrin_switch_zone(zone, *new_contents, type);

	if (switch_ret != KNOT_EOK) {
		log_zone_error("%s Failed to replace current zone.\n", msgpref);
		// Cleanup old and new contents
		xfrin_rollback_update(zone->contents, new_contents,
		                      &chs->changes);

		/* Free changesets, but not the data. */
		knot_free_changesets(&chs);
		return KNOT_ERROR;
	}

	xfrin_cleanup_successful_update(&chs->changes);

	/* Free changesets, but not the data. */
	knot_free_changesets(&chs);
	assert(ret == KNOT_EOK);
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_schedule_notify(knot_zone_t *zone)
{
	/* Do not issue NOTIFY queries if stub. */
	if (!knot_zone_contents(zone)) {
		return KNOT_EOK;
	}

	/* Schedule NOTIFY to slaves. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	conf_zone_t *cfg = zd->conf;
	conf_remote_t *r = 0;
	WALK_LIST(r, cfg->acl.notify_out) {

		/* Fetch remote. */
		conf_iface_t *cfg_if = r->remote;

		/* Create request. */
		knot_ns_xfr_t *rq = xfr_task_create(zone, XFR_TYPE_NOTIFY, XFR_FLAG_UDP);
		if (!rq) {
			log_server_error("Failed to create NOTIFY for '%s', "
			                 "not enough memory.\n", cfg->name);
			continue;
		}

		/* Parse server address. */
		sockaddr_t addr;
		sockaddr_set(&addr, cfg_if->family, cfg_if->address, cfg_if->port);
		xfr_task_setaddr(rq, &addr, &cfg_if->via);
		rq->data = (void *)((long)cfg->notify_retries + 1);
		if (xfr_enqueue(zd->server->xfr, rq) != KNOT_EOK) {
			log_server_error("Failed to enqueue NOTIFY for '%s'.",
			                 cfg->name);
			continue;
		}
	}

	return KNOT_EOK;
}

int zones_schedule_refresh(knot_zone_t *zone, int64_t time)
{
	if (!zone || !zone->data) {
		return KNOT_EINVAL;
	}

	/* Cancel REFRESH timer. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	evsched_t *sch = zd->server->sched;
	if (zd->xfr_in.timer) {
		evsched_cancel(sch, zd->xfr_in.timer);
		evsched_event_free(sch, zd->xfr_in.timer);
		zd->xfr_in.timer = 0;
	}

	/* Cancel EXPIRE timer. */
	if (zd->xfr_in.expire) {
		evsched_cancel(sch, zd->xfr_in.expire);
		evsched_event_free(sch, zd->xfr_in.expire);
		zd->xfr_in.expire = 0;
	}

	/* Check XFR/IN master server. */
	pthread_mutex_lock(&zd->lock);
	rcu_read_lock();
	zd->xfr_in.state = XFR_IDLE;
	if (zd->xfr_in.has_master) {

		/* Schedule REFRESH timer. */
		if (time < 0) {
			if (knot_zone_contents(zone))
				time = zones_jitter(zones_soa_refresh(zone));
			else
				time = zd->xfr_in.bootstrap_retry;
		}

		zd->xfr_in.timer = evsched_schedule_cb(sch, zones_refresh_ev,
		                                       zone, time);
		dbg_zones("zone: REFRESH '%s' set to %u\n",
		          zd->conf->name, time);
		zd->xfr_in.state = XFR_SCHED;
	}
	rcu_read_unlock();
	pthread_mutex_unlock(&zd->lock);

	return KNOT_EOK;
}

int zones_process_update_response(knot_ns_xfr_t *data, uint8_t *rwire, size_t *rsize)
{
	/* Processing of a forwarded response:
	 * change packet id
	 */
	int ret = KNOT_EOK;
	knot_wire_set_id(rwire, (uint16_t)data->packet_nr);

	/* Forward the response. */
	ret = data->send(data->fwd_src_fd, &data->fwd_addr, rwire, *rsize);
	if (ret != *rsize) {
		ret = KNOT_ECONN;
	} else {
		ret = KNOT_EOK;
	}

	/* As it is a response, do not reply back. */
	*rsize = 0;
	return ret;
}


int zones_verify_tsig_query(const knot_packet_t *query,
                            const knot_tsig_key_t *key,
                            knot_rcode_t *rcode, uint16_t *tsig_rcode,
                            uint64_t *tsig_prev_time_signed)
{
	assert(key != NULL);
	assert(rcode != NULL);
	assert(tsig_rcode != NULL);

	const knot_rrset_t *tsig_rr = knot_packet_tsig(query);
	if (tsig_rr == NULL) {
		dbg_zones("TSIG key required, but not in query - REFUSED.\n");
		*rcode = KNOT_RCODE_REFUSED;
		return KNOT_TSIG_EBADKEY;
	}

	/*
	 * 1) Check if we support the requested algorithm.
	 */
	knot_tsig_algorithm_t alg = tsig_rdata_alg(tsig_rr);
	if (knot_tsig_digest_length(alg) == 0) {
		log_answer_info("Unsupported digest algorithm "
		                "requested, treating as bad key\n");
		/*! \todo [TSIG] It is unclear from RFC if I
		 *               should treat is as a bad key
		 *               or some other error.
		 */
		*rcode = KNOT_RCODE_NOTAUTH;
		*tsig_rcode = KNOT_RCODE_BADKEY;
		return KNOT_TSIG_EBADKEY;
	}

	const knot_dname_t *kname = knot_rrset_owner(tsig_rr);
	assert(kname != NULL);

	/*
	 * 2) Find the particular key used by the TSIG.
	 *    Check not only name, but also the algorithm.
	 */
	if (key && kname && knot_dname_compare(key->name, kname) == 0
	    && key->algorithm == alg) {
		dbg_zones_verb("Found claimed TSIG key for comparison\n");
	} else {
		*rcode = KNOT_RCODE_NOTAUTH;
		*tsig_rcode = KNOT_RCODE_BADKEY;
		return KNOT_TSIG_EBADKEY;
	}

	/*
	 * 3) Validate the query with TSIG.
	 */
	/* Prepare variables for TSIG */
	/*! \todo These need to be saved to the response somehow. */
	//size_t tsig_size = tsig_wire_maxsize(key);
	size_t digest_max_size = knot_tsig_digest_length(key->algorithm);
	//size_t digest_size = 0;
	//uint64_t tsig_prev_time_signed = 0;
	//uint8_t *digest = (uint8_t *)malloc(digest_max_size);
	//memset(digest, 0 , digest_max_size);

	/* Copy MAC from query. */
	dbg_zones_verb("Validating TSIG from query\n");

	//const uint8_t* mac = tsig_rdata_mac(tsig_rr);
	size_t mac_len = tsig_rdata_mac_length(tsig_rr);

	int ret = KNOT_EOK;

	if (mac_len > digest_max_size) {
		*rcode = KNOT_RCODE_FORMERR;
		dbg_zones("MAC length %zu exceeds digest "
		       "maximum size %zu\n", mac_len, digest_max_size);
		return KNOT_EMALF;
	} else {
		//memcpy(digest, mac, mac_len);
		//digest_size = mac_len;

		/* Check query TSIG. */
		ret = knot_tsig_server_check(tsig_rr,
		                             knot_packet_wireformat(query),
		                             knot_packet_size(query), key);
		dbg_zones_verb("knot_tsig_server_check() returned %s\n",
		               knot_strerror(ret));

		/* Evaluate TSIG check results. */
		switch(ret) {
		case KNOT_EOK:
			*rcode = KNOT_RCODE_NOERROR;
			break;
		case KNOT_TSIG_EBADKEY:
			*tsig_rcode = KNOT_RCODE_BADKEY;
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_TSIG_EBADSIG:
			*tsig_rcode = KNOT_RCODE_BADSIG;
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_TSIG_EBADTIME:
			*tsig_rcode = KNOT_RCODE_BADTIME;
			// store the time signed from the query
			*tsig_prev_time_signed = tsig_rdata_time_signed(tsig_rr);
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_EMALF:
			*rcode = KNOT_RCODE_FORMERR;
			break;
		default:
			*rcode = KNOT_RCODE_SERVFAIL;
		}
	}

	return ret;
}
