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

#include "common/lists.h"
#include "common/prng.h"
#include "libknot/dname.h"
#include "libknot/util/wire.h"
#include "knot/zone/zone-dump-text.h"
#include "knot/zone/zone-load.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/zonedb.h"
#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "knot/other/error.h"
#include "knot/other/log.h"
#include "knot/server/notify.h"
#include "knot/server/server.h"
#include "libknot/updates/xfr-in.h"
#include "knot/server/zones.h"
#include "libknot/util/error.h"
#include "knot/zone/zone-dump.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/updates/changesets.h"
#include "libknot/tsig-op.h"
#include "libknot/packet/response.h"

static const size_t XFRIN_CHANGESET_BINARY_SIZE = 100;
static const size_t XFRIN_CHANGESET_BINARY_STEP = 100;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Wrapper for TCP send.
 * \todo Implement generic fd pool properly with callbacks.
 */
#include "knot/server/tcp-handler.h"
static int zones_send_cb(int fd, sockaddr_t *addr, uint8_t *msg, size_t msglen)
{
	return tcp_send(fd, msg, msglen);
}

/*----------------------------------------------------------------------------*/

/*! \brief Zone data destructor function. */
static int zonedata_destroy(knot_zone_t *zone)
{
	dbg_zones_verb("zones: zonedata_destroy(%p) called\n", zone);
	
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd) {
		return KNOTD_EINVAL;
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

	/* Remove list of pending NOTIFYs. */
	pthread_mutex_lock(&zd->lock);
	notify_ev_t *ev = 0, *evn = 0;
	WALK_LIST_DELSAFE(ev, evn, zd->notify_pending) {
		zones_cancel_notify(zd, ev);
	}
	pthread_mutex_unlock(&zd->lock);

	/* Cancel IXFR DB sync timer. */
	if (zd->ixfr_dbsync) {
		evsched_t *sch = zd->ixfr_dbsync->parent;
		evsched_cancel(sch, zd->ixfr_dbsync);
		evsched_event_free(sch, zd->ixfr_dbsync);
		zd->ixfr_dbsync = 0;
	}

	/* Destroy mutex. */
	pthread_mutex_destroy(&zd->lock);
	pthread_mutex_destroy(&zd->xfr_in.lock);

	acl_delete(&zd->xfr_in.acl);
	acl_delete(&zd->xfr_out);
	acl_delete(&zd->notify_in);
	acl_delete(&zd->notify_out);

	/* Close IXFR db. */
	journal_close(zd->ixfr_db);

	free(zd);
	
	/* Invalidate. */
	zone->dtor = 0;
	zone->data = 0;

	return KNOTD_EOK;
}

/*! \brief Zone data constructor function. */
static int zonedata_init(conf_zone_t *cfg, knot_zone_t *zone)
{
	zonedata_t *zd = malloc(sizeof(zonedata_t));
	if (!zd) {
		return KNOTD_ENOMEM;
	}

	/* Link to config. */
	zd->conf = cfg;
	zd->server = 0;

	/* Initialize mutex. */
	pthread_mutex_init(&zd->lock, 0);

	/* Initialize ACLs. */
	zd->xfr_out = 0;
	zd->notify_in = 0;
	zd->notify_out = 0;

	/* Initialize XFR-IN. */
	sockaddr_init(&zd->xfr_in.master, -1);
	zd->xfr_in.timer = 0;
	zd->xfr_in.expire = 0;
	zd->xfr_in.next_id = -1;
	zd->xfr_in.acl = 0;
	zd->xfr_in.wrkr = 0;
	zd->xfr_in.bootstrap_retry = 0;
	pthread_mutex_init(&zd->xfr_in.lock, 0);

	/* Initialize NOTIFY. */
	init_list(&zd->notify_pending);

	/* Initialize IXFR database. */
	zd->ixfr_db = journal_open(cfg->ixfr_db, cfg->ixfr_fslimit,
	                           JOURNAL_DIRTY);
	if (!zd->ixfr_db) {
		int ret = journal_create(cfg->ixfr_db, JOURNAL_NCOUNT);
		if (ret != KNOTD_EOK) {
			log_server_error("Failed to create journal file "
			                 "'%s'\n", cfg->ixfr_db);
		}
		zd->ixfr_db = journal_open(cfg->ixfr_db, cfg->ixfr_fslimit,
		                           JOURNAL_DIRTY);
	}
	
	if (zd->ixfr_db == 0) {
		log_server_error("Failed to open journal file "
		                 "'%s'\n", cfg->ixfr_db);
	}

	/* Initialize IXFR database syncing event. */
	zd->ixfr_dbsync = 0;

	/* Set and install destructor. */
	zone->data = zd;
	zone->dtor = zonedata_destroy;

	/* Set zonefile SOA serial. */
	const knot_rrset_t *soa_rrs = 0;
	const knot_rdata_t *soa_rr = 0;

	/* Load serial. */
	zd->zonefile_serial = 0;
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	if (contents) {
		soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
					  KNOT_RRTYPE_SOA);
		soa_rr = knot_rrset_rdata(soa_rrs);
		int64_t serial = knot_rdata_soa_serial(soa_rr);
		zd->zonefile_serial = (uint32_t)serial;
		if (serial < 0) {
			return KNOTD_EINVAL;
		}
	}

	return KNOTD_EOK;
}

/*!
 * \brief Return SOA timer value.
 *
 * \param zone Pointer to zone.
 * \param rr_func RDATA specificator.
 * \return Timer in miliseconds.
 */
static uint32_t zones_soa_timer(knot_zone_t *zone,
                                uint32_t (*rr_func)(const knot_rdata_t*))
{
	if (!zone) {
		dbg_zones_verb("zones: zones_soa_timer() called "
		               "with NULL zone\n");
	}

	uint32_t ret = 0;

	/* Retrieve SOA RDATA. */
	const knot_rrset_t *soa_rrs = 0;
	const knot_rdata_t *soa_rr = 0;
	knot_zone_contents_t * zc = knot_zone_get_contents((zone));
	if (!zc) {
		return 0;
	}

	soa_rrs = knot_node_rrset(knot_zone_contents_apex(zc),
	                            KNOT_RRTYPE_SOA);
	soa_rr = knot_rrset_rdata(soa_rrs);
	ret = rr_func(soa_rr);

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
	return zones_soa_timer(zone, knot_rdata_soa_refresh);
}

/*!
 * \brief Return SOA RETRY timer value.
 *
 * \param zone Pointer to zone.
 * \return RETRY timer in miliseconds.
 */
static uint32_t zones_soa_retry(knot_zone_t *zone)
{
	return zones_soa_timer(zone, knot_rdata_soa_retry);
}

/*!
 * \brief Return SOA EXPIRE timer value.
 *
 * \param zone Pointer to zone.
 * \return EXPIRE timer in miliseconds.
 */
static uint32_t zones_soa_expire(knot_zone_t *zone)
{
	return zones_soa_timer(zone, knot_rdata_soa_expire);
}

/*!
 * \brief XFR/IN expire event handler.
 */
static int zones_expire_ev(event_t *e)
{
	rcu_read_lock();
	dbg_zones("zones: EXPIRE timer event\n");
	knot_zone_t *zone = (knot_zone_t *)e->data;
	if (!zone) {
		return KNOTD_EINVAL;
	}
	if (!zone->data) {
		return KNOTD_EINVAL;
	}

	zonedata_t *zd = (zonedata_t *)zone->data;
	
	/* Won't accept any pending SOA responses. */
	zd->xfr_in.next_id = -1;

	/* Mark the zone as expired. This will remove the zone contents. */
	knot_zone_contents_t *contents = knot_zonedb_expire_zone(
			zd->server->nameserver->zone_db, zone->name);

	if (contents == NULL) {
		log_server_warning("Non-existent zone expired. Ignoring.\n");
		rcu_read_unlock();
		return 0;
	}
	
	
	rcu_read_unlock();
	
	dbg_zones_verb("zones: zone %s expired, waiting for xfers to finish\n",
	               zd->conf->name);
	pthread_mutex_lock(&zd->xfr_in.lock);
	dbg_zones_verb("zones: zone %s locked, no xfers are running\n",
	               zd->conf->name);
	
	synchronize_rcu();
	pthread_mutex_unlock(&zd->xfr_in.lock);
	
	log_server_info("Zone '%s' expired.\n", zd->conf->name);
	
	/* Early finish this event to prevent lockup during cancellation. */
	dbg_zones("zones: zone expired, removing from database\n");
	evsched_event_finished(e->parent);
	
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
	
	knot_zone_contents_deep_free(&contents, 0);
	
	return 0;
}

/*!
 * \brief Zone REFRESH or RETRY event.
 */
static int zones_refresh_ev(event_t *e)
{
	dbg_zones("zones: REFRESH or RETRY timer event\n");
	knot_zone_t *zone = (knot_zone_t *)e->data;
	if (!zone) {
		return KNOTD_EINVAL;
	}

	/* Cancel pending timers. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd) {
		return KNOTD_EINVAL;
	}

	/* Prepare buffer for query. */
	uint8_t qbuf[SOCKET_MTU_SZ];
	size_t buflen = SOCKET_MTU_SZ;

	/* Lock RCU. */
	rcu_read_lock();

	/* Check for contents. */
	if (!knot_zone_contents(zone)) {

		/* Bootstrap from XFR master. */
		knot_ns_xfr_t xfr_req;
		memset(&xfr_req, 0, sizeof(knot_ns_xfr_t));
		memcpy(&xfr_req.addr, &zd->xfr_in.master, sizeof(sockaddr_t));
		xfr_req.data = (void *)zone;
		xfr_req.send = zones_send_cb;

		/* Select transfer method. */
		xfr_req.type = XFR_TYPE_AIN;
		xfr_req.zone = zone;
		
		/* Select TSIG key. */
		if (zd->xfr_in.tsig_key.name) {
			xfr_req.tsig_key = &zd->xfr_in.tsig_key;
		}

		/* Unlock zone contents. */
		rcu_read_unlock();

		/* Enqueue XFR request. */
		int locked = pthread_mutex_trylock(&zd->xfr_in.lock);
		if (locked != 0) {
			dbg_zones("zones: already bootstrapping '%s'\n",
			          zd->conf->name);
			return KNOTD_EOK;
		}

		log_zone_info("Attempting to bootstrap zone %s from master\n",
			      zd->conf->name);
		pthread_mutex_unlock(&zd->xfr_in.lock);
		
		return xfr_request(zd->server->xfr_h, &xfr_req);
	}
	
	/* Do not issue SOA query if transfer is pending. */
	int locked = pthread_mutex_trylock(&zd->xfr_in.lock);
	if (locked != 0) {
		dbg_zones("zones: zone '%s' is being transferred, "
		          "deferring SOA query\n",
		          zd->conf->name);
		
		/* Reschedule as RETRY timer. */
		evsched_schedule(e->parent, e, zones_soa_retry(zone));
		dbg_zones("zones: RETRY of '%s' after %u seconds\n",
		          zd->conf->name, zones_soa_retry(zone) / 1000);
		
		/* Unlock RCU. */
		rcu_read_unlock();
		return KNOTD_EOK;
	} else {
		pthread_mutex_unlock(&zd->xfr_in.lock);
	}

	/* Create query. */
	/*! \todo API for retrieval of name. */
	
	/*! \todo [TSIG] CHANGE!!! only for compatibility now. */
	knot_ns_xfr_t xfr_req;
	memset(&xfr_req, 0, sizeof(knot_ns_xfr_t));
	xfr_req.wire = qbuf;
	
	int ret = xfrin_create_soa_query(zone->name, &xfr_req, &buflen);
	if (ret == KNOT_EOK) {

		sockaddr_t *master = &zd->xfr_in.master;

		/* Create socket on random port. */
		int sock = socket_create(master->family, SOCK_DGRAM);

		/* Send query. */
		ret = KNOTD_ERROR;
		if (sock > -1) {
			int sent = sendto(sock, qbuf, buflen, 0,
			                  master->ptr, master->len);
		
			/* Store ID of the awaited response. */
			if (sent == buflen) {
				ret = KNOTD_EOK;
			} else {
				socket_close(sock);
				sock = -1;
			}
		}
		
		/* Check result. */
		if (ret == KNOTD_EOK) {
			zd->xfr_in.next_id = knot_wire_get_id(qbuf);
			dbg_zones("zones: expecting SOA response "
			          "ID=%d for '%s'\n",
			          zd->xfr_in.next_id, zd->conf->name);
			
			/* Watch socket. */
			knot_ns_xfr_t req;
			memset(&req, 0, sizeof(req));
			req.session = sock;
			req.type = XFR_TYPE_SOA;
			req.zone = zone;
			memcpy(&req.addr, master, sizeof(sockaddr_t));
			sockaddr_update(&req.addr);
			xfr_request(zd->server->xfr_h, &req);
		}
	} else {
		ret = KNOTD_ERROR;
	}

	/* Schedule EXPIRE timer on first attempt. */
	if (!zd->xfr_in.expire) {
		uint32_t expire_tmr = zones_soa_expire(zone);
		zd->xfr_in.expire = evsched_schedule_cb(
					      e->parent,
					      zones_expire_ev,
					      zone, expire_tmr);
		dbg_zones("zones: EXPIRE of '%s' after %u seconds\n",
		          zd->conf->name, expire_tmr / 1000);
	}

	/* Reschedule as RETRY timer. */
	evsched_schedule(e->parent, e, zones_soa_retry(zone));
	dbg_zones("zones: RETRY of '%s' after %u seconds\n",
	          zd->conf->name, zones_soa_retry(zone) / 1000);

	/* Unlock RCU. */
	rcu_read_unlock();

	return ret;
}

/*!
 * \brief Send NOTIFY to slave server.
 */
static int zones_notify_send(event_t *e)
{
	dbg_notify("notify: NOTIFY timer event\n");
	
	notify_ev_t *ev = (notify_ev_t *)e->data;
	knot_zone_t *zone = ev->zone;
	if (!zone) {
		log_zone_error("notify: NOTIFY invalid event received\n");
		evsched_event_free(e->parent, e);
		free(ev);
		return KNOTD_EINVAL;
	}

	/* Check for answered/cancelled query. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	knot_zone_contents_t *contents = knot_zone_get_contents(zone);

	/* Reduce number of available retries. */
	--ev->retries;

	/* Check number of retries. */
	if (ev->retries < 0) {
		log_server_notice("NOTIFY query maximum number of retries "
				  "for zone %s exceeded.\n",
				  zd->conf->name);
		pthread_mutex_lock(&zd->lock);
		rem_node(&ev->n);
		evsched_event_free(e->parent, e);
		free(ev);
		pthread_mutex_unlock(&zd->lock);
		return KNOTD_EMALF;
	}

	/* Prepare buffer for query. */
	uint8_t qbuf[SOCKET_MTU_SZ];
	size_t buflen = sizeof(qbuf);

        /* RFC suggests 60s, but it is configurable. */
        int retry_tmr = ev->timeout * 1000;
 
        /* Reschedule. */
        conf_read_lock();
        evsched_schedule(e->parent, e, retry_tmr);
        dbg_notify("notify: Query RETRY after %u secs (zone '%s')\n",
                   retry_tmr / 1000, zd->conf->name);
        conf_read_unlock();

	/* Create query. */
	int ret = notify_create_request(contents, qbuf, &buflen);
	if (ret == KNOTD_EOK && zd->server) {

		/* Lock RCU. */
		rcu_read_lock();

		/* Create socket on random port. */
		int sock = socket_create(ev->addr.family, SOCK_DGRAM);

		/* Send query. */
		ret = -1;
		if (sock > -1) {
			ret = sendto(sock, qbuf, buflen, 0,
				     ev->addr.ptr, ev->addr.len);
		}

		/* Store ID of the awaited response. */
		if (ret == buflen) {
			char r_addr[SOCKADDR_STRLEN];
			sockaddr_tostr(&ev->addr, r_addr, sizeof(r_addr));
			int r_port = sockaddr_portnum(&ev->addr);
			ev->msgid = knot_wire_get_id(qbuf);
			log_server_info("Issued NOTIFY query to %s:%d, expecting "
					"response ID=%d\n",
					r_addr, r_port,
					ev->msgid);
			
		}

		/* Watch socket. */
		knot_ns_xfr_t req;
		memset(&req, 0, sizeof(req));
		req.session = sock;
		req.type = XFR_TYPE_NOTIFY;
		req.zone = zone;
		memcpy(&req.addr, &ev->addr, sizeof(sockaddr_t));
		xfr_request(zd->server->xfr_h, &req);

		/* Unlock RCU */
		rcu_read_unlock();
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

	return KNOTD_EOK;
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
		return KNOTD_EINVAL;
	}

	/* Fetch zone data. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd) {
		return KNOTD_EINVAL;
	}

	/* Execute zonefile sync. */
	int ret = zones_zonefile_sync(zone);
	if (ret == KNOTD_EOK) {
		log_zone_info("Applied differences of '%s' to zonefile.\n",
		              zd->conf->name);
	} else if (ret != KNOTD_ERANGE) {
		log_zone_warning("Failed to apply differences of '%s' "
		                 "to zonefile.\n",
		                 zd->conf->name);
	}

	/* Reschedule. */
	conf_read_lock();
	evsched_schedule(e->parent, e, zd->conf->dbsync_timeout * 1000);
	dbg_zones("zones: next IXFR database SYNC of '%s' in %d seconds\n",
	          zd->conf->name, zd->conf->dbsync_timeout);
	conf_read_unlock();

	return ret;
}

/*!
 * \brief Update ACL list from configuration.
 *
 * \param acl Pointer to existing or NULL ACL.
 * \param acl_list List of remotes from configuration.
 *
 * \retval KNOTD_EOK on success.
 * \retval KNOTD_EINVAL on invalid parameters.
 * \retval KNOTD_ENOMEM on failed memory allocation.
 */
static int zones_set_acl(acl_t **acl, list* acl_list)
{
	if (!acl || !acl_list) {
		return KNOTD_EINVAL;
	}

	/* Truncate old ACL. */
	acl_delete(acl);

	/* Create new ACL. */
	*acl = acl_new(ACL_DENY, 0);
	if (!*acl) {
		return KNOTD_ENOMEM;
	}

	/* Load ACL rules. */
	conf_remote_t *r = 0;
	WALK_LIST(r, *acl_list) {

		/* Initialize address. */
		/*! Port matching disabled, port = 0. */
		sockaddr_t addr;
		conf_iface_t *cfg_if = r->remote;
		int ret = sockaddr_set(&addr, cfg_if->family,
				       cfg_if->address, 0);

		/* Load rule. */
		if (ret > 0) {
			acl_create(*acl, &addr, ACL_ACCEPT, cfg_if);
		}
	}

	return KNOTD_EOK;
}

/*!
 * \brief Load zone to zone database.
 *
 * \param zonedb Zone database to load the zone into.
 * \param zone_name Zone name (owner of the apex node).
 * \param source Path to zone file source.
 * \param filename Path to requested compiled zone file.
 *
 * \retval KNOTD_EOK
 * \retval KNOTD_EINVAL
 * \retval KNOTD_EZONEINVAL
 */
static int zones_load_zone(knot_zonedb_t *zonedb, const char *zone_name,
			   const char *source, const char *filename)
{
	knot_zone_t *zone = NULL;

	/* Check path */
	if (filename) {
		dbg_zones("zones: parsing zone database '%s'\n", filename);
		zloader_t *zl = 0;
		int ret = knot_zload_open(&zl, filename);
		switch(ret) {
		case KNOT_EOK:
			/* OK */
			break;
		case KNOT_EFEWDATA:
			log_server_error("Compiled zone db '%s' not exists.\n",
					 filename);
			return KNOTD_EZONEINVAL;
		case KNOT_ECRC:
			log_server_error("Compiled zone db CRC mismatches, "
					 "db is corrupted or .crc file is "
					 "deleted.\n");
			return KNOTD_EZONEINVAL;
		case KNOT_EMALF:
			log_server_error("Compiled db '%s' is too old, "
			                 " please recompile.\n",
			                 filename);
			return KNOTD_EZONEINVAL;
		case KNOT_ERROR:
		case KNOT_ENOMEM:
		default:
			log_server_error("Failed to read zone db file '%s'.\n",
					 filename);
			return KNOTD_EZONEINVAL;
		}

		/* Check if the db is up-to-date */
		int src_changed = strcmp(source, zl->source) != 0;
		if (src_changed || knot_zload_needs_update(zl)) {
			log_server_warning("Database for zone '%s' is not "
			                   "up-to-date. Please recompile.\n",
			                   zone_name);
		}

		zone = knot_zload_load(zl);
		
		/* Check loaded name. */
		const knot_dname_t *dname = knot_zone_name(zone);
		knot_dname_t *dname_req = 0;
		dname_req = knot_dname_new_from_str(zone_name,
		                                    strlen(zone_name), 0);
		if (knot_dname_compare(dname, dname_req) != 0) {
			log_server_warning("Origin of the zone db file is "
			                   "different than '%s'\n",
			                   zone_name);
			knot_zone_deep_free(&zone, 0);
			zone = 0;
			
		}
		knot_dname_free(&dname_req);

		/* CLEANUP */
		//knot_zone_contents_dump(zone->contents, 1);

		if (zone) {
			/* save the timestamp from the zone db file */
			struct stat s;
			if (stat(filename, &s) < 0) {
				dbg_zones("zones: failed to stat() zone db, "
					  "something is seriously wrong\n");
				knot_zone_deep_free(&zone, 0);
				zone = 0;
			} else {
				knot_zone_set_version(zone, s.st_mtime);
				if (knot_zonedb_add_zone(zonedb, zone) != 0){
					knot_zone_deep_free(&zone, 0);
					zone = 0;
				}
			}
		}

		knot_zload_close(zl);

		if (!zone) {
			log_server_error("Failed to load "
					 "db '%s' for zone '%s'.\n",
					 filename, zone_name);
			return KNOTD_EZONEINVAL;
		}
	} else {
		/* db is null. */
		return KNOTD_EINVAL;
	}

	/* CLEANUP */
//	knot_zone_dump(zone, 1);

	return KNOTD_EOK;
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

static int zones_changesets_from_binary(knot_changesets_t *chgsets)
{
	assert(chgsets != NULL);
	assert(chgsets->allocated >= chgsets->count);
	/*
	 * Parses changesets from the binary format stored in chgsets->data
	 * into the changeset_t structures.
	 */
	knot_rrset_t *rrset = 0;
	int ret = 0;

	for (int i = 0; i < chgsets->count; ++i) {

		/* Read initial changeset RRSet - SOA. */
		knot_changeset_t* chs = chgsets->sets + i;
		size_t remaining = chs->size;
		ret = knot_zload_rrset_deserialize(&rrset, chs->data, &remaining);
		if (ret != KNOT_EOK) {
			dbg_xfr("xfr: SOA: failed to deserialize data "
			        "from changeset, %s\n", knot_strerror(ret));
			return KNOTD_EMALF;
		}

		/* in this special case (changesets loaded
		 * from journal) the SOA serial should already
		 * be set, check it.
		 */
		assert(knot_rrset_type(rrset) == KNOT_RRTYPE_SOA);
		assert(chs->serial_from ==
		       knot_rdata_soa_serial(knot_rrset_rdata(rrset)));
		knot_changeset_store_soa(&chs->soa_from, &chs->serial_from,
					 rrset);

		dbg_xfr_verb("xfr: reading RRSets to REMOVE\n");

		/* Read remaining RRSets */
		int in_remove_section = 1;
		while (remaining > 0) {

			/* Parse next RRSet. */
			rrset = 0;
			uint8_t *stream = chs->data + (chs->size - remaining);
			ret = knot_zload_rrset_deserialize(&rrset, stream, &remaining);
			if (ret != KNOT_EOK) {
				dbg_xfr("xfr: failed to deserialize data "
				        "from changeset, %s\n",
				        knot_strerror(ret));
				return KNOTD_EMALF;
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
					knot_rrset_free(&rrset);
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
					return KNOTD_ERROR;
				}
			}
		}
		
		dbg_xfr_verb("xfr: read all RRSets in changeset\n");
	}

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_load_changesets(const knot_zone_t *zone, 
                                 knot_changesets_t *dst,
                                 uint32_t from, uint32_t to)
{
	if (!zone || !dst) {
		dbg_zones_detail("Bad arguments: zone=%p, dst=%p\n", zone, dst);
		return KNOTD_EINVAL;
	}
	if (!zone->data) {
		dbg_zones_detail("Bad arguments: zone->data=%p\n", zone->data);
		return KNOTD_EINVAL;
	}
	
	dbg_xfr("Loading changesets from serial %u to %u\n", from, to);

	/* Fetch zone-specific data. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd->ixfr_db) {
		dbg_zones_detail("Bad arguments: zd->ixfr_db=%p\n", zone->data);
		return KNOTD_EINVAL;
	}

	/* Read entries from starting serial until finished. */
	uint32_t found_to = from;
	journal_node_t *n = 0;
	int ret = journal_fetch(zd->ixfr_db, from, ixfrdb_key_from_cmp, &n);
	if (ret != KNOTD_EOK) {
		dbg_xfr("xfr: failed to fetch starting changeset: %s\n",
		        knotd_strerror(ret));
		return ret;
	}
	
	while (n != 0 && n != journal_end(zd->ixfr_db)) {

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
			--dst->count;
			dbg_xfr("xfr: failed to check changesets size: %s\n",
			        knot_strerror(ret));
			return KNOTD_ERROR;
		}

		/* Initialize changeset. */
		dbg_xfr_detail("xfr: reading entry #%zu id=%llu\n",
		               dst->count, (unsigned long long)n->id);
		knot_changeset_t *chs = dst->sets + dst->count;
		chs->serial_from = ixfrdb_key_from(n->id);
		chs->serial_to = ixfrdb_key_to(n->id);
		chs->data = malloc(n->len);
		if (!chs->data) {
			return KNOTD_ENOMEM;
		}

		/* Read journal entry. */
		ret = journal_read(zd->ixfr_db, n->id,
				   0, (char*)chs->data);
		if (ret != KNOTD_EOK) {
			dbg_xfr("xfr: failed to read data from journal\n");
			free(chs->data);
			return KNOTD_ERROR;
		}

		/* Update changeset binary size. */
		chs->size = chs->allocated = n->len;

		/* Next node. */
		found_to = chs->serial_to;
		++dst->count;
		++n;

		/*! \todo Check consistency. */
	}
	
	dbg_xfr_detail("xfr: Journal entries read.\n");

	/* Unpack binary data. */
	int unpack_ret = zones_changesets_from_binary(dst);
	if (unpack_ret != KNOT_EOK) {
		dbg_xfr("xfr: failed to unpack changesets "
		        "from binary, %s\n", knot_strerror(unpack_ret));
		return KNOTD_ERROR;
	}

	/* Check for complete history. */
	if (to != found_to) {
		dbg_xfr_detail("Returning ERANGE\n");
		return KNOTD_ERANGE;
	}

	/* History reconstructed. */
	dbg_xfr_detail("Returning EOK\n");
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Apply changesets to zone from journal.
 *
 * \param zone Specified zone.
 *
 * \retval KNOTD_EOK if successful.
 * \retval KNOTD_EINVAL on invalid parameters.
 * \retval KNOTD_ENOENT if zone has no contents.
 * \retval KNOTD_ERROR on unspecified error.
 */
static int zones_journal_apply(knot_zone_t *zone)
{
	/* Fetch zone. */
	if (!zone) {
		return KNOTD_EINVAL;
	}

	knot_zone_contents_t *contents = knot_zone_get_contents(zone);
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!contents || !zd) {
		return KNOTD_ENOENT;
	}

	/* Fetch SOA serial. */
	const knot_rrset_t *soa_rrs = 0;
	const knot_rdata_t *soa_rr = 0;
	soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
	                            KNOT_RRTYPE_SOA);
	soa_rr = knot_rrset_rdata(soa_rrs);
	int64_t serial_ret = knot_rdata_soa_serial(soa_rr);
	if (serial_ret < 0) {
		return KNOTD_EINVAL;
	}
	uint32_t serial = (uint32_t)serial_ret;

	/* Load all pending changesets. */
	dbg_zones_verb("zones: loading all changesets of '%s' from SERIAL %u\n",
	               zd->conf->name, serial);
	knot_changesets_t* chsets = malloc(sizeof(knot_changesets_t));
	memset(chsets, 0, sizeof(knot_changesets_t));
	/*! \todo Check what should be the upper bound. */
	int ret = zones_load_changesets(zone, chsets, serial, serial - 1);
	if (ret == KNOTD_EOK || ret == KNOTD_ERANGE) {
		if (chsets->count > 0) {
			/* Apply changesets. */
			log_server_info("Applying '%zu' changesets from journal "
			                "to zone '%s'.\n",
			                chsets->count, zd->conf->name);
			int apply_ret = xfrin_apply_changesets_to_zone(zone, chsets);
			if (apply_ret != KNOT_EOK) {
				log_server_error("Failed to apply changesets to "
				                 "'%s' - %s\n",
				                 zd->conf->name,
				                 knot_strerror(apply_ret));
				ret = KNOTD_ERROR;
			}
		}
	} else {
		dbg_zones("zones: failed to load changesets - %s\n",
		          knotd_strerror(ret));
	}

	/* Free changesets and return. */
	knot_free_changesets(&chsets);
	return ret;
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Fill the new database with zones.
 *
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param ns Name server instance.
 * \param zone_conf Zone configuration.
 * \param db_old Old zone database.
 * \param db_new New zone database.
 *
 * \return Number of inserted zones.
 */
static int zones_insert_zones(knot_nameserver_t *ns,
			      const list *zone_conf,
                              const knot_zonedb_t *db_old,
                              knot_zonedb_t *db_new)
{
	/*! \todo Change to zone contents. */

	node *n = 0;
	int inserted = 0;
	/* for all zones in the configuration */
	WALK_LIST(n, *zone_conf) {
		conf_zone_t *z = (conf_zone_t *)n;

		/* Convert the zone name into a domain name. */
		/* Local allocation, will be discarded. */
		knot_dname_t *zone_name = knot_dname_new_from_str(z->name,
		                                         strlen(z->name), NULL);
		if (zone_name == NULL) {
			log_server_error("Error creating domain name from zone"
			                 " name\n");
			return inserted;
		}

		dbg_zones_verb("zones: inserting zone %s into the new database.\n",
		               z->name);

		/* try to find the zone in the current zone db */
		knot_zone_t *zone = knot_zonedb_find_zone(db_old,
		                                          zone_name);
		int reload = 0;

		/* Attempt to bootstrap if db or source does not exist. */
		struct stat s;
		int stat_ret = stat(z->file, &s);
		if (zone != NULL) {
			/* if found, check timestamp of the file against the
			 * loaded zone
			 */
			if (knot_zone_version(zone) < s.st_mtime) {
				/* the file is newer, reload! */
				reload = 1;
			}
		} else {
			reload = 1;
		}

		/* Reload zone file. */
		int ret = KNOTD_ERROR;
		if (reload) {
			/* Zone file not exists and has master set. */
			if (stat_ret < 0 && !EMPTY_LIST(z->acl.xfr_in)) {

				/* Create stub database. */
				dbg_zones_verb("zones: loading stub zone '%s' "
				               "for bootstrap.\n",
				               z->name);
				knot_dname_t *owner = 0;
				owner = knot_dname_deep_copy(zone_name);
				knot_zone_t* sz = knot_zone_new_empty(owner);
				if (sz) {
					/* Add stub zone to db_new. */
					ret = knot_zonedb_add_zone(db_new, sz);
					if (ret != KNOT_EOK) {
						dbg_zones("zones: failed to add "
						          "stub zone '%s'.\n",
						          z->name);
						knot_zone_deep_free(&sz, 0);
						sz = 0;
						ret = KNOTD_ERROR;
					} else {
						log_server_info("Will attempt to "
								"bootstrap zone "
								"%s from AXFR "
								"master.\n",
								z->name);
						--inserted;
					}

				} else {
					dbg_zones("zones: failed to create "
					          "stub zone '%s'.\n",
					          z->name);
					ret = KNOTD_ERROR;
				}

			} else {
				dbg_zones_verb("zones: loading zone '%s' "
				               "from '%s'\n",
				               z->name,
				               z->db);
				ret = zones_load_zone(db_new, z->name,
							  z->file, z->db);
				if (ret == KNOTD_EOK) {
					log_server_info("Loaded zone '%s'\n",
					                z->name);
				} else {
					log_server_error("Failed to load zone "
					                 "'%s' - %s\n",
					                 z->name,
					                 knotd_strerror(ret));
				}
			}

			/* Find zone. */
			if (ret == KNOTD_EOK) {
				/* Find the new zone */
				zone = knot_zonedb_find_zone(db_new,
				                             zone_name);
				++inserted;
				
				dbg_zones_verb("zones: inserted '%s' into "
				               "database, initializing data\n",
				               z->name);

				/* Initialize zone-related data. */
				zonedata_init(z, zone);

			}
			/* unused return value, if not loaded, just continue */
		} else {
			/* just insert the zone into the new zone db */
			dbg_zones_verb("zones: found '%s' in old database, "
			               "copying to new.\n",
			               z->name);
			log_server_info("Zone '%s' is up-to-date, no need "
			                "for reload.\n", z->name);
			int ret = knot_zonedb_add_zone(db_new, zone);
			if (ret != KNOT_EOK) {
				log_server_error("Error adding known zone '%s' to"
				                 " the new database - %s\n",
				                 z->name, knot_strerror(ret));
			} else {
				++inserted;
			}
		}

		/* Update zone data. */
		if (zone) {
			zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);

			/* Update refs. */
			zd->conf = z;

			/* Update ACLs. */
			dbg_zones("Updating zone ACLs.\n");
			zones_set_acl(&zd->xfr_in.acl, &z->acl.xfr_in);
			zones_set_acl(&zd->xfr_out, &z->acl.xfr_out);
			zones_set_acl(&zd->notify_in, &z->acl.notify_in);
			zones_set_acl(&zd->notify_out, &z->acl.notify_out);

			/* Update server pointer. */
			zd->server = (server_t *)knot_ns_get_data(ns);

			/* Update master server address. */
			memset(&zd->xfr_in.tsig_key, 0, sizeof(knot_key_t));
			sockaddr_init(&zd->xfr_in.master, -1);
			if (!EMPTY_LIST(z->acl.xfr_in)) {
				conf_remote_t *r = HEAD(z->acl.xfr_in);
				conf_iface_t *cfg_if = r->remote;
				sockaddr_set(&zd->xfr_in.master,
					     cfg_if->family,
					     cfg_if->address,
					     cfg_if->port);

				if (cfg_if->key) {
					memcpy(&zd->xfr_in.tsig_key,
					       cfg_if->key,
					       sizeof(knot_key_t));
				}

				dbg_zones("zones: using %s:%d as XFR master "
				          "for '%s'\n",
				          cfg_if->address,
				          cfg_if->port,
				          z->name);
			}

			/* Apply changesets from journal. */
			zones_journal_apply(zone);

			/* Update events scheduled for zone. */
			zones_timers_update(zone, z, 
			             ((server_t *)knot_ns_get_data(ns))->sched);
		}

		/* CLEANUP */
//		knot_zone_contents_dump(knot_zone_get_contents(zone), 1);

		/* Directly discard zone. */
		knot_dname_free(&zone_name);
	}
	return inserted;
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
 * \retval KNOTD_EOK
 * \retval KNOTD_ERROR
 */
static int zones_remove_zones(const knot_zonedb_t *db_new,
                              knot_zonedb_t *db_old)
{
	const knot_zone_t **new_zones = knot_zonedb_zones(db_new);
	if (new_zones == NULL) {
		return KNOTD_ENOMEM;
	}

	for (int i = 0; i < knot_zonedb_zone_count(db_new); ++i) {
		/* try to find the new zone in the old DB
		 * if the pointers match, remove the zone from old DB
		 */
		/*! \todo Find better way of removing zone with given pointer.*/
		knot_zone_t *old_zone = knot_zonedb_find_zone(
		                        db_old, knot_zone_name(new_zones[i]));
		if (old_zone == new_zones[i]) {
dbg_zones_exec(
			char *name = knot_dname_to_str(knot_zone_name(old_zone));
			dbg_zones_verb("zones: zone pointers match, removing zone %s "
                                       "from database.\n", name);
			free(name);
);
			knot_zone_t * rm = knot_zonedb_remove_zone(db_old,
			                              knot_zone_name(old_zone));
			assert(rm == old_zone);
		}
	}

	free(new_zones);

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_verify_tsig_query(const knot_packet_t *query,
                                   const knot_rrset_t *tsig_rr,
                                   const knot_key_t *key,
                                   knot_rcode_t *rcode, uint16_t *tsig_rcode,
                                   uint64_t *tsig_prev_time_signed)
{
	assert(tsig_rr != NULL);
	assert(key != NULL);
	assert(rcode != NULL);
	assert(tsig_rcode != NULL);

	/*
	 * 1) Check if we support the requested algorithm.
	 */
	tsig_algorithm_t alg = tsig_rdata_alg(tsig_rr);
	if (tsig_alg_digest_length(alg) == 0) {
		log_answer_info("Unsupported digest algorithm "
		                "requested, treating as bad key\n");
		/*! \todo [TSIG] It is unclear from RFC if I
		 *               should treat is as a bad key
		 *               or some other error.
		 */
		*rcode = KNOT_RCODE_NOTAUTH;
		*tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
		return KNOT_TSIG_EBADKEY;
	}

	const knot_dname_t *kname = knot_rrset_owner(tsig_rr);
	assert(kname != NULL);

	/*
	 * 2) Find the particular key used by the TSIG.
	 */
	if (key && kname && knot_dname_compare(key->name, kname) == 0) {
		dbg_zones_verb("Found claimed TSIG key for comparison\n");
	} else {
		*rcode = KNOT_RCODE_NOTAUTH;
		*tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
		return KNOT_TSIG_EBADKEY;
	}

	/*
	 * 3) Validate the query with TSIG.
	 */
	/* Prepare variables for TSIG */
	/*! \todo These need to be saved to the response somehow. */
	//size_t tsig_size = tsig_wire_maxsize(key);
	size_t digest_max_size = tsig_alg_digest_length(key->algorithm);
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
			*tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_TSIG_EBADSIG:
			*tsig_rcode = KNOT_TSIG_RCODE_BADSIG;
			*rcode = KNOT_RCODE_NOTAUTH;
			break;
		case KNOT_TSIG_EBADTIME:
			*tsig_rcode = KNOT_TSIG_RCODE_BADTIME;
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

/*----------------------------------------------------------------------------*/

static int zones_check_tsig_query(const knot_zone_t *zone,
                                  knot_packet_t *query,
                                  const sockaddr_t *addr,
                                  knot_rcode_t *rcode,
                                  uint16_t *tsig_rcode,
                                  knot_key_t **tsig_key_zone,
                                  uint64_t *tsig_prev_time_signed)
{
	assert(zone != NULL);
	assert(query != NULL);
	assert(rcode != NULL);
	assert(tsig_key_zone != NULL);

	knot_rrset_t *tsig = NULL;

	if (knot_packet_additional_rrset_count(query) > 0) {
		/*! \todo warning */
		tsig = knot_packet_additional_rrset(query,
		                 knot_packet_additional_rrset_count(query) - 1);
		if (knot_rrset_type(tsig) == KNOT_RRTYPE_TSIG) {
			dbg_zones_verb("found TSIG in normal query\n");
        } else {
            tsig = NULL; /* Invalidate if not TSIG RRTYPE. */
        }
	}

	if (tsig == NULL) {
		// no TSIG, this is completely valid
		*tsig_rcode = 0;
		return KNOT_EOK;
	}

	// if there is some TSIG in the query, find the TSIG associated with
	// the zone
	//knot_key_t *tsig_key_zone = NULL;

	dbg_zones_verb("Checking zone and ACL.\n");
	int ret = zones_query_check_zone(zone, addr, tsig_key_zone, rcode);

	/*! \todo What if there is TSIG, but no key is configured? */

	if (ret == KNOTD_EOK) {
		if (*tsig_key_zone != NULL) {
			// everything OK, so check TSIG
			dbg_zones_verb("Verifying TSIG.\n");
			ret = zones_verify_tsig_query(query, tsig, *tsig_key_zone,
			                              rcode, tsig_rcode,
			                              tsig_prev_time_signed);
		} else {
			dbg_zones_verb("No key configured for zone.\n");
			// no key configured for zone, return BADKEY
			*tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
			*rcode = KNOT_RCODE_NOTAUTH;
			ret = KNOT_TSIG_EBADKEY;
		}
	}

	// save TSIG RR to query structure
	knot_packet_set_tsig(query, tsig);

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
		return KNOTD_EINVAL;
	}

	/* Lock RCU to ensure none will deallocate any data under our hands. */
	rcu_read_lock();

	/* Grab a pointer to the old database */
	*db_old = ns->zone_db;
	if (*db_old == NULL) {
		log_server_error("Missing zone database in nameserver structure"
		                 ".\n");
		return KNOTD_ERROR;
	}

	/* Create new zone DB */
	knot_zonedb_t *db_new = knot_zonedb_new();
	if (db_new == NULL) {
		return KNOTD_ERROR;
	}

	log_server_info("Loading %d compiled zones...\n", conf->zones_count);

	/* Insert all required zones to the new zone DB. */
	int inserted = zones_insert_zones(ns, &conf->zones, *db_old, db_new);

	log_server_info("Loaded %d out of %d zones.\n", inserted,
	                conf->zones_count);

	if (inserted != conf->zones_count) {
		log_server_warning("Not all the zones were loaded.\n");
	}

	dbg_zones_detail("zones: old db in nameserver: %p, old db stored: %p, "
	                 "new db: %p\n", ns->zone_db, *db_old, db_new);

	/* Switch the databases. */
	(void)rcu_xchg_pointer(&ns->zone_db, db_new);

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
	if (ret != KNOTD_EOK) {
		return ret;
	}

	/* Unlock RCU, messing with any data will not affect us now */
	rcu_read_unlock();

	return KNOTD_EOK;
}

int zones_zonefile_sync(knot_zone_t *zone)
{
	if (!zone) {
		return KNOTD_EINVAL;
	}
	if (!zone->data) {
		return KNOTD_EINVAL;
	}

	/* Fetch zone data. */
	int ret = KNOTD_EOK;
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Lock zone data. */
	pthread_mutex_lock(&zd->lock);

	knot_zone_contents_t *contents = knot_zone_get_contents(zone);
	if (!contents) {
		pthread_mutex_unlock(&zd->lock);
		return KNOTD_EINVAL;
	}

	/* Latest zone serial. */
	const knot_rrset_t *soa_rrs = 0;
	const knot_rdata_t *soa_rr = 0;
	soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
	                            KNOT_RRTYPE_SOA);
	soa_rr = knot_rrset_rdata(soa_rrs);
	int64_t serial_ret = knot_rdata_soa_serial(soa_rr);
	if (serial_ret < 0) {
		pthread_mutex_unlock(&zd->lock);
		return KNOTD_EINVAL;
	}
	uint32_t serial_to = (uint32_t)serial_ret;

	/* Check for difference against zonefile serial. */
	if (zd->zonefile_serial != serial_to) {

		/* Save zone to zonefile. */
		conf_read_lock();
		dbg_zones("zones: syncing '%s' differences to '%s' "
		          "(SOA serial %u)\n",
		          zd->conf->name, zd->conf->file, serial_to);
		zone_dump_text(contents, zd->conf->file);
		conf_read_unlock();

		/* Update journal entries. */
		dbg_zones_verb("zones: unmarking all dirty nodes "
		               "in '%s' journal\n",
		               zd->conf->name);
		journal_walk(zd->ixfr_db, zones_ixfrdb_sync_apply);

		/* Update zone file serial. */
		dbg_zones("zones: new '%s' zonefile serial is %u\n",
		          zd->conf->name, serial_to);
		zd->zonefile_serial = serial_to;
	} else {
		dbg_zones_verb("zones: '%s' zonefile is in sync "
		               "with differences\n", zd->conf->name);
		ret = KNOTD_ERANGE;
	}

	/* Unlock zone data. */
	pthread_mutex_unlock(&zd->lock);

	return ret;
}

/*----------------------------------------------------------------------------*/

int zones_query_check_zone(const knot_zone_t *zone, const sockaddr_t *addr,
                           knot_key_t **tsig_key, knot_rcode_t *rcode)
{
	if (addr == NULL || tsig_key == NULL || rcode == NULL) {
		dbg_zones_verb("Wrong arguments.\n");
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_EINVAL;
	}

	/* Check zone data. */
	const zonedata_t *zd = (const zonedata_t *)knot_zone_data(zone);
	if (zd == NULL) {
		dbg_zones("zones: invalid zone data for zone %p\n", zone);
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_ERROR;
	}

	/* Check xfr-out ACL */
	acl_key_t *match = NULL;
	if (acl_match(zd->xfr_out, addr, &match) == ACL_DENY) {
		log_answer_warning("Unauthorized query or request for XFR "
		                   "'%s/OUT'.\n", zd->conf->name);
		*rcode = KNOT_RCODE_REFUSED;
		return KNOTD_EACCES;
	} else {
		dbg_zones("zones: authorized query or request for XFR "
		          "'%s/OUT'. match=%p\n", zd->conf->name, match);
		if (match) {
			/* Save configured TSIG key for comparison. */
			conf_iface_t *iface = (conf_iface_t*)(match->val);
			dbg_zones_detail("iface=%p, iface->key=%p\n",
					 iface, iface->key);
			*tsig_key = iface->key;
		}
	}
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_xfr_check_zone(knot_ns_xfr_t *xfr, knot_rcode_t *rcode)
{
	if (xfr == NULL || rcode == NULL) {
		return KNOTD_EINVAL;
	}

	/* Check if the zone is found. */
	if (xfr->zone == NULL) {
		*rcode = KNOT_RCODE_REFUSED;
		return KNOTD_EACCES;
	}

	/* Check zone contents. */
	if (knot_zone_contents(xfr->zone) == NULL) {
		dbg_zones("zones: invalid zone contents for zone %p\n",
		          xfr->zone);
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_EEXPIRED;
	}

	return zones_query_check_zone(xfr->zone, &xfr->addr, &xfr->tsig_key,
	                              rcode);
}

/*----------------------------------------------------------------------------*/

int zones_normal_query_answer(knot_nameserver_t *nameserver,
                              knot_packet_t *query, const sockaddr_t *addr,
                              uint8_t *resp_wire, size_t *rsize)
{
	rcu_read_lock();

	knot_packet_t *resp = NULL;
	const knot_zone_t *zone = NULL;

	dbg_zones_verb("Preparing response structure.\n");
	int ret = knot_ns_prep_normal_response(nameserver, query, &resp, &zone);

	// check for TSIG in the query
	if (knot_packet_additional_rrset_count(query) > 0) {
		/*! \todo warning */
		const knot_rrset_t *tsig = knot_packet_additional_rrset(query,
		                 knot_packet_additional_rrset_count(query) - 1);
		if (knot_rrset_type(tsig) == KNOT_RRTYPE_TSIG) {
			dbg_zones_verb("found TSIG in normal query\n");
			knot_packet_set_tsig(query, tsig);
		}
	}

	knot_rcode_t rcode = 0;

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

	if (zone == NULL && knot_packet_tsig(query) == NULL) {
		/*! \todo If there is TSIG, this should be probably handled
		 *        as a key error.
		 */
		rcode = KNOT_RCODE_REFUSED;
	}

	assert(resp != NULL);

	if (rcode != KNOT_RCODE_NOERROR) {
		dbg_zones_verb("Failed preparing response structure: %s.\n",
		               knot_strerror(rcode));
		knot_ns_error_response(nameserver, knot_packet_id(query),
		                       rcode, resp_wire, rsize);
	} else {
		/*
		 * Now we have zone. Verify TSIG if it is in the packet.
		 */
		assert(rcode == KNOT_RCODE_NOERROR);
		uint16_t tsig_rcode = 0;
		knot_key_t *tsig_key_zone = NULL;
        uint64_t tsig_prev_time_signed = 0; /*! \todo Verify, as it was uninitialized! */

		size_t answer_size = *rsize;
		int ret = KNOT_EOK;

		if (zone == NULL) {
			assert(knot_packet_tsig(query) != NULL);
			// treat as BADKEY error
			rcode = KNOT_RCODE_NOTAUTH;
			tsig_rcode = KNOT_TSIG_RCODE_BADKEY;
			ret = KNOT_TSIG_EBADKEY;
		} else {
			dbg_zones_verb("Checking TSIG in query.\n");
			ret = zones_check_tsig_query(zone, query, addr,
			                             &rcode, &tsig_rcode,
			                             &tsig_key_zone,
			                             &tsig_prev_time_signed);
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
			ret = knot_ns_answer_normal(nameserver, zone, resp,
			                            resp_wire, &answer_size);

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
				                tsig_alg_digest_length(
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
				    tsig_rcode != KNOT_TSIG_RCODE_BADTIME) {
					dbg_zones_verb("Adding TSIG.\n");
					ret = knot_tsig_add(resp_wire,
					                    &answer_size,
					                    *rsize, tsig_rcode,
					                     knot_packet_tsig(
					                            query));

					*rsize = answer_size;

				} else if (tsig_rcode
				           == KNOT_TSIG_RCODE_BADTIME) {
					dbg_zones_verb("Signing error resp.\n");
					//*rsize = answer_size;

					const knot_rrset_t *tsig =
					      knot_packet_tsig(
					          knot_packet_query(resp));

					size_t digest_max_size =
					           tsig_alg_digest_length(
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

int zones_process_response(knot_nameserver_t *nameserver, 
                           sockaddr_t *from,
                           knot_packet_t *packet, uint8_t *response_wire,
                           size_t *rsize)
{
	if (!packet || !rsize || nameserver == NULL || from == NULL ||
	    response_wire == NULL) {
		return KNOTD_EINVAL;
	}

	/* Handle SOA query response, cancel EXPIRE timer
	 * and start AXFR transfer if needed.
	 * Reset REFRESH timer on finish.
	 */
	if (knot_packet_qtype(packet) == KNOT_RRTYPE_SOA) {
		
		if (knot_packet_rcode(packet) != KNOT_RCODE_NOERROR) {
			/*! \todo Handle error response. */
			return KNOTD_ERROR;
		}

		/* No response. */
		*rsize = 0;

		/* Find matching zone and ID. */
		const knot_dname_t *zone_name = knot_packet_qname(packet);
		/*! \todo Change the access to the zone db. */
		knot_zone_t *zone = knot_zonedb_find_zone(
		                        nameserver->zone_db,
		                        zone_name);

		/* Get zone contents. */
		rcu_read_lock();
		const knot_zone_contents_t *contents =
				knot_zone_contents(zone);

		if (!zone || !knot_zone_data(zone) || !contents) {
			rcu_read_unlock();
			return KNOTD_EINVAL;
		}

		/* Match ID against awaited. */
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		uint16_t pkt_id = knot_packet_id(packet);
		if ((int)pkt_id != zd->xfr_in.next_id) {
			rcu_read_unlock();
			return KNOTD_ERROR;
		}

		/* Check SOA SERIAL. */
		int ret = xfrin_transfer_needed(contents, packet);
		dbg_zones_verb("xfrin_transfer_needed() returned %d\n", ret);
		if (ret < 0) {
			/* RETRY/EXPIRE timers running, do not interfere. */
			return KNOTD_ERROR;
		}
		
		/* No updates available. */
		evsched_t *sched =
			((server_t *)knot_ns_get_data(nameserver))->sched;
		if (ret == 0) {
			log_zone_info("SOA query for zone '%s' answered, no "
				      "transfer needed.\n", zd->conf->name);
			rcu_read_unlock();

			/* Reinstall timers. */
			zones_timers_update(zone, zd->conf, sched);
			return KNOTD_EOK;
		}
		
		assert(ret > 0);
		
		/* Already transferring. */
		if (pthread_mutex_trylock(&zd->xfr_in.lock) != 0) {
			/* Unlock zone contents. */
			dbg_zones("zones: SOA response received, but zone is "
			          "being transferred, refusing to start another "
			          "transfer\n");
			rcu_read_unlock();
			return KNOTD_EOK;
		} else {
			pthread_mutex_unlock(&zd->xfr_in.lock);
		}

		/* Prepare XFR client transfer. */
		knot_ns_xfr_t xfr_req;
		memset(&xfr_req, 0, sizeof(knot_ns_xfr_t));
		memcpy(&xfr_req.addr, from, sizeof(sockaddr_t));
		xfr_req.zone = (void *)zone;
		xfr_req.send = zones_send_cb;

		/* Select transfer method. */
		xfr_req.type = zones_transfer_to_use(contents);
		
		/* Select TSIG key. */
		if (zd->xfr_in.tsig_key.name) {
			xfr_req.tsig_key = &zd->xfr_in.tsig_key;
		}

		/* Unlock zone contents. */
		rcu_read_unlock();

		/* Enqueue XFR request. */
		return xfr_request(((server_t *)knot_ns_get_data(
		                     nameserver))->xfr_h, &xfr_req);
	}


	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

knot_ns_xfr_type_t zones_transfer_to_use(const knot_zone_contents_t *zone)
{
	/*! \todo Implement. */
	return XFR_TYPE_IIN;
}

/*----------------------------------------------------------------------------*/

static int zones_find_zone_for_xfr(const knot_zone_contents_t *zone, 
                                   const char **zonefile, const char **zonedb)
{
	/* find the zone file name and zone db file name for the zone */
	conf_t *cnf = conf();
	node *n = NULL;
	WALK_LIST(n, cnf->zones) {
		conf_zone_t *zone_conf = (conf_zone_t *)n;
		knot_dname_t *zone_name = knot_dname_new_from_str(
			zone_conf->name, strlen(zone_conf->name), NULL);
		if (zone_name == NULL) {
			return KNOTD_ENOMEM;
		}

		int r = knot_dname_compare(zone_name, knot_node_owner(
		                              knot_zone_contents_apex(zone)));

		/* Directly discard dname, won't be needed. */
		knot_dname_free(&zone_name);

		if (r == 0) {
			/* found the right zone */
			*zonefile = zone_conf->file;
			*zonedb = zone_conf->db;
			return KNOTD_EOK;
		}
	}

	char *name = knot_dname_to_str(knot_node_owner(
	                 knot_zone_contents_apex(zone)));
	dbg_zones("zones: no zone found for the zone received by transfer "
	          "(%s).\n", name);
	free(name);

	return KNOTD_ENOENT;
}

/*----------------------------------------------------------------------------*/

static char *zones_find_free_filename(const char *old_name)
{
	/* find zone name not present on the disk */
	int free_name = 0;
	size_t name_size = strlen(old_name);

	char *new_name = malloc(name_size + 3);
	if (new_name == NULL) {
		return NULL;
	}
	memcpy(new_name, old_name, name_size);
	new_name[name_size] = '.';
	new_name[name_size + 2] = 0;

	dbg_zones_verb("zones: finding free name for the zone file.\n");
	int c = 48;
	FILE *file;
	while (!free_name && c < 58) {
		new_name[name_size + 1] = c;
		dbg_zones_verb("zones: trying file name %s\n", new_name);
		if ((file = fopen(new_name, "r")) != NULL) {
			fclose(file);
			++c;
		} else {
			free_name = 1;
		}
	}

	if (free_name) {
		return new_name;
	} else {
		free(new_name);
		return NULL;
	}
}

/*----------------------------------------------------------------------------*/

static int zones_dump_xfr_zone_text(knot_zone_contents_t *zone, 
                                    const char *zonefile)
{
	assert(zone != NULL && zonefile != NULL);

	/*! \todo new_zonefile may be created by another process,
	 *        until the zone_dump_text is called. Needs to be opened in
	 *        this function for writing.
	 *        Use open() for exclusive open and fcntl() for locking.
	 */

	char *new_zonefile = zones_find_free_filename(zonefile);

	if (new_zonefile == NULL) {
		log_zone_warning("Failed to find filename for temporary "
		                 "storage of the transferred zone.\n");
		return KNOTD_ERROR;	/*! \todo New error code? */
	}

	int rc = zone_dump_text(zone, new_zonefile);

	if (rc != KNOTD_EOK) {
		log_zone_warning("Failed to save the transferred zone to '%s'.\n",
		                 new_zonefile);
		free(new_zonefile);
		return KNOTD_ERROR;
	}

	/*! \todo this would also need locking as well. */
	remove(zonefile); /* Don't care, as the rename will trigger the error. */
	if (rename(new_zonefile, zonefile) != 0) {
		log_zone_warning("Failed to replace old zone file '%s'' with a new"
		                 " zone file '%s'.\n", zonefile, new_zonefile);
		/*! \todo with proper locking, this shouldn't happen,
		 *        revise it later on.
		 */
		zone_dump_text(zone, zonefile);
		free(new_zonefile);
		return KNOTD_ERROR;
	}


	free(new_zonefile);
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

static int ns_dump_xfr_zone_binary(knot_zone_contents_t *zone, 
                                   const char *zonedb,
                                   const char *zonefile)
{
	assert(zone != NULL && zonedb != NULL);

	/*! \todo new_zonedb may be created by another process,
	 *        until the zone_dump_text is called. Needs to be opened in
	 *        this function for writing.
	 *        Use open() for exclusive open and fcntl() for locking.
	 */
	char *new_zonedb = zones_find_free_filename(zonedb);

	if (new_zonedb == NULL) {
		dbg_zones("zones: failed to find free filename for temporary "
		          "storage of the zone binary file '%s'\n",
		          zonedb);
		return KNOTD_ERROR;	/*! \todo New error code? */
	}

	/*! \todo this would also need locking as well. */
	int rc = knot_zdump_dump_and_swap(zone, new_zonedb, zonedb, zonefile);
	free(new_zonedb);

	if (rc != KNOT_EOK) {
		return KNOTD_ERROR;
	}


	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_save_zone(const knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || xfr->data == NULL) {
		return KNOTD_EINVAL;
	}
	
	knot_zone_contents_t *zone = 
		(knot_zone_contents_t *)xfr->data;
	
	const char *zonefile = NULL;
	const char *zonedb = NULL;
	
	int ret = zones_find_zone_for_xfr(zone, &zonefile, &zonedb);
	if (ret != KNOTD_EOK) {
		return ret;
	}
	
	assert(zonefile != NULL && zonedb != NULL);
	
	/* dump the zone into text zone file */
	ret = zones_dump_xfr_zone_text(zone, zonefile);
	if (ret != KNOTD_EOK) {
		return KNOTD_ERROR;
	}
	/* dump the zone into binary db file */
	ret = ns_dump_xfr_zone_binary(zone, zonedb, zonefile);
	if (ret != KNOTD_EOK) {
		return KNOTD_ERROR;
	}
	
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_ns_conf_hook(const struct conf_t *conf, void *data)
{
	knot_nameserver_t *ns = (knot_nameserver_t *)data;
	dbg_zones_verb("zones: reconfiguring name server.\n");

	knot_zonedb_t *old_db = 0;

	int ret = zones_update_db_from_config(conf, ns, &old_db);
	if (ret != KNOTD_EOK) {
		return ret;
	}
	/* Wait until all readers finish with reading the zones. */
	synchronize_rcu();

	dbg_zones_verb("zones: nameserver's zone db: %p, old db: %p\n",
	               ns->zone_db, old_db);

	/* Delete all deprecated zones and delete the old database. */
	knot_zonedb_deep_free(&old_db);

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_check_binary_size(uint8_t **data, size_t *allocated,
                                   size_t required)
{
	if (required <= *allocated) {
		return KNOTD_EOK;
	}

	/* Allocate new memory block. */
	size_t new_count = required;
	uint8_t *new_data = malloc(new_count * sizeof(uint8_t));
	if (new_data == NULL) {
		return KNOTD_ENOMEM;
	}

	/* Clear memory block and copy old data. */
	memset(new_data, 0, new_count * sizeof(uint8_t));
	memcpy(new_data, *data, *allocated);

	/* Switch pointers and free old pointer. */
	free(*data);
	*data = new_data;
	*allocated = new_count;

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_changeset_rrset_to_binary(uint8_t **data, size_t *size,
                                           size_t *allocated,
                                           knot_rrset_t *rrset)
{
	assert(data != NULL);
	assert(size != NULL);
	assert(allocated != NULL);

	/*
	 * In *data, there is the whole changeset in the binary format,
	 * the actual RRSet will be just appended to it
	 */

	uint8_t *binary = NULL;
	size_t actual_size = 0;
	int ret = knot_zdump_rrset_serialize(rrset, &binary, &actual_size);
	if (ret != KNOT_EOK || binary == NULL) {
		return KNOTD_ERROR;  /*! \todo Other code? */
	}

	ret = zones_check_binary_size(data, allocated, *size + actual_size);
	if (ret != KNOT_EOK) {
		free(binary);
		return KNOTD_ERROR;
	}

	memcpy(*data + *size, binary, actual_size);
	*size += actual_size;
	free(binary);

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_changesets_to_binary(knot_changesets_t *chgsets)
{
	assert(chgsets != NULL);
	assert(chgsets->allocated >= chgsets->count);

	/*
	 * Converts changesets to the binary format stored in chgsets->data
	 * from the changeset_t structures.
	 */
	int ret;

	for (int i = 0; i < chgsets->count; ++i) {
		knot_changeset_t *ch = &chgsets->sets[i];
		assert(ch->data == NULL);
		assert(ch->size == 0);

		/* 1) origin SOA */
		ret = zones_changeset_rrset_to_binary(&ch->data, &ch->size,
		                                &ch->allocated, ch->soa_from);
		if (ret != KNOT_EOK) {
			free(ch->data);
			ch->data = NULL;
			dbg_zones("zones_changeset_rrset_to_binary(): %s\n",
			          knot_strerror(ret));
			return KNOTD_ERROR;
		}

		int j;

		/* 2) remove RRsets */
		assert(ch->remove_allocated >= ch->remove_count);
		for (j = 0; j < ch->remove_count; ++j) {
			ret = zones_changeset_rrset_to_binary(&ch->data,
			                                      &ch->size,
			                                      &ch->allocated,
			                                      ch->remove[j]);
			if (ret != KNOT_EOK) {
				free(ch->data);
				ch->data = NULL;
				dbg_zones("zones_changeset_rrset_to_binary(): %s\n",
					  knot_strerror(ret));
				return KNOTD_ERROR;
			}
		}

		/* 3) new SOA */
		ret = zones_changeset_rrset_to_binary(&ch->data, &ch->size,
		                                &ch->allocated, ch->soa_to);
		if (ret != KNOT_EOK) {
			free(ch->data);
			ch->data = NULL;
			dbg_zones("zones_changeset_rrset_to_binary(): %s\n",
				  knot_strerror(ret));
			return KNOTD_ERROR;
		}

		/* 4) add RRsets */
		assert(ch->add_allocated >= ch->add_count);
		for (j = 0; j < ch->add_count; ++j) {
			ret = zones_changeset_rrset_to_binary(&ch->data,
			                                      &ch->size,
			                                      &ch->allocated,
			                                      ch->add[j]);
			if (ret != KNOT_EOK) {
				free(ch->data);
				ch->data = NULL;
				dbg_zones("zones_changeset_rrset_to_binary(): %s\n",
					  knot_strerror(ret));
				return KNOTD_ERROR;
			}
		}
	}

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_store_changesets(knot_ns_xfr_t *xfr)
{
	if (xfr == NULL || xfr->data == NULL || xfr->zone == NULL) {
		return KNOTD_EINVAL;
	}
	
	knot_zone_t *zone = xfr->zone;
	knot_changesets_t *src = (knot_changesets_t *)xfr->data;
	
	/*! \todo Convert to binary format. */
	
	int ret = zones_changesets_to_binary(src);
	if (ret != KNOTD_EOK) {
		return ret;
	}

	/* Fetch zone-specific data. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd->ixfr_db) {
		return KNOTD_EINVAL;
	}

	/* Begin writing to journal. */
	for (unsigned i = 0; i < src->count; ++i) {

		/* Make key from serials. */
		knot_changeset_t* chs = src->sets + i;
		uint64_t k = ixfrdb_key_make(chs->serial_from, chs->serial_to);

		/* Write entry. */
		int ret = journal_write(zd->ixfr_db, k, (const char*)chs->data,
		                        chs->size);

		/* Check for errors. */
		while (ret != KNOTD_EOK) {

			/* Sync to zonefile may be needed. */
			if (ret == KNOTD_EAGAIN) {

				/* Cancel sync timer. */
				event_t *tmr = zd->ixfr_dbsync;
				if (tmr) {
					dbg_xfr_verb("xfr: cancelling zonefile "
					             "SYNC timer of '%s'\n",
					             zd->conf->name);
					evsched_cancel(tmr->parent, tmr);
				}

				/* Synchronize. */
				dbg_xfr_verb("xfr: forcing zonefile SYNC "
				             "of '%s'\n",
				             zd->conf->name);
				ret = zones_zonefile_sync(zone);
				if (ret != KNOTD_EOK && ret != KNOTD_ERANGE) {
					continue;
				}

				/* Reschedule sync timer. */
				if (tmr) {
					/* Fetch sync timeout. */
					conf_read_lock();
					int timeout = zd->conf->dbsync_timeout;
					timeout *= 1000; /* Convert to ms. */
					conf_read_unlock();

					/* Reschedule. */
					dbg_xfr_verb("xfr: resuming SYNC "
					             "of '%s'\n",
					             zd->conf->name);
					evsched_schedule(tmr->parent, tmr,
					                 timeout);

				}

				/* Attempt to write again. */
				ret = journal_write(zd->ixfr_db, k,
						    (const char*)chs->data,
						    chs->size);
			} else {
				/* Other errors. */
				return KNOTD_ERROR;
			}
		}

		/* Free converted binary data. */
		free(chs->data);
		chs->data = 0;
		chs->size = 0;
	}

	/* Written changesets to journal. */
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_xfr_load_changesets(knot_ns_xfr_t *xfr, uint32_t serial_from,
                              uint32_t serial_to) 
{
	if (!xfr || !xfr->zone || !knot_zone_contents(xfr->zone)) {
		dbg_zones_detail("Wrong parameters: xfr=%p,"
		                " xfr->zone = %p\n", xfr, xfr->zone);
		return KNOTD_EINVAL;
	}
	
	knot_changesets_t *chgsets = (knot_changesets_t *)
	                               calloc(1, sizeof(knot_changesets_t));
	CHECK_ALLOC_LOG(chgsets, KNOTD_ENOMEM);
	
	int ret = ns_serial_compare(serial_to, serial_from);
	dbg_zones_verb("Compared serials, result: %d\n", ret);
	
	/* if serial_to is not larger than serial_from, do not load anything */
	if (ret <= 0) {
		xfr->data = chgsets;
		return KNOTD_EOK;
	}
	
	dbg_zones("Loading changesets...\n");
	
	ret = zones_load_changesets(xfr->zone, chgsets,
	                                serial_from, serial_to);
	if (ret != KNOTD_EOK) {
		dbg_zones_verb("Loading changesets failed: %s\n",
		               knotd_strerror(ret));
		knot_free_changesets(&chgsets);
		return ret;
	}
	
	xfr->data = chgsets;
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_apply_changesets(knot_ns_xfr_t *xfr) 
{
	if (xfr == NULL || xfr->zone == NULL || xfr->data == NULL) {
		return KNOTD_EINVAL;
	}
	
	return xfrin_apply_changesets_to_zone(xfr->zone, 
	                                      (knot_changesets_t *)xfr->data);
}

/*----------------------------------------------------------------------------*/

int zones_timers_update(knot_zone_t *zone, conf_zone_t *cfzone, evsched_t *sch)
{
	if (!sch || !zone) {
		return KNOTD_EINVAL;
	}

	/* Fetch zone data. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd) {
		return KNOTD_EINVAL;
	}

	/* Cancel REFRESH timer. */
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

	/* Remove list of pending NOTIFYs. */
	pthread_mutex_lock(&zd->lock);
	notify_ev_t *ev = 0, *evn = 0;
	WALK_LIST_DELSAFE(ev, evn, zd->notify_pending) {
		zones_cancel_notify(zd, ev);
	}
	pthread_mutex_unlock(&zd->lock);

	/* Check XFR/IN master server. */
	if (zd->xfr_in.master.ptr) {

		/* Schedule REFRESH timer. */
		uint32_t refresh_tmr = 0;
		if (knot_zone_contents(zone)) {
			refresh_tmr = zones_soa_refresh(zone);
		} else {
			refresh_tmr = zd->xfr_in.bootstrap_retry;
		}
		zd->xfr_in.timer = evsched_schedule_cb(sch, zones_refresh_ev,
							 zone, refresh_tmr);
		dbg_zones("zone: REFRESH set to %u\n", refresh_tmr);
	}

	/* Schedule IXFR database syncing. */
	/*! \todo Sync timer should not be reset after each xfr. */
	int sync_timeout = cfzone->dbsync_timeout * 1000; /* Convert to ms. */
	if (zd->ixfr_dbsync) {
		evsched_cancel(sch, zd->ixfr_dbsync);
		evsched_event_free(sch, zd->ixfr_dbsync);
		zd->ixfr_dbsync = 0;
	}
	if (zd->ixfr_db) {
		zd->ixfr_dbsync = evsched_schedule_cb(sch,
		                                      zones_zonefile_sync_ev,
		                                      zone, sync_timeout);
	}

	/* Do not issue NOTIFY queries if stub. */
	if (!knot_zone_contents(zone)) {
		conf_read_unlock();
		return KNOTD_EOK;
	}

	/* Schedule NOTIFY to slaves. */
	conf_remote_t *r = 0;
	conf_read_lock();
	WALK_LIST(r, cfzone->acl.notify_out) {

		/* Fetch remote. */
		conf_iface_t *cfg_if = r->remote;

		/* Create request. */
		notify_ev_t *ev = malloc(sizeof(notify_ev_t));
		if (!ev) {
			free(ev);
			dbg_zones("notify: out of memory to create "
				    "NOTIFY query for %s\n", cfg_if->name);
			continue;
		}

		/* Parse server address. */
		int ret = sockaddr_set(&ev->addr, cfg_if->family,
				       cfg_if->address,
				       cfg_if->port);
		if (ret < 1) {
			free(ev);
			dbg_zones("notify: NOTIFY slave %s has invalid "
				    "address\n", cfg_if->name);
			continue;
		}

		/* Prepare request. */
		ev->retries = cfzone->notify_retries + 1; /* first + N retries*/
		ev->msgid = 0;
		ev->zone = zone;
		ev->timeout = cfzone->notify_timeout;

		/* Schedule request (30 - 60s random delay). */
		int tmr_s = 30 + (int)(30.0 * tls_rand());
		pthread_mutex_lock(&zd->lock);
		ev->timer = evsched_schedule_cb(sch, zones_notify_send, ev,
						tmr_s * 1000);
		add_tail(&zd->notify_pending, &ev->n);
		pthread_mutex_unlock(&zd->lock);

		log_server_info("Scheduled NOTIFY query after %d s to %s:%d\n",
			    tmr_s, cfg_if->address, cfg_if->port);
	}

	conf_read_unlock();

	return KNOTD_EOK;
}

int zones_cancel_notify(zonedata_t *zd, notify_ev_t *ev)
{
	if (!zd || !ev || !ev->timer) {
		return KNOTD_EINVAL;
	}

	/* Wait for event to finish running. */
#ifdef KNOTD_NOTIFY_DEBUG
	int pkt_id = ev->msgid; /*< Do not optimize! */
#endif
	event_t *tmr = ev->timer;
	ev->timer = 0;
	pthread_mutex_unlock(&zd->lock);
	evsched_cancel(tmr->parent, tmr);

	/* Re-lock and find again (if not deleted). */
	pthread_mutex_lock(&zd->lock);
	int match_exists = 0;
	notify_ev_t *tmpev = 0;
	WALK_LIST(tmpev, zd->notify_pending) {
		if (tmpev == ev) {
			match_exists = 1;
			break;
		}
	}

	/* Event deleted before cancelled. */
	if (!match_exists) {
		dbg_notify("notify: NOTIFY event for query ID=%u was "
		           "deleted before cancellation.\n",
		           pkt_id);
		return KNOTD_EOK;

	}

	/* Free event (won't be scheduled again). */
	dbg_notify("notify: NOTIFY query ID=%u event cancelled.\n",
	           pkt_id);
	rem_node(&ev->n);
	evsched_event_free(tmr->parent, tmr);
	free(ev);
	return KNOTD_EOK;
}
