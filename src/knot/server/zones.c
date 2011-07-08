#include <sys/stat.h>

#include "common/lists.h"
#include "dnslib/debug.h"
#include "dnslib/dname.h"
#include "dnslib/wire.h"
#include "dnslib/zone-dump-text.h"
#include "dnslib/zone-load.h"
#include "dnslib/zone.h"
#include "dnslib/zonedb.h"
#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "knot/other/error.h"
#include "knot/other/log.h"
#include "knot/server/notify.h"
#include "knot/server/server.h"
#include "knot/server/xfr-in.h"
#include "knot/server/zones.h"

/*----------------------------------------------------------------------------*/

/*! \brief Zone data destructor function. */
static int zonedata_destroy(dnslib_zone_t *zone)
{
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd) {
		return KNOT_EINVAL;
	}

	/* Destroy mutex. */
	pthread_mutex_destroy(&zd->lock);

	acl_delete(&zd->xfr_out);
	acl_delete(&zd->notify_in);
	acl_delete(&zd->notify_out);

	/* Close IXFR db. */
	journal_close(zd->ixfr_db);

	free(zd);

	return KNOT_EOK;
}

/*! \brief Zone data constructor function. */
static int zonedata_init(conf_zone_t *cfg, dnslib_zone_t *zone)
{
	zonedata_t *zd = malloc(sizeof(zonedata_t));
	if (!zd) {
		return KNOT_ENOMEM;
	}

	/* Link to config. */
	zd->conf = cfg;

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
	zd->xfr_in.ifaces = 0;
	zd->xfr_in.next_id = -1;

	/* Initialize NOTIFY. */
	init_list(&zd->notify_pending);

	/* Initialize IXFR database. */
	zd->ixfr_db = journal_open(cfg->ixfr_db, cfg->ixfr_fslimit,
				   JOURNAL_DIRTY);
	if (!zd->ixfr_db) {
		journal_create(cfg->ixfr_db, JOURNAL_NCOUNT);
		zd->ixfr_db = journal_open(cfg->ixfr_db, cfg->ixfr_fslimit,
					   JOURNAL_DIRTY);
	}

	/* Initialize IXFR database syncing event. */
	zd->ixfr_dbsync = 0;

	/* Set zonefile SOA serial. */
	const dnslib_rrset_t *soa_rrs = 0;
	const dnslib_rdata_t *soa_rr = 0;
	soa_rrs = dnslib_node_rrset(dnslib_zone_apex(zone), DNSLIB_RRTYPE_SOA);
	soa_rr = dnslib_rrset_rdata(soa_rrs);
	zd->zonefile_serial = (uint32_t)dnslib_rdata_soa_serial(soa_rr);

	/* Set and install destructor. */
	zone->data = zd;
	zone->dtor = zonedata_destroy;

	return KNOT_EOK;
}

/*!
 * \brief Return SOA timer value.
 *
 * \param zone Pointer to zone.
 * \param rr_func RDATA specificator.
 * \return Timer in miliseconds.
 */
static uint32_t zones_soa_timer(dnslib_zone_t *zone,
				  uint32_t (*rr_func)(const dnslib_rdata_t*))
{
	uint32_t ret = 0;

	/* Retrieve SOA RDATA. */
	const dnslib_rrset_t *soa_rrs = 0;
	const dnslib_rdata_t *soa_rr = 0;
	soa_rrs = dnslib_node_rrset(dnslib_zone_apex(zone),
				    DNSLIB_RRTYPE_SOA);
	soa_rr = dnslib_rrset_rdata(soa_rrs);
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
static uint32_t zones_soa_refresh(dnslib_zone_t *zone)
{
	return zones_soa_timer(zone, dnslib_rdata_soa_refresh);
}

/*!
 * \brief Return SOA RETRY timer value.
 *
 * \param zone Pointer to zone.
 * \return RETRY timer in miliseconds.
 */
static uint32_t zones_soa_retry(dnslib_zone_t *zone)
{
	return zones_soa_timer(zone, dnslib_rdata_soa_retry);
}

/*!
 * \brief Return SOA EXPIRE timer value.
 *
 * \param zone Pointer to zone.
 * \return EXPIRE timer in miliseconds.
 */
static uint32_t zones_soa_expire(dnslib_zone_t *zone)
{
	return zones_soa_timer(zone, dnslib_rdata_soa_expire);
}

/*!
 * \brief AXFR-IN expire event handler.
 */
static int zones_axfrin_expire(event_t *e)
{
	debug_zones("axfrin: EXPIRE timer event\n");
	dnslib_zone_t *zone = (dnslib_zone_t *)e->data;
	if (!zone) {
		return KNOT_EINVAL;
	}
	if (!zone->data) {
		return KNOT_EINVAL;
	}

	/* Cancel pending timers. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (zd->xfr_in.timer) {
		evsched_cancel(e->parent, zd->xfr_in.timer);
		evsched_event_free(e->parent, zd->xfr_in.timer);
		zd->xfr_in.timer = 0;
	}

	/* Delete self. */
	evsched_event_free(e->parent, e);
	zd->xfr_in.expire = 0;
	zd->xfr_in.next_id = -1;

	/*! \todo Remove zone from database. */
	return 0;
}

/*!
 * \brief AXFR-IN poll event handler.
 */
static int zones_axfrin_poll(event_t *e)
{
	debug_zones("axfrin: REFRESH or RETRY timer event\n");
	dnslib_zone_t *zone = (dnslib_zone_t *)e->data;
	if (!zone) {
		return KNOT_EINVAL;
	}
	if (!zone->data) {
		return KNOT_EINVAL;
	}

	/* Cancel pending timers. */
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Get zone dname. */
	const dnslib_node_t *apex = dnslib_zone_apex(zone);
	const dnslib_dname_t *dname = dnslib_node_owner(apex);

	/* Prepare buffer for query. */
	uint8_t qbuf[SOCKET_MTU_SZ];
	size_t buflen = SOCKET_MTU_SZ;

	/* Create query. */
	int ret = xfrin_create_soa_query(dname, qbuf, &buflen);
	if (ret == KNOT_EOK && zd->xfr_in.ifaces) {

		int sock = -1;
		iface_t *i = 0;
		sockaddr_t *master = &zd->xfr_in.master;

		/*! \todo Bind to random port? xfr_master should then use some
		 *        polling mechanisms to handle incoming events along
		 *        with polled packets - evqueue should implement this.
		 */

		/* Lock RCU. */
		rcu_read_lock();

		/* Find suitable interface. */
		WALK_LIST(i, **zd->xfr_in.ifaces) {
			if (i->type[UDP_ID] == master->family) {
				sock = i->fd[UDP_ID];
				break;
			}
		}

		/* Unlock RCU. */
		rcu_read_unlock();

		/* Send query. */
		ret = -1;
		if (sock > -1) {
			ret = sendto(sock, qbuf, buflen, 0,
				     master->ptr, master->len);
		}

		/* Store ID of the awaited response. */
		if (ret == buflen) {
			zd->xfr_in.next_id = dnslib_wire_get_id(qbuf);
			debug_zones("axfrin: expecting SOA response ID=%d\n",
				    zd->xfr_in.next_id);
		}
	}

	/* Schedule EXPIRE timer on first attempt. */
	if (!zd->xfr_in.expire) {
		uint32_t expire_tmr = zones_soa_expire(zone);
		zd->xfr_in.expire = evsched_schedule_cb(
					      e->parent,
					      zones_axfrin_expire,
					      zone, expire_tmr);
		debug_zones("axfrin: scheduling EXPIRE timer after %u secs\n",
			    expire_tmr / 1000);
	}

	/* Reschedule as RETRY timer. */
	evsched_schedule(e->parent, e, zones_soa_retry(zone));
	debug_zones("axfrin: RETRY after %u secs\n",
		    zones_soa_retry(zone) / 1000);
	return ret;
}

/*!
 * \brief Send NOTIFY to slave server.
 */
static int zones_notify_send(event_t *e)
{
	notify_ev_t *ev = (notify_ev_t *)e->data;
	dnslib_zone_t *zone = ev->zone;
	if (!zone) {
		return KNOT_EINVAL;
	}
	if (!zone->data) {
		return KNOT_EINVAL;
	}

	debug_zones("notify: NOTIFY timer event\n");

	/* Prepare buffer for query. */
	uint8_t qbuf[SOCKET_MTU_SZ];
	size_t buflen = SOCKET_MTU_SZ;

	/* Create query. */
	zonedata_t *zd = (zonedata_t *)zone->data;
	int ret = notify_create_request(zone, qbuf, &buflen);
	if (ret == KNOT_EOK && zd->xfr_in.ifaces) {

		/*! \todo Bind to random port? See zones_axfrin_poll(). */

		/* Lock RCU. */
		rcu_read_lock();

		/* Find suitable interface. */
		int sock = -1;
		iface_t *i = 0;
		WALK_LIST(i, **zd->xfr_in.ifaces) {
			if (i->type[UDP_ID] == ev->addr.family) {
				sock = i->fd[UDP_ID];
				break;
			}
		}

		/* Unlock RCU. */
		rcu_read_unlock();

		/* Send query. */
		ret = -1;
		if (sock > -1) {
			ret = sendto(sock, qbuf, buflen, 0,
				     ev->addr.ptr, ev->addr.len);
		}

		/* Store ID of the awaited response. */
		if (ret == buflen) {
			ev->msgid = dnslib_wire_get_id(qbuf);
			debug_zones("notify: sent NOTIFY, expecting "
				    "response ID=%d\n", ev->msgid);
		}

	}

	/* Reduce number of available retries. */
	--ev->retries;

	/* Check number of retries. */
	if (ev->retries == 0) {
		debug_zones("notify: NOTIFY maximum retry time exceeded\n");
		evsched_event_free(e->parent, ev->timer);
		rem_node(&ev->n);
		free(ev);
		return KNOT_EMALF;
	}

	/* RFC suggests 60s, but it is configurable. */
	int retry_tmr = ev->timeout * 1000;

	/* Reschedule. */
	evsched_schedule(e->parent, e, retry_tmr);
	debug_zones("notify: RETRY after %u secs\n",
		    retry_tmr / 1000);
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
	debug_zones("ixfr_db: SYNC timer event\n");

	/* Fetch zone. */
	dnslib_zone_t *zone = (dnslib_zone_t *)e->data;
	if (!zone) {
		return KNOT_EINVAL;
	}
	if (!zone->data) {
		return KNOT_EINVAL;
	}

	/* Fetch zone data. */
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Execute zonefile sync. */
	int ret =  zones_zonefile_sync(zone);

	/* Reschedule. */
	conf_read_lock();
	evsched_schedule(e->parent, e, zd->conf->dbsync_timeout * 1000);
	conf_read_unlock();

	return ret;
}

/*!
 * \brief Update timers related to zone.
 *
 */
void zones_timers_update(dnslib_zone_t *zone, conf_zone_t *cfzone, evsched_t *sch)
{
	/* Fetch zone data. */
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Check AXFR-IN master server. */
	if (zd->xfr_in.master.ptr) {

		/* Schedule REFRESH timer. */
		uint32_t refresh_tmr = zones_soa_refresh(zone);
		zd->xfr_in.timer = evsched_schedule_cb(sch, zones_axfrin_poll,
							 zone, refresh_tmr);

		/* Cancel EXPIRE timer. */
		if (zd->xfr_in.expire) {
			evsched_cancel(sch, zd->xfr_in.expire);
			evsched_event_free(sch, zd->xfr_in.expire);
			zd->xfr_in.expire = 0;
		}
	}

	/* Remove list of pending NOTIFYs. */
	node *n = 0, *nxt = 0;
	WALK_LIST_DELSAFE(n, nxt, zd->notify_pending) {
		notify_ev_t *ev = (notify_ev_t *)n;
		rem_node(n);
		evsched_cancel(sch, ev->timer);
		evsched_event_free(sch, ev->timer);
		free(ev);
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
			debug_zones("notify: out of memory to create "
				    "NOTIFY query for %s\n", cfg_if->name);
			continue;
		}

		/* Parse server address. */
		int ret = sockaddr_set(&ev->addr, cfg_if->family,
				       cfg_if->address,
				       cfg_if->port);
		if (ret < 1) {
			free(ev);
			debug_zones("notify: NOTIFY slave %s has invalid "
				    "address\n", cfg_if->name);
			continue;
		}

		/* Prepare request. */
		ev->retries = cfzone->notify_retries + 1; /* first + N retries*/
		ev->msgid = -1;
		ev->zone = zone;
		ev->timeout = cfzone->notify_timeout;

		/* Schedule request (30 - 60s random delay). */
		int tmr_s = 30 + (int)(30.0 * (rand() / (RAND_MAX + 1.0)));
		add_tail(&zd->notify_pending, &ev->n);
		ev->timer = evsched_schedule_cb(sch, zones_notify_send, ev,
						tmr_s * 1000);

		debug_zones("notify: scheduled NOTIFY query after %d s to %s\n",
			    tmr_s, cfg_if->name);
	}

	/* Schedule IXFR database syncing. */
	int sync_timeout = cfzone->dbsync_timeout * 1000; /* Convert to ms. */
	if (!zd->ixfr_dbsync) {
		zd->ixfr_dbsync = evsched_schedule_cb(sch,
						      zones_zonefile_sync_ev,
						      zone, sync_timeout);
	} else {
		evsched_cancel(sch, zd->ixfr_dbsync);
		evsched_schedule(sch, zd->ixfr_dbsync, sync_timeout);
	}
	conf_read_unlock();
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
	*acl = acl_new(ACL_DENY, 0);
	if (!*acl) {
		return KNOT_ENOMEM;
	}

	/* Load ACL rules. */
	conf_remote_t *r = 0;
	WALK_LIST(r, *acl_list) {

		/* Initialize address. */
		sockaddr_t addr;
		conf_iface_t *cfg_if = r->remote;
		int ret = sockaddr_set(&addr, cfg_if->family,
				       cfg_if->address, cfg_if->port);

		/* Load rule. */
		if (ret > 0) {
			acl_create(*acl, &addr, ACL_ACCEPT);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Load zone to zone database.
 *
 * \param zonedb Zone database to load the zone into.
 * \param zone_name Zone name (owner of the apex node).
 * \param source Path to zone file source.
 * \param filename Path to requested compiled zone file.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_EZONEINVAL
 */
static int zones_load_zone(dnslib_zonedb_t *zonedb, const char *zone_name,
			   const char *source, const char *filename)
{
	dnslib_zone_t *zone = NULL;

	// Check path
	if (filename) {
		debug_server("Parsing zone database '%s'\n", filename);
		zloader_t *zl = dnslib_zload_open(filename);
		if (!zl) {
			log_server_error("Compiled db '%s' is too old, "
			                 " please recompile.\n",
			                 filename);
			return KNOT_EZONEINVAL;
		}

		// Check if the db is up-to-date
		int src_changed = strcmp(source, zl->source) != 0;
		if (src_changed || dnslib_zload_needs_update(zl)) {
			log_server_warning("Database for zone '%s' is not "
			                   "up-to-date. Please recompile.\n",
			                   zone_name);
		}

		zone = dnslib_zload_load(zl);
		if (zone) {
			// save the timestamp from the zone db file
			struct stat s;
			stat(filename, &s);
			dnslib_zone_set_version(zone, s.st_mtime);

			if (dnslib_zonedb_add_zone(zonedb, zone) != 0){
				dnslib_zone_deep_free(&zone, 0);
				zone = 0;
			}
		}

		dnslib_zload_close(zl);

		if (!zone) {
			log_server_error("Failed to load "
					 "db '%s' for zone '%s'.\n",
					 filename, zone_name);
			return KNOT_EZONEINVAL;
		}
	} else {
		/* db is null. */
		return KNOT_EINVAL;
	}

//	dnslib_zone_dump(zone, 1);

	return KNOT_EOK;
}

/*!
 * \brief Apply changesets to zone from journal.
 *
 * \param zone Specified zone.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL on invalid parameters.
 * \retval KNOT_EOK on unspecified error.
 */
static int zones_journal_apply(dnslib_zone_t *zone)
{
	/* Fetch zone. */
	if (!zone) {
		return KNOT_EINVAL;
	}

	/* Fetch SOA serial. */
	const dnslib_rrset_t *soa_rrs = 0;
	const dnslib_rdata_t *soa_rr = 0;
	soa_rrs = dnslib_node_rrset(dnslib_zone_apex(zone), DNSLIB_RRTYPE_SOA);
	soa_rr = dnslib_rrset_rdata(soa_rrs);
	uint32_t serial = (uint32_t)dnslib_rdata_soa_serial(soa_rr);

	/* Load all pending changesets. */
	debug_zones("update_zone: loading all changesets from %u\n", serial);
	xfrin_changesets_t* chsets = malloc(sizeof(xfrin_changesets_t));
	memset(chsets, 0, sizeof(xfrin_changesets_t));
	int ret = xfr_load_changesets(zone, chsets, serial, serial - 1);
	if (ret == KNOT_EOK || ret == KNOT_ERANGE) {

		/* Apply changesets. */
		debug_zones("update_zone: applying %u changesets\n",
			    chsets->count);
		xfrin_apply_changesets(zone, chsets);

	} else {
		debug_zones("update_zone: failed to load changesets\n");
	}

	/* Free changesets and return. */
	xfrin_free_changesets(&chsets);
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
static int zones_insert_zones(ns_nameserver_t *ns,
			      const list *zone_conf,
                              const dnslib_zonedb_t *db_old,
                              dnslib_zonedb_t *db_new)
{
	node *n = 0;
	int inserted = 0;
	// for all zones in the configuration
	WALK_LIST(n, *zone_conf) {
		conf_zone_t *z = (conf_zone_t *)n;
		// convert the zone name into a domain name
		dnslib_dname_t *zone_name = dnslib_dname_new_from_str(z->name,
		                                         strlen(z->name), NULL);
		if (zone_name == NULL) {
			log_server_error("Error creating domain name from zone"
			                 " name\n");
			return inserted;
		}

		debug_zones("Inserting zone %s into the new database.\n",
		            z->name);

		// try to find the zone in the current zone db
		dnslib_zone_t *zone = dnslib_zonedb_find_zone(db_old,
		                                              zone_name);
		int reload = 0;

		if (zone != NULL) {
			// if found, check timestamp of the file against the
			// loaded zone
			struct stat s;
			stat(z->file, &s);
			if (dnslib_zone_version(zone) < s.st_mtime) {
				// the file is newer, reload!
				reload = 1;
			}
		} else {
			reload = 1;
		}

		if (reload) {
			debug_zones("Not found in old database or the loaded"
			            " version is old, loading...\n");
			int ret = zones_load_zone(db_new, z->name,
						  z->file, z->db);
			if (ret != KNOT_EOK) {
				log_server_error("Error loading new zone to"
				                 " the new database: %s\n",
				                 knot_strerror(ret));
			} else {
				// Find the new zone
				zone = dnslib_zonedb_find_zone(db_new,
							       zone_name);
				++inserted;

				/* Initialize zone-related data. */
				zonedata_init(z, zone);

			}
			// unused return value, if not loaded, just continue
		} else {
			// just insert the zone into the new zone db
			debug_zones("Found in old database, copying to new.\n");
			int ret = dnslib_zonedb_add_zone(db_new, zone);
			if (ret != KNOT_EOK) {
				log_server_error("Error adding old zone to"
				                 " the new database: %s\n",
				                 knot_strerror(ret));
			} else {
				++inserted;
			}
		}

		/* Update zone data. */
		if (zone) {
			zonedata_t *zd = (zonedata_t *)zone->data;

			/* Apply changesets from journal. */
			zones_journal_apply(zone);

			/* Update ACLs. */
			debug_zones("Updating zone ACLs.\n");
			zones_set_acl(&zd->xfr_out, &z->acl.xfr_out);
			zones_set_acl(&zd->notify_in, &z->acl.notify_in);
			zones_set_acl(&zd->notify_out, &z->acl.notify_out);

			/* Update available interfaces. */
			zd->xfr_in.ifaces = &ns->server->ifaces;

			/* Update master server address. */
			sockaddr_init(&zd->xfr_in.master, -1);
			if (!EMPTY_LIST(z->acl.xfr_in)) {
				conf_remote_t *r = HEAD(z->acl.xfr_in);
				conf_iface_t *cfg_if = r->remote;
				sockaddr_set(&zd->xfr_in.master,
					     cfg_if->family,
					     cfg_if->address,
					     cfg_if->port);
			}

			/* Update events scheduled for zone. */
			zones_timers_update(zone, z, ns->server->sched);
		}

		dnslib_zone_dump(zone, 1);

		dnslib_dname_free(&zone_name);
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
 * \retval KNOT_EOK
 * \retval KNOT_ERROR
 */
static int zones_remove_zones(const list *zone_conf, dnslib_zonedb_t *db_old)
{
	node *n;
	// for all zones in the configuration
	WALK_LIST(n, *zone_conf) {
		conf_zone_t *z = (conf_zone_t *)n;
		// convert the zone name into a domain name
		dnslib_dname_t *zone_name = dnslib_dname_new_from_str(z->name,
		                                         strlen(z->name), NULL);
		if (zone_name == NULL) {
			log_server_error("Error creating domain name from zone"
			                 " name\n");
			return KNOT_ERROR;
		}
		debug_zones("Removing zone %s from the old database.\n",
		            z->name);
		// remove the zone from the old zone db, but do not delete it
		dnslib_zonedb_remove_zone(db_old, zone_name, 0);

		dnslib_dname_free(&zone_name);
	}
	return KNOT_EOK;
}


/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int zones_update_db_from_config(const conf_t *conf, ns_nameserver_t *ns,
                               dnslib_zonedb_t **db_old)
{
	// Check parameters
	if (conf == NULL || ns == NULL) {
		return KNOT_EINVAL;
	}

	// Lock RCU to ensure noone will deallocate any data under our hands.
	rcu_read_lock();

	// Grab a pointer to the old database
	*db_old = ns->zone_db;
	if (*db_old == NULL) {
		log_server_error("Missing zone database in nameserver structure"
		                 ".\n");
		return KNOT_ERROR;
	}

	// Create new zone DB
	dnslib_zonedb_t *db_new = dnslib_zonedb_new();
	if (db_new == NULL) {
		return KNOT_ERROR;
	}

	log_server_info("Loading %d zones...\n", conf->zones_count);

	// Insert all required zones to the new zone DB.
	int inserted = zones_insert_zones(ns, &conf->zones, *db_old, db_new);

	log_server_info("Loaded %d out of %d zones.\n", inserted,
	                conf->zones_count);

	if (inserted != conf->zones_count) {
		log_server_warning("Not all the zones were loaded.\n");
	}

	debug_zones("Old db in nameserver: %p, old db stored: %p, new db: %p\n",
	            ns->zone_db, *db_old, db_new);

	// Switch the databases.
	(void)rcu_xchg_pointer(&ns->zone_db, db_new);

	debug_zones("db in nameserver: %p, old db stored: %p, new db: %p\n",
	            ns->zone_db, *db_old, db_new);

	/*
	 *  Remove all zones present in the new DB from the old DB.
	 *  No new thread can access these zones in the old DB, as the
	 *  databases are already switched.
	 */
	int ret = zones_remove_zones(&conf->zones, *db_old);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Unlock RCU, messing with any data will not affect us now
	rcu_read_unlock();

	debug_zones("Old database is empty (%p): %s\n", (*db_old)->zones,
	            skip_is_empty((*db_old)->zones) ? "yes" : "no");

	return KNOT_EOK;
}

int zones_zonefile_sync(dnslib_zone_t *zone)
{
	if (!zone) {
		return KNOT_EINVAL;
	}
	if (!zone->data) {
		return KNOT_EINVAL;
	}

	/* Fetch zone data. */
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Lock zone data. */
	pthread_mutex_lock(&zd->lock);

	/* Latest zone serial. */
	const dnslib_rrset_t *soa_rrs = 0;
	const dnslib_rdata_t *soa_rr = 0;
	soa_rrs = dnslib_node_rrset(dnslib_zone_apex(zone), DNSLIB_RRTYPE_SOA);
	soa_rr = dnslib_rrset_rdata(soa_rrs);
	uint32_t serial_to = (uint32_t)dnslib_rdata_soa_serial(soa_rr);

	/* Check for difference against zonefile serial. */
	if (zd->zonefile_serial != serial_to) {

		/* Save zone to zonefile. */
		conf_read_lock();
		debug_zones("ixfr_db: syncing '%s' to '%s' (SOA serial %u)\n",
			   zd->conf->name, zd->conf->file, serial_to);
		zone_dump_text(zone, zd->conf->file);
		conf_read_unlock();

		/* Update journal entries. */
		debug_zones("ixfr_db: unmarking all dirty nodes in journal\n");
		journal_walk(zd->ixfr_db, zones_ixfrdb_sync_apply);

		/* Update zone file serial. */
		debug_zones("ixfr_db: new zonefile serial is %u\n", serial_to);
		zd->zonefile_serial = serial_to;
	} else {
		debug_zones("ixfr_db: nothing to sync\n");
	}

	/* Unlock zone data. */
	pthread_mutex_unlock(&zd->lock);

	return KNOT_EOK;
}
