#include <sys/stat.h>

#include "common/lists.h"
#include "libknot/debug.h"
#include "libknot/dname.h"
#include "libknot/wire.h"
#include "knot/zone/zone-dump-text.h"
#include "knot/zone/zone-load.h"
#include "libknot/zone.h"
#include "libknot/zonedb.h"
#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "knot/other/error.h"
#include "knot/other/log.h"
#include "knot/server/notify.h"
#include "knot/server/server.h"
#include "libknot/xfr-in.h"
#include "knot/server/zones.h"
#include "libknot/error.h"
#include "knot/zone/zone-dump.h"
#include "libknot/name-server.h"
#include "libknot/changesets.h"

static const size_t XFRIN_CHANGESET_BINARY_SIZE = 100;
static const size_t XFRIN_CHANGESET_BINARY_STEP = 100;

/*----------------------------------------------------------------------------*/

/*! \brief Zone data destructor function. */
static int zonedata_destroy(knot_zone_t *zone)
{
	zonedata_t *zd = (zonedata_t *)zone->data;
	if (!zd) {
		return KNOTD_EINVAL;
	}

	/* Destroy mutex. */
	pthread_mutex_destroy(&zd->lock);

	acl_delete(&zd->xfr_in.acl);
	acl_delete(&zd->xfr_out);
	acl_delete(&zd->notify_in);
	acl_delete(&zd->notify_out);

	/* Close IXFR db. */
	journal_close(zd->ixfr_db);

	free(zd);

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
	zd->xfr_in.acl = 0;

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

	/* Set and install destructor. */
	zone->data = zd;
	zone->dtor = zonedata_destroy;

	/* Set zonefile SOA serial. */
	const knot_rrset_t *soa_rrs = 0;
	const knot_rdata_t *soa_rr = 0;
	/*! \todo Checks for NULL!!! */
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
	                            KNOT_RRTYPE_SOA);
	soa_rr = knot_rrset_rdata(soa_rrs);
	int64_t serial = knot_rdata_soa_serial(soa_rr);
	zd->zonefile_serial = (uint32_t)serial;
	if (serial < 0) {
		return KNOTD_EINVAL;
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
	uint32_t ret = 0;

	/* Retrieve SOA RDATA. */
	const knot_rrset_t *soa_rrs = 0;
	const knot_rdata_t *soa_rr = 0;
	soa_rrs = knot_node_rrset(knot_zone_contents_apex(
	                                knot_zone_contents((zone))),
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
 * \brief AXFR-IN expire event handler.
 */
static int zones_axfrin_expire(event_t *e)
{
	debug_zones("axfrin: EXPIRE timer event\n");
	knot_zone_t *zone = (knot_zone_t *)e->data;
	if (!zone) {
		return KNOTD_EINVAL;
	}
	if (!zone->data) {
		return KNOTD_EINVAL;
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
	knot_zone_t *zone = (knot_zone_t *)e->data;
	if (!zone) {
		return KNOTD_EINVAL;
	}
	if (!zone->data) {
		return KNOTD_EINVAL;
	}

	/* Cancel pending timers. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);

	/* Prepare buffer for query. */
	uint8_t qbuf[SOCKET_MTU_SZ];
	size_t buflen = SOCKET_MTU_SZ;

	/* Create query. */
	int ret = xfrin_create_soa_query(knot_zone_contents(zone), qbuf, &buflen);
	if (ret == KNOTD_EOK && zd->xfr_in.ifaces) {

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
			zd->xfr_in.next_id = knot_wire_get_id(qbuf);
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
	knot_zone_t *zone = ev->zone;
	if (!zone) {
		return KNOTD_EINVAL;
	}
	if (!knot_zone_data(zone)) {
		return KNOTD_EINVAL;
	}

	debug_zones("notify: NOTIFY timer event\n");

	/* Prepare buffer for query. */
	uint8_t qbuf[SOCKET_MTU_SZ];
	size_t buflen = SOCKET_MTU_SZ;

	/* Create query. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	int ret = notify_create_request(knot_zone_contents(zone), qbuf,
	                                &buflen);
	if (ret == KNOTD_EOK && zd->xfr_in.ifaces) {

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
			ev->msgid = knot_wire_get_id(qbuf);
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
		return KNOTD_EMALF;
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

	return KNOTD_EOK;
}

/*!
 * \brief Sync chagnes in zone to zonefile.
 */
static int zones_zonefile_sync_ev(event_t *e)
{
	debug_zones("ixfr_db: SYNC timer event\n");

	/* Fetch zone. */
	knot_zone_t *zone = (knot_zone_t *)e->data;
	if (!zone) {
		return KNOTD_EINVAL;
	}
	if (!zone->data) {
		return KNOTD_EINVAL;
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
void zones_timers_update(knot_zone_t *zone, conf_zone_t *cfzone, evsched_t *sch)
{
	/* Fetch zone data. */
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Check AXFR-IN master server. */
	if (zd->xfr_in.master.ptr) {

		/* Schedule REFRESH timer. */
		uint32_t refresh_tmr = zones_soa_refresh(zone);
		zd->xfr_in.timer = evsched_schedule_cb(sch, zones_axfrin_poll,
							 zone, refresh_tmr);
		debug_zones("notify: REFRESH set to %u\n", refresh_tmr);

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
		sockaddr_t addr;
		conf_iface_t *cfg_if = r->remote;
		int ret = sockaddr_set(&addr, cfg_if->family,
				       cfg_if->address, cfg_if->port);

		/* Load rule. */
		if (ret > 0) {
			acl_create(*acl, &addr, ACL_ACCEPT);
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

	// Check path
	if (filename) {
		debug_server("Parsing zone database '%s'\n", filename);
		zloader_t *zl = knot_zload_open(filename);
		if (!zl) {
			log_server_error("Compiled db '%s' is too old, "
			                 " please recompile.\n",
			                 filename);
			return KNOTD_EZONEINVAL;
		}

		// Check if the db is up-to-date
		int src_changed = strcmp(source, zl->source) != 0;
		if (src_changed || knot_zload_needs_update(zl)) {
			log_server_warning("Database for zone '%s' is not "
			                   "up-to-date. Please recompile.\n",
			                   zone_name);
		}

		zone = knot_zload_load(zl);

		knot_zone_contents_dump(zone->contents, 1);

		if (zone) {
			// save the timestamp from the zone db file
			struct stat s;
			stat(filename, &s);
			knot_zone_set_version(zone, s.st_mtime);

			if (knot_zonedb_add_zone(zonedb, zone) != 0){
				knot_zone_deep_free(&zone, 0);
				zone = 0;
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
	size_t size = 0;
	size_t parsed = 0;
	knot_rrset_t *rrset;
	int soa = 0;
	int ret = 0;

	for (int i = 0; i < chgsets->count; ++i) {
		ret = knot_zload_rrset_deserialize(&rrset,
			chgsets->sets[i].data + parsed, &size);
		if (ret != KNOT_EOK) {
			return KNOT_EMALF;
		}

		while (rrset != NULL) {
			parsed += size;

			if (soa == 0) {
				assert(knot_rrset_type(rrset)
				       == KNOT_RRTYPE_SOA);

				/* in this special case (changesets loaded
				 * from journal) the SOA serial should already
				 * be set, check it.
				 */
				assert(chgsets->sets[i].serial_from
				       == knot_rdata_soa_serial(
				              knot_rrset_rdata(rrset)));
				knot_changeset_store_soa(
					&chgsets->sets[i].soa_from,
					&chgsets->sets[i].serial_from, rrset);
				++soa;
				continue;
			}

			if (soa == 1) {
				if (knot_rrset_type(rrset)
				    == KNOT_RRTYPE_SOA) {
					/* in this special case (changesets
					 * loaded from journal) the SOA serial
					 * should already be set, check it.
					 */
					assert(chgsets->sets[i].serial_from
					       == knot_rdata_soa_serial(
					            knot_rrset_rdata(rrset)));
					knot_changeset_store_soa(
						&chgsets->sets[i].soa_to,
						&chgsets->sets[i].serial_to,
						rrset);
					++soa;
				} else {
					ret = knot_changeset_add_rrset(
						&chgsets->sets[i].remove,
						&chgsets->sets[i].remove_count,
						&chgsets->sets[i]
						    .remove_allocated,
						rrset);
					if (ret != KNOT_EOK) {
						return ret;
					}
				}
			} else {
				if (knot_rrset_type(rrset)
				    == KNOT_RRTYPE_SOA) {
					return KNOT_EMALF;
				} else {
					ret = knot_changeset_add_rrset(
						&chgsets->sets[i].add,
						&chgsets->sets[i].add_count,
						&chgsets->sets[i].add_allocated,
						rrset);
					if (ret != KNOT_EOK) {
						return ret;
					}
				}
			}

			ret = knot_zload_rrset_deserialize(&rrset,
					chgsets->sets[i].data + parsed, &size);
			if (ret != KNOT_EOK) {
				return KNOT_EMALF;
			}
		}
	}

	/*! \todo Mark ENOTSUP as EOK when fixed. */
	return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

static int zones_load_changesets(const knot_zone_t *zone, 
                                 knot_changesets_t *dst,
                                 uint32_t from, uint32_t to)
{
	if (!zone || !dst) {
		return KNOT_EBADARG;
	}
	if (!zone->data) {
		return KNOT_EBADARG;
	}

	/* Fetch zone-specific data. */
	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd->ixfr_db) {
		return KNOT_EBADARG;
	}

	/* Read entries from starting serial until finished. */
	uint32_t found_to = from;
	journal_node_t *n = 0;
	int ret = journal_fetch(zd->ixfr_db, from, ixfrdb_key_from_cmp, &n);
	while (n != 0 && n != journal_end(zd->ixfr_db)) {

		/* Check for history end. */
		if (to == found_to) {
			break;
		}

		/* Check changesets size if needed. */
		++dst->count;
		ret = knot_changesets_check_size(dst);
		if (ret != KNOT_EOK) {
			debug_knot_xfr("ixfr_db: failed to check changesets size\n");
			--dst->count;
			return ret;
		}

		/* Initialize changeset. */
		knot_changeset_t *chs = dst->sets + (dst->count - 1);
		chs->serial_from = ixfrdb_key_from(n->id);
		chs->serial_to = ixfrdb_key_to(n->id);
		chs->data = malloc(n->len);
		if (!chs->data) {
			--dst->count;
			return KNOT_ENOMEM;
		}

		/* Read journal entry. */
		ret = journal_read(zd->ixfr_db, n->id,
				   0, (char*)chs->data);
		if (ret != KNOTD_EOK) {
			debug_knot_xfr("ixfr_db: failed to read data from journal\n");
			--dst->count;
			return KNOT_ERROR;
		}

		/* Next node. */
		found_to = chs->serial_to;
		++n;

		/*! \todo Check consistency. */
	}

	/* Unpack binary data. */
	ret = zones_changesets_from_binary(dst);
	if (ret != KNOT_EOK) {
		debug_knot_xfr("ixfr_db: failed to unpack changesets "
			       "from binary\n");
		return ret;
	}

	/* Check for complete history. */
	if (to != found_to) {
		return KNOT_ERANGE;
	}

	/* History reconstructed. */
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Apply changesets to zone from journal.
 *
 * \param zone Specified zone.
 *
 * \retval KNOTD_EOK if successful.
 * \retval KNOTD_EINVAL on invalid parameters.
 * \retval KNOTD_EOK on unspecified error.
 */
static int zones_journal_apply(knot_zone_t *zone)
{
	/* Fetch zone. */
	if (!zone) {
		return KNOTD_EINVAL;
	}

	knot_zone_contents_t *contents = knot_zone_get_contents(zone);

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
	debug_zones("update_zone: loading all changesets from %u\n", serial);
	knot_changesets_t* chsets = malloc(sizeof(knot_changesets_t));
	memset(chsets, 0, sizeof(knot_changesets_t));
	int ret = zones_load_changesets(zone, chsets, serial, serial - 1);
	if (ret == KNOT_EOK || ret == KNOT_ERANGE) {

		/* Apply changesets. */
		debug_zones("update_zone: applying %zu changesets\n",
			    chsets->count);
		ret = xfrin_apply_changesets_to_zone(zone, chsets);
		if (ret != KNOT_EOK) {
			debug_zones("update_zone: application of changesets "
				    "failed with '%s'\n",
				    knot_strerror2(ret));
		}

	} else {
		debug_zones("update_zone: failed to load changeset, %s\n",
			    knot_strerror2(ret));
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
	// for all zones in the configuration
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

		debug_zones("Inserting zone %s into the new database.\n",
		            z->name);

		// try to find the zone in the current zone db
		knot_zone_t *zone = knot_zonedb_find_zone(db_old,
		                                              zone_name);
		int reload = 0;

		if (zone != NULL) {
			// if found, check timestamp of the file against the
			// loaded zone
			struct stat s;
			stat(z->file, &s);
			if (knot_zone_version(zone) < s.st_mtime) {
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
			if (ret != KNOTD_EOK) {
				log_server_error("Error loading new zone to"
				                 " the new database: %s\n",
				                 knot_strerror(ret));
			} else {
				// Find the new zone
				zone = knot_zonedb_find_zone(db_new,
				                               zone_name);
				++inserted;

				/* Initialize zone-related data. */
				zonedata_init(z, zone);

			}
			// unused return value, if not loaded, just continue
		} else {
			// just insert the zone into the new zone db
			debug_zones("Found in old database, copying to new.\n");
			int ret = knot_zonedb_add_zone(db_new, zone);
			if (ret != KNOTD_EOK) {
				log_server_error("Error adding old zone to"
				                 " the new database: %s\n",
				                 knot_strerror(ret));
			} else {
				++inserted;
			}
		}

		/* Update zone data. */
		if (zone) {
			zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);

			/* Update refs. */
			zd->conf = z;

			/* Apply changesets from journal. */
			zones_journal_apply(zone);

			/* Update ACLs. */
			debug_zones("Updating zone ACLs.\n");
			zones_set_acl(&zd->xfr_in.acl, &z->acl.xfr_in);
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

				debug_zones("Using %s:%d as zone XFR master.\n",
					    cfg_if->address,
					    cfg_if->port);
			}

			/* Update events scheduled for zone. */
			zones_timers_update(zone, z, ns->server->sched);
		}

		knot_zone_contents_dump(knot_zone_get_contents(zone), 1);

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
static int zones_remove_zones(const list *zone_conf, knot_zonedb_t *db_old)
{
	node *n;
	// for all zones in the configuration
	WALK_LIST(n, *zone_conf) {
		conf_zone_t *z = (conf_zone_t *)n;

		/* Convert the zone name into a domain name. */
		/* Local allocation, will be discarded. */
		knot_dname_t *zone_name = knot_dname_new_from_str(z->name,
		                                         strlen(z->name), NULL);
		if (zone_name == NULL) {
			log_server_error("Error creating domain name from zone"
			                 " name\n");
			return KNOTD_ERROR;
		}
		debug_zones("Removing zone %s from the old database.\n",
		            z->name);
		// remove the zone from the old zone db, but do not delete it
		knot_zonedb_remove_zone(db_old, zone_name, 0);

		/* Directly discard. */
		knot_dname_free(&zone_name);
	}
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int zones_update_db_from_config(const conf_t *conf, knot_nameserver_t *ns,
                               knot_zonedb_t **db_old)
{
	// Check parameters
	if (conf == NULL || ns == NULL) {
		return KNOTD_EINVAL;
	}

	// Lock RCU to ensure noone will deallocate any data under our hands.
	rcu_read_lock();

	// Grab a pointer to the old database
	*db_old = ns->zone_db;
	if (*db_old == NULL) {
		log_server_error("Missing zone database in nameserver structure"
		                 ".\n");
		return KNOTD_ERROR;
	}

	// Create new zone DB
	knot_zonedb_t *db_new = knot_zonedb_new();
	if (db_new == NULL) {
		return KNOTD_ERROR;
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
	if (ret != KNOTD_EOK) {
		return ret;
	}

	// Unlock RCU, messing with any data will not affect us now
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
	zonedata_t *zd = (zonedata_t *)zone->data;

	/* Lock zone data. */
	pthread_mutex_lock(&zd->lock);

	knot_zone_contents_t *contents = knot_zone_get_contents(zone);

	/* Latest zone serial. */
	const knot_rrset_t *soa_rrs = 0;
	const knot_rdata_t *soa_rr = 0;
	soa_rrs = knot_node_rrset(knot_zone_contents_apex(contents),
	                            KNOT_RRTYPE_SOA);
	soa_rr = knot_rrset_rdata(soa_rrs);
	int64_t serial_ret = knot_rdata_soa_serial(soa_rr);
	if (serial_ret < 0) {
		return KNOTD_EINVAL;
	}
	uint32_t serial_to = (uint32_t)serial_ret;

	/* Check for difference against zonefile serial. */
	if (zd->zonefile_serial != serial_to) {

		/* Save zone to zonefile. */
		conf_read_lock();
		debug_zones("ixfr_db: syncing '%s' to '%s' (SOA serial %u)\n",
			   zd->conf->name, zd->conf->file, serial_to);
		zone_dump_text(contents, zd->conf->file);
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

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_xfr_check_zone(knot_ns_xfr_t *xfr, knot_rcode_t *rcode)
{
	if (xfr == NULL || xfr->zone == NULL || rcode == NULL) {
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_EINVAL;
	}
	
	/* Check zone data. */
	zonedata_t *zd = (zonedata_t *)xfr->zone->data;
	if (zd == NULL) {
		debug_zones("Invalid zone data.\n");
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOTD_ERROR;
	}

	// Check xfr-out ACL
	if (acl_match(zd->xfr_out, &xfr->addr) == ACL_DENY) {
		debug_zones("Request for AXFR OUT is not authorized.\n");
		*rcode = KNOT_RCODE_REFUSED;
		return KNOTD_ERROR;
	} else {
		debug_zones("Authorized AXFR OUT request.\n");
	}
	return KNOTD_EOK;
}

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

int zones_process_response(knot_nameserver_t *nameserver, 
                           sockaddr_t *from,
                           knot_packet_t *packet, uint8_t *response_wire,
                           size_t *rsize)
{
	if (!packet || !rsize || nameserver == NULL || from == NULL ||
	    response_wire == NULL) {
		return KNOTD_EINVAL;
	}

	/*! \todo Handle SOA query response, cancel EXPIRE timer
	 *        and start AXFR transfer if needed.
	 *        Reset REFRESH timer on finish.
	 */
	if (knot_packet_qtype(packet) == KNOT_RRTYPE_SOA) {

		/* No response. */
		*rsize = 0;

		/* Find matching zone and ID. */
		const knot_dname_t *zone_name = knot_packet_qname(packet);
		/*! \todo Change the access to the zone db. */
		knot_zone_t *zone = knot_zonedb_find_zone(
		                        nameserver->zone_db,
		                        zone_name);
		if (!zone) {
			return KNOTD_EINVAL;
		}
		if (!knot_zone_data(zone)) {
			return KNOTD_EINVAL;
		}

		/* Match ID against awaited. */
		zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
		uint16_t pkt_id = knot_packet_id(packet);
		if ((int)pkt_id != zd->xfr_in.next_id) {
			return KNOTD_ERROR;
		}

		/* Cancel EXPIRE timer. */
		evsched_t *sched = nameserver->server->sched;
		event_t *expire_ev = zd->xfr_in.expire;
		if (expire_ev) {
			evsched_cancel(sched, expire_ev);
			evsched_event_free(sched, expire_ev);
			zd->xfr_in.expire = 0;
		}

		/* Cancel REFRESH/RETRY timer. */
		event_t *refresh_ev = zd->xfr_in.timer;
		if (refresh_ev) {
			debug_zones("zone: canceling REFRESH timer\n");
			evsched_cancel(sched, refresh_ev);
		}

		/* Get zone contents. */
		rcu_read_lock();
		const knot_zone_contents_t *contents =
				knot_zone_contents(zone);

		/* Check SOA SERIAL. */
		if (xfrin_transfer_needed(contents, packet) < 1) {

			/* Reinstall REFRESH timer. */
			uint32_t ref_tmr = 0;

			/* Retrieve SOA RDATA. */
			const knot_rrset_t *soa_rrs = 0;
			const knot_rdata_t *soa_rr = 0;
			soa_rrs = knot_node_rrset(
			             knot_zone_contents_apex(contents),
			             KNOT_RRTYPE_SOA);
			soa_rr = knot_rrset_rdata(soa_rrs);
			ref_tmr = knot_rdata_soa_refresh(soa_rr);
			ref_tmr *= 1000; /* Convert to miliseconds. */

			debug_zones("zone: reinstalling REFRESH timer (%u ms)\n",
				ref_tmr);

			evsched_schedule(sched, refresh_ev, ref_tmr);
			rcu_read_unlock();
			return KNOTD_EOK;
		}

		/* Prepare XFR client transfer. */
		knot_ns_xfr_t xfr_req;
		memset(&xfr_req, 0, sizeof(knot_ns_xfr_t));
		memcpy(&xfr_req.addr, from, sizeof(sockaddr_t));
		xfr_req.data = (void *)zone;
		xfr_req.send = zones_send_cb;

		/* Select transfer method. */
		xfr_req.type = zones_transfer_to_use(contents);

		/* Unlock zone contents. */
		rcu_read_unlock();

		/* Enqueue XFR request. */
		return xfr_request(nameserver->server->xfr_h, &xfr_req);
	}


	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

xfr_type_t zones_transfer_to_use(const knot_zone_contents_t *zone)
{
	/*! \todo Implement. */
	return XFR_TYPE_AIN;
}

/*----------------------------------------------------------------------------*/

static int zones_find_zone_for_xfr(const knot_zone_contents_t *zone, 
                                   const char **zonefile, const char **zonedb)
{
	// find the zone file name and zone db file name for the zone
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
			// found the right zone
			*zonefile = zone_conf->file;
			*zonedb = zone_conf->db;
			return KNOTD_EOK;
		}
	}

	char *name = knot_dname_to_str(knot_node_owner(
	                 knot_zone_contents_apex(zone)));
	debug_zones("No zone found for the zone received by transfer "
	                 "(%s).\n", name);
	free(name);

	return KNOTD_ENOENT;
}

/*----------------------------------------------------------------------------*/

static char *zones_find_free_filename(const char *old_name)
{
	// find zone name not present on the disk
	int free_name = 0;
	size_t name_size = strlen(old_name);

	char *new_name = malloc(name_size + 3);
	if (new_name == NULL) {
		return NULL;
	}
	memcpy(new_name, old_name, name_size);
	new_name[name_size] = '.';
	new_name[name_size + 2] = 0;

	debug_knot_ns("Finding free name for the zone file.\n");
	int c = 48;
	FILE *file;
	while (!free_name && c < 58) {
		new_name[name_size + 1] = c;
		debug_knot_ns("Trying file name %s\n", new_name);
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
		debug_zones("Failed to find free filename for temporary "
		                 "storage of the zone text file.\n");
		return KNOTD_ERROR;	/*! \todo New error code? */
	}

	int rc = zone_dump_text(zone, new_zonefile);

	if (rc != KNOTD_EOK) {
		debug_zones("Failed to save the zone to text zone file %s."
		                 "\n", new_zonefile);
		free(new_zonefile);
		return KNOTD_ERROR;
	}

	/*! \todo this would also need locking as well. */
	if (remove(zonefile) == 0) {
		if (rename(new_zonefile, zonefile) != 0) {
			debug_zones("Failed to replace old zonefile %s with new"
				    " zone file %s.\n", zonefile, new_zonefile);
			/*! \todo with proper locking, this shouldn't happen,
			 *        revise it later on.
			 */
			zone_dump_text(zone, zonefile);
			return KNOTD_ERROR;
		}
	} else {
		debug_zones("Failed to replace old zonefile %s.\n", zonefile);
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
		debug_zones("Failed to find free filename for temporary "
		                 "storage of the zone binary file.\n");
		return KNOTD_ERROR;	/*! \todo New error code? */
	}

	int rc = knot_zdump_binary(zone, new_zonedb, 0, zonefile);

	if (rc != KNOT_EOK) {
		debug_zones("Failed to save the zone to binary zone db %s."
		                 "\n", new_zonedb);
		free(new_zonedb);
		return KNOTD_ERROR;
	}

	/*! \todo this would also need locking as well. */
	if (remove(zonedb) == 0) {

		/*! \todo remove CRC file correctly as well, there should be an
		 *        API for that.
		 */
		const char *tmp_ext = ".crc";
		char *crc_fn = malloc(strlen(zonedb) + strlen(tmp_ext) + 1);
		memcpy(crc_fn, zonedb, strlen(zonedb)+1);
		strcat(crc_fn, tmp_ext);
		remove(crc_fn);

		/* rename new crc */
		char *tmp_crc = malloc(strlen(new_zonedb) + strlen(tmp_ext) + 1);
		memcpy(tmp_crc, new_zonedb, strlen(new_zonedb)+1);
		strcat(tmp_crc, tmp_ext);
		rename(tmp_crc, crc_fn);

		free(tmp_crc);
		free(crc_fn);

		/* rename zonedb */
		if (rename(new_zonedb, zonedb) != 0) {
			debug_zones("Failed to replace old zonefile %s with new"
				    " zone file %s.\n", zonedb, new_zonedb);
			/*! \todo with proper locking, this shouldn't happen,
			 *        revise it later on.
			 */
			zone_dump_text(zone, zonedb);
			return KNOTD_ERROR;
		}
	} else {
		debug_zones("Failed to replace old zonefile %s.\n", zonedb);
		return KNOTD_ERROR;
	}

	free(new_zonedb);
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
	
	// dump the zone into text zone file
	ret = zones_dump_xfr_zone_text(zone, zonefile);
	if (ret != KNOTD_EOK) {
		return KNOTD_ERROR;
	}
	// dump the zone into binary db file
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
	debug_zones("Event: reconfiguring name server.\n");

	knot_zonedb_t *old_db = 0;

	int ret = zones_update_db_from_config(conf, ns, &old_db);
	if (ret != KNOTD_EOK) {
		return ret;
	}
	// Wait until all readers finish with reading the zones.
	synchronize_rcu();

	debug_zones("Nameserver's zone db: %p, old db: %p\n", ns->zone_db,
	            old_db);

	// Delete all deprecated zones and delete the old database.
	knot_zonedb_deep_free(&old_db);

	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

static int zones_check_binary_size(uint8_t **data, size_t *allocated,
                                   size_t required)
{
	if (required > *allocated) {
		size_t new_size = *allocated;
		while (new_size <= required) {
			new_size += XFRIN_CHANGESET_BINARY_STEP;
		}
		uint8_t *new_data = (uint8_t *)malloc(new_size);
		if (new_data == NULL) {
			return KNOT_ENOMEM;
		}

		memcpy(new_data, *data, *allocated);
		uint8_t *old_data = *data;
		*data = new_data;
		*allocated = new_size;
		free(old_data);
	}

	return KNOT_EOK;
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
	if (ret != KNOT_EOK) {
		return KNOT_ERROR;  /*! \todo Other code? */
	}

	ret = zones_check_binary_size(data, allocated, *size + actual_size);
	if (ret != KNOT_EOK) {
		free(binary);
		return ret;
	}

	memcpy(*data + *size, binary, actual_size);
	*size += actual_size;
	free(binary);

	return KNOT_EOK;
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

		// 1) origin SOA
		ret = zones_changeset_rrset_to_binary(&ch->data, &ch->size,
		                                &ch->allocated, ch->soa_from);
		if (ret != KNOT_EOK) {
			free(ch->data);
			ch->data = NULL;
			return ret;
		}

		int j;

		// 2) remove RRsets
		assert(ch->remove_allocated >= ch->remove_count);
		for (j = 0; j < ch->remove_count; ++j) {
			ret = zones_changeset_rrset_to_binary(&ch->data,
			                                      &ch->size,
			                                      &ch->allocated,
			                                      ch->remove[j]);
			if (ret != KNOT_EOK) {
				free(ch->data);
				ch->data = NULL;
				return ret;
			}
		}

		// 3) new SOA
		ret = zones_changeset_rrset_to_binary(&ch->data, &ch->size,
		                                &ch->allocated, ch->soa_to);
		if (ret != KNOT_EOK) {
			free(ch->data);
			ch->data = NULL;
			return ret;
		}

		// 4) add RRsets
		assert(ch->add_allocated >= ch->add_count);
		for (j = 0; j < ch->add_count; ++j) {
			ret = zones_changeset_rrset_to_binary(&ch->data,
			                                      &ch->size,
			                                      &ch->allocated,
			                                      ch->add[j]);
			if (ret != KNOT_EOK) {
				free(ch->data);
				ch->data = NULL;
				return ret;
			}
		}
	}

	return KNOT_EOK;
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
					debug_knot_xfr("ixfr_db: cancelling SYNC "
							 "timer\n");
					evsched_cancel(tmr->parent, tmr);
				}

				/* Synchronize. */
				debug_knot_xfr("ixfr_db: forcing zonefile SYNC\n");
				ret = zones_zonefile_sync(zone);
				if (ret != KNOTD_EOK) {
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
					debug_knot_xfr("ixfr_db: resuming SYNC "
							 "timer\n");
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
	}

	/* Written changesets to journal. */
	return KNOTD_EOK;
}

/*----------------------------------------------------------------------------*/

int zones_xfr_load_changesets(knot_ns_xfr_t *xfr) 
{
	if (xfr == NULL || xfr->data == NULL || xfr->zone == NULL) {
		return KNOTD_EINVAL;
	}
	
	const knot_zone_t *zone = xfr->zone;
	const knot_zone_contents_t *contents = knot_zone_contents(zone);
	
	knot_changesets_t *chgsets = (knot_changesets_t *)
	                               calloc(1, sizeof(knot_changesets_t));
	
	const knot_rrset_t *zone_soa =
		knot_node_rrset(knot_zone_contents_apex(contents),
		                  KNOT_RRTYPE_SOA);
	// retrieve origin (xfr) serial and target (zone) serial
	uint32_t zone_serial = knot_rdata_soa_serial(
	                             knot_rrset_rdata(zone_soa));
	uint32_t xfr_serial = knot_rdata_soa_serial(knot_rrset_rdata(
			knot_packet_authority_rrset(xfr->query, 0)));
	
	int ret = zones_load_changesets(zone, chgsets, xfr_serial, zone_serial);
	if (ret != KNOTD_EOK) {
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
