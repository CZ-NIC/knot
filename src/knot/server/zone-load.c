/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <assert.h>
#include <sys/stat.h>
#include <inttypes.h>

#include "knot/conf/conf.h"
#include "knot/other/debug.h"
#include "knot/server/zone-load.h"
#include "knot/server/zones.h"
#include "knot/zone/zone-load.h"
#include "libknot/dname.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/random.h"
#include "libknot/nameserver/name-server.h"
#include "libknot/rdata.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/zone.h"
#include "libknot/zone/zonedb.h"
#include "zscanner/descriptor.h"

static const size_t XFRIN_BOOTSTRAP_DELAY = 2000; /*!< AXFR bootstrap avg. delay */

/*- zone data manipulation --------------------------------------------------*/

/*!
 * \brief Zone data destructor function.
 */
static int zonedata_destroy(knot_zone_t *zone)
{
	if (zone == NULL) {
		return KNOT_EINVAL;
	}

	zonedata_t *zd = (zonedata_t *)knot_zone_data(zone);
	if (!zd) {
		return KNOT_EINVAL;
	}

	/* Cancel REFRESH timer. */
	evsched_t *sch = zd->server->sched;
	if (zd->xfr_in.timer) {
		evsched_cancel(sch, zd->xfr_in.timer);
		evsched_event_free(sch, zd->xfr_in.timer);
		zd->xfr_in.timer = NULL;
	}

	/* Cancel EXPIRE timer. */
	if (zd->xfr_in.expire) {
		evsched_cancel(sch, zd->xfr_in.expire);
		evsched_event_free(sch, zd->xfr_in.expire);
		zd->xfr_in.expire = NULL;
	}

	/* Cancel IXFR DB sync timer. */
	if (zd->ixfr_dbsync) {
		evsched_cancel(sch, zd->ixfr_dbsync);
		evsched_event_free(sch, zd->ixfr_dbsync);
		zd->ixfr_dbsync = NULL;
	}

	/* Cancel DNSSEC timer. */
	if (zd->dnssec_timer) {
		evsched_cancel(sch, zd->dnssec_timer);
		evsched_event_free(sch, zd->dnssec_timer);
		zd->dnssec_timer = NULL;
	}

	acl_delete(&zd->xfr_in.acl);
	acl_delete(&zd->xfr_out);
	acl_delete(&zd->notify_in);
	acl_delete(&zd->notify_out);
	acl_delete(&zd->update_in);
	pthread_mutex_destroy(&zd->lock);
	pthread_mutex_destroy(&zd->ddns_lock);

	/* Close IXFR db. */
	journal_close(zd->ixfr_db);

	/* Free assigned config. */
	conf_free_zone(zd->conf);

	free(zd);
	zone->data = 0;
	return KNOT_EOK;
}

/*!
 * \brief Zone data constructor function.
 */
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

	/* Initialize mutexes. */
	pthread_mutex_init(&zd->lock, 0);
	pthread_mutex_init(&zd->ddns_lock, 0);

	/* Initialize XFR-IN. */
	sockaddr_init(&zd->xfr_in.master, -1);
	zd->xfr_in.bootstrap_retry = knot_random_uint32_t() % XFRIN_BOOTSTRAP_DELAY;

	/* Initialize IXFR database. */
	zd->ixfr_db = journal_open(cfg->ixfr_db, cfg->ixfr_fslimit, JOURNAL_DIRTY);
	if (zd->ixfr_db == NULL) {
		char ebuf[256] = {0};
		if (strerror_r(errno, ebuf, sizeof(ebuf)) == 0) {
			log_server_warning("Couldn't open journal file for "
			                   "zone '%s', disabling incoming "
			                   "IXFR. (%s)\n", cfg->name, ebuf);
		}
	}

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
		int64_t serial = knot_rdata_soa_serial(soa_rrs);
		zd->zonefile_serial = (uint32_t)serial;
		if (serial < 0) {
			return KNOT_EINVAL;
		}
	}

	return KNOT_EOK;
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
static int set_acl(acl_t **acl, list_t* acl_list)
{
	if (!acl || !acl_list) {
		return KNOT_EINVAL;
	}

	/* Create new ACL. */
	acl_t *old_acl = *acl;
	acl_t *new_acl = acl_new();
	if (new_acl == NULL) {
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
			acl_insert(new_acl, &addr, cfg_if);
		}
	}

	/* Synchronize and free old pointers. */
	*acl = new_acl;
	synchronize_rcu();

	/*! \note This is temporary solution.
	 *        Proper solution is to cancel/wait transfers and events
	 *        before zone starts reloading. This guarantess that nobody is
	 *        accessing the old zone configuration.
	 */
	acl_delete(&old_acl);

	return KNOT_EOK;
}

/*! \brief Create timer if not exists, cancel if running. */
static void timer_reset(evsched_t *sched, event_t **ev,
			event_cb_t cb, knot_zone_t *zone)
{
	if (*ev == NULL) {
		*ev = evsched_event_new_cb(sched, cb, zone);
	} else {
		evsched_cancel(sched, *ev);
	}
}

/*! \brief Reset zone data timers. */
static void zonedata_reset_timers(knot_zone_t *zone)
{
	zonedata_t *zd = zone->data;
	
	/* Create or cancel existing events. They must not be freed during their
	 * lifetime since they are referenced from numerous places.
	 * So each reload does following:
	 *  1. all events are cancelled on zonedata update, but initialized
	 *  2. all events may be scheduled (without changing the callback)
	 *  3. events may be freed _ONLY_ on zone teardown
	 */

	evsched_t *scheduler = zd->server->sched;
	timer_reset(scheduler, &zd->ixfr_dbsync, zones_flush_ev, zone);
	timer_reset(scheduler, &zd->xfr_in.timer, zones_refresh_ev, zone);
	timer_reset(scheduler, &zd->xfr_in.expire, zones_expire_ev, zone);
	timer_reset(scheduler, &zd->dnssec_timer, zones_dnssec_ev, zone);	
}

/*!
 * \brief Update zone data from new configuration.
 *
 * \param zone  Zone to be updated.
 * \param conf  New zone configuration.
 * \param ns    Server data structure.
 */
static void zonedata_update(knot_zone_t *zone, conf_zone_t *conf,
                            knot_nameserver_t *ns)
{
	assert(zone);
	assert(conf);
	assert(ns);
	assert(ns->data);

	zonedata_t *zd = zone->data;
	assert(zd);

	// data pointers
	conf_zone_t *old_conf = NULL;
	if (zd->conf != conf) {
		old_conf = zd->conf;
		zd->conf = conf;
	}

	zd->server = (server_t *)ns->data;

	/* Reset event timers. */
	zonedata_reset_timers(zone);

	// ACLs

	set_acl(&zd->xfr_in.acl, &conf->acl.xfr_in);
	set_acl(&zd->xfr_out,    &conf->acl.xfr_out);
	set_acl(&zd->notify_in,  &conf->acl.notify_in);
	set_acl(&zd->notify_out, &conf->acl.notify_out);
	set_acl(&zd->update_in,  &conf->acl.update_in);

	// clear incoming XFRs master

	zd->xfr_in.has_master = 0;
	memset(&zd->xfr_in.tsig_key, 0, sizeof(knot_tsig_key_t));
	sockaddr_init(&zd->xfr_in.master, -1);
	sockaddr_init(&zd->xfr_in.via, -1);

	// set incoming XFRs master

	if (!EMPTY_LIST(conf->acl.xfr_in)) {
		zd->xfr_in.has_master = 1;

		conf_remote_t *master = HEAD(conf->acl.xfr_in);
		conf_iface_t *master_if = master->remote;
		sockaddr_set(&zd->xfr_in.master, master_if->family,
		             master_if->address, master_if->port);

		if (sockaddr_isvalid(&master_if->via)) {
			sockaddr_copy(&zd->xfr_in.via, &master_if->via);
		}

		if (master_if->key) {
			memcpy(&zd->xfr_in.tsig_key, master_if->key,
			       sizeof(knot_tsig_key_t));
		}
	}

	// ANY queries policy

	/*! \todo Zone contents settings can be replaced by other async
	          operation, like transfer processing. */

	rcu_read_lock();
	if (conf->disable_any) {
		knot_zone_contents_disable_any(zone->contents);
	} else {
		knot_zone_contents_enable_any(zone->contents);
	}
	rcu_read_unlock();

	/* Synchronize and free old pointers. */
	synchronize_rcu();

	/*! \note This is temporary solution.
	 *        Proper solution is to cancel/wait transfers and events
	 *        before zone starts reloading. This guarantess that nobody is
	 *        accessing the old zone configuration.
	 */
	conf_free_zone(old_conf);
}

/*! \brief Freeze the zone data to prevent any further transfers or
 *         events manipulation.
 */
static void zonedata_freeze(knot_zone_t *zone)
{
	zonedata_t *zone_data = zone->data;
	
	/*! \todo NOTIFY, xfers and updates now MUST NOT trigger reschedule. */
	/*! \todo No new xfers or updates should be processed. */
	/*! \todo Raise some kind of flag. */
	
	/* Wait for readers to notice the change. */
	synchronize_rcu();

	/* Cancel all pending timers. */
	zonedata_reset_timers(zone);
	
	/* Now some transfers may already be running, we need to wait for them. */
	/*! \todo This should be done somehow. */
	
	/* Reacquire journal to ensure all operations on it are finished. */
	if (journal_retain(zone_data->ixfr_db) == KNOT_EOK) {
		journal_release(zone_data->ixfr_db);
	}
}

/*- zone file status --------------------------------------------------------*/

/*!
 * \brief Zone file status.
 */
typedef enum {
	ZONE_STATUS_NOT_FOUND = 0,  //!< Zone file does not exist.
	ZONE_STATUS_FOUND_NEW,      //!< Zone file exists, not loaded yet.
	ZONE_STATUS_FOUND_CURRENT,  //!< Zone file exists, same as loaded.
	ZONE_STATUS_FOUND_UPDATED,  //!< Zone file exists, newer than loaded.
} zone_status_t;

/*!
 * \brief Check zone file status.
 *
 * \param zone      Previous instance of the zone (can be NULL).
 * \param filename  File name of zone file.
 *
 * \return Zone status.
 */
static zone_status_t zone_file_status(const knot_zone_t *zone,
                                      const char *filename)
{
	struct stat zf_stat = { 0 };
	int result = stat(filename, &zf_stat);

	if (result == -1) {
		return ZONE_STATUS_NOT_FOUND;
	} else if (zone == NULL) {
		return ZONE_STATUS_FOUND_NEW;
	} else if (knot_zone_version(zone) == zf_stat.st_mtime) {
		return ZONE_STATUS_FOUND_CURRENT;
	} else {
		return ZONE_STATUS_FOUND_UPDATED;
	}
}

/*- zone loading/updating ---------------------------------------------------*/

/*!
 * \brief Create zone stub for zone bootstrapping.
 *
 * \param apex  Zone name.
 *
 * \return New zone, NULL in case of allocation error.
 */
static knot_zone_t *create_bootstrap_zone(const knot_dname_t *apex)
{
	knot_dname_t *owner = knot_dname_copy(apex);
	knot_zone_t *result = knot_zone_new_empty(owner);

	if (result == NULL) {
		knot_dname_free(&owner);
	}

	return result;
}

/*!
 * \brief Handle retrieval of zone if zone file does not exist.
 *
 * \param old_zone  Old loaded zone (can be NULL).
 * \param apex      Zone name.
 * \param conf      New configuration for given zone.
 * \param ns        Name server structure.
 *
 * \return New zone, NULL if bootstrap not possible.
 */
knot_zone_t *get_not_found_zone(knot_zone_t *old_zone, const knot_dname_t *apex,
                                conf_zone_t *conf, knot_nameserver_t *ns)
{
	assert(apex);
	assert(conf);
	assert(ns);

	bool bootstrap = !EMPTY_LIST(conf->acl.xfr_in);
	if (!bootstrap) {
		return NULL;
	}

	if (old_zone) {
		return old_zone;
	}

	knot_zone_t *new_zone = create_bootstrap_zone(apex);
	zonedata_init(conf, new_zone);
	if (!new_zone) {
		log_server_error("Bootstrap of zone '%s' failed: %s\n",
		                 conf->name, knot_strerror(KNOT_ENOMEM));
		return NULL;
	}

	return new_zone;
}

/*!
 * \brief Load zone.
 *
 * \param conf Zone configuration.
 *
 * \return Loaded zone, NULL in case of error.
 */
static knot_zone_t *load_zone(conf_zone_t *conf)
{
	assert(conf);

	zloader_t *zl = NULL;
	knot_zone_t *zone = NULL;

	/* Open zone file for parsing. */
	switch (knot_zload_open(&zl, conf->file, conf->name, conf->enable_checks)) {
	case KNOT_EOK:
		break;
	case KNOT_EACCES:
		log_server_error("No access/permission to zone file '%s'.\n",
		                 conf->file);
		knot_zload_close(zl);
		return NULL;
	default:
		log_server_error("Failed to load zone file '%s'\n", conf->file);
		knot_zload_close(zl);
		return NULL;
	}

	/* Check the source file */
	assert(zl != NULL);
	zone = knot_zload_load(zl);
	if (!zone) {
		log_zone_error("Zone '%s' could not be loaded.\n", conf->name);
		knot_zload_close(zl);
		return NULL;
	}

	/* Check if loaded origin matches. */
	const knot_dname_t *dname = knot_zone_name(zone);
	knot_dname_t *dname_req = NULL;
	dname_req = knot_dname_from_str(conf->name);
	if (knot_dname_cmp(dname, dname_req) != 0) {
		log_server_error("Origin of the zone db file is "
				 "different than '%s'\n",
				 conf->name);
		knot_zone_deep_free(&zone);
		return NULL;
	} else {
		/* Save the timestamp from the zone db file. */
		struct stat st;
		if (stat(conf->file, &st) < 0) {
			dbg_zones("zones: failed to stat() zone db, "
				  "something is seriously wrong\n");
			knot_zone_deep_free(&zone);
			return NULL;
		} else {
			knot_zone_set_version(zone, st.st_mtime);
		}
	}
	knot_dname_free(&dname_req);
	knot_zload_close(zl);

	zonedata_init(conf, zone);

	return zone;
}

/*!
 * \brief Log message about loaded zone (name, status, serial).
 *
 * \param zone       Zone structure.
 * \param zone_name  Printable name of the zone.
 * \param status     Zone file status.
 */
static void log_zone_load_info(const knot_zone_t *zone, const char *zone_name,
                               zone_status_t status)
{
	const char *action = NULL;

	switch (status) {
	case ZONE_STATUS_NOT_FOUND:     action = "bootstrapped";  break;
	case ZONE_STATUS_FOUND_NEW:     action = "loaded";        break;
	case ZONE_STATUS_FOUND_CURRENT: action = "is up-to-date"; break;
	case ZONE_STATUS_FOUND_UPDATED: action = "reloaded";      break;
	}
	assert(action);

	int64_t serial = 0;
	if (zone->contents && zone->contents->apex) {
		const knot_rrset_t *soa;
		soa = knot_node_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
		serial = knot_rdata_soa_serial(soa);
	}

	log_server_info("Zone '%s' %s (serial %" PRId64 ")\n",
	                zone_name, action, serial);
}

/*!
 * \brief Load or reload the zone.
 *
 * \param old_zone  Already loaded zone (can be NULL).
 * \param apex      Zone apex.
 * \param conf      Zone configuration.
 * \param ns        Name server structure.
 *
 * \return Error code, KNOT_EOK if successful.
 */
knot_zone_t *get_zone(knot_zone_t *old_zone, const knot_dname_t *apex,
                      conf_zone_t *conf, knot_nameserver_t *ns)
{
	assert(apex);
	assert(conf);
	assert(ns);

	zone_status_t zstatus = zone_file_status(old_zone, conf->file);
	knot_zone_t *new_zone = NULL;

	switch (zstatus) {
	case ZONE_STATUS_NOT_FOUND:
		new_zone = get_not_found_zone(old_zone, apex, conf, ns);
		break;
	case ZONE_STATUS_FOUND_NEW:
	case ZONE_STATUS_FOUND_UPDATED:
		new_zone = load_zone(conf);
		break;
	case ZONE_STATUS_FOUND_CURRENT:
		assert(old_zone);
		new_zone = old_zone;
		break;
	default:
		assert(0);
	}

	if (!new_zone) {
		log_server_error("Failed to load zone '%s'.\n", conf->name);
		return NULL;
	}

	log_zone_load_info(new_zone, conf->name, zstatus);

	return new_zone;
}

/*!
 * \brief Load/reload the zone, apply journal, sign it and schedule XFR sync.
 *
 * \param[out] dst   Pointer to successfully loaded zone.
 * \param[in]  conf  Zone configuration.
 * \param[in]  ns    Name server structure.
 *
 * \return Error code, KNOT_EOK if sucessful.
 */
static int update_zone(knot_zone_t **dst, conf_zone_t *conf, knot_nameserver_t *ns)
{
	assert(dst);
	assert(conf);
	assert(ns);

	int result = KNOT_ERROR;

	knot_dname_t *apex = knot_dname_from_str(conf->name);
	if (!apex) {
		return KNOT_ENOMEM;
	}

	knot_zone_t *old_zone = knot_zonedb_find_zone(ns->zone_db, apex);
	knot_zone_t *new_zone = get_zone(old_zone, apex, conf, ns);

	knot_dname_free(&apex);

	if (!new_zone) {
		return KNOT_EZONENOENT;
	}
	
	/*! \todo What should be done as part of the #26
	 *  - Zone MUST BE created anew every time, content may be refcounted.
	 *    (or at least zone->data and it must be updated in a RCU safe way)
	 *  - Zone about the be obsoleted should be frozen (see more info in zonedata_freeze)
	 *  - Refcounting on zone can be removed then, because freeze
	 *    guarantees that zone is not and won't be participating on further
	 *    transfers, updates or events.
	 */
	
	/* Freeze the old zone blocks any further transfers or events,
	 * as it will be deleted later on. */
	if (old_zone && new_zone != old_zone) {
		zonedata_freeze(old_zone);
	}

	zonedata_update(new_zone, conf, ns);

	result = zones_journal_apply(new_zone);
	if (result != KNOT_EOK && result != KNOT_ERANGE && result != KNOT_ENOENT) {
		log_server_error("Zone '%s', failed to apply changes from "
		                 "journal: %s\n",
		                 conf->name, knot_strerror(result));
		goto fail;
	}

	bool modified = (old_zone != new_zone);
	result = zones_do_diff_and_sign(conf, new_zone, ns, modified);
	if (result != KNOT_EOK) {
		log_server_error("Zone '%s', failed to sign the zone: %s\n",
		                 conf->name, knot_strerror(result));
		goto fail;
	}

	/* Schedule zonefile flush. */
	zones_schedule_ixfr_sync(new_zone, conf->dbsync_timeout);

	knot_zone_contents_t *new_contents = new_zone->contents;
	if (new_contents) {
		/* Check NSEC3PARAM state if present. */
		result = knot_zone_contents_load_nsec3param(new_contents);
		if (result != KNOT_EOK) {
			log_zone_error("NSEC3 signed zone has invalid or no "
				       "NSEC3PARAM record.\n");
			goto fail;
		}
		/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
		if (knot_zone_contents_is_signed(new_contents)) {
			unsigned edns_dnssec_min = EDNS_MIN_DNSSEC_PAYLOAD;
			if (knot_edns_get_payload(ns->opt_rr) < edns_dnssec_min) {
				log_zone_warning("EDNS payload lower than %uB for "
						 "DNSSEC-enabled zone '%s'.\n",
						 edns_dnssec_min, conf->name);
			}
		}
	}

fail:
	assert(new_zone);

	if (result == KNOT_EOK) {
		*dst = new_zone;
	} else {
		// unbind configuration from zone, which failed to load
		zonedata_t *zone_data = new_zone->data;
		if (zone_data->conf == conf) {
			zone_data->conf = NULL;
		}

		// free zone, unless we were refreshing old one
		if (new_zone != old_zone) {
			knot_zone_deep_free(&new_zone);
		}
	}

	return result;
}

/*! \brief Context for threaded zone loader. */
typedef struct {
	const struct conf_t *config;
	knot_nameserver_t *ns;
	knot_zonedb_t *db_new;
	pthread_mutex_t lock;
} zone_loader_ctx_t;

/*! Thread entrypoint for loading zones. */
static int zone_loader_thread(dthread_t *thread)
{
	if (thread == NULL || thread->data == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_ERROR;
	knot_zone_t *zone = NULL;
	conf_zone_t *zone_config = NULL;
	zone_loader_ctx_t *ctx = (zone_loader_ctx_t *)thread->data;
	for(;;) {
		/* Fetch zone configuration from the list. */
		pthread_mutex_lock(&ctx->lock);
		if (EMPTY_LIST(ctx->config->zones)) {
			pthread_mutex_unlock(&ctx->lock);
			break;
		}

		/* Disconnect from the list and start processing. */
		zone_config = HEAD(ctx->config->zones);
		rem_node(&zone_config->n);
		pthread_mutex_unlock(&ctx->lock);

		/* Update the zone. */
		ret = update_zone(&zone, zone_config, ctx->ns);

		/* Insert into database if properly loaded. */
		pthread_mutex_lock(&ctx->lock);
		if (ret == KNOT_EOK) {
			if (knot_zonedb_add_zone(ctx->db_new, zone) != KNOT_EOK) {
				log_server_error("Failed to insert zone '%s' "
				                 "into database.\n", zone_config->name);
				knot_zone_deep_free(&zone);
			}
		} else {
			/* Unable to load, discard configuration. */
			conf_free_zone(zone_config);
		}
		pthread_mutex_unlock(&ctx->lock);
	}

	return KNOT_EOK;
}

static int zone_loader_destruct(dthread_t *thread)
{
	knot_crypto_cleanup_thread();
	return KNOT_EOK;
}

/*!
 * \brief Fill the new database with zones.
 *
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param ns Name server instance.
 * \param conf Server configuration.
 *
 * \return Number of inserted zones.
 */
static knot_zonedb_t *load_zonedb(knot_nameserver_t *ns, const conf_t *conf)
{
	/* Initialize threaded loader. */
	zone_loader_ctx_t ctx = {0};
	ctx.ns = ns;
	ctx.config = conf;
	ctx.db_new = knot_zonedb_new(conf->zones_count);
	if (ctx.db_new == NULL) {
		return NULL;
	}

	if (conf->zones_count == 0) {
		return ctx.db_new;
	}

	if (pthread_mutex_init(&ctx.lock, NULL) < 0) {
		knot_zonedb_free(&ctx.db_new);
		return NULL;
	}

	/* Initialize threads. */
	size_t thread_count = MIN(conf->zones_count, dt_optimal_size());
	dt_unit_t *unit = NULL;
	unit = dt_create_coherent(thread_count, &zone_loader_thread,
	                          &zone_loader_destruct, &ctx);
	if (unit != NULL) {
		/* Start loading. */
		dt_start(unit);
		dt_join(unit);
		dt_delete(&unit);
	} else {
		knot_zonedb_free(&ctx.db_new);
		ctx.db_new = NULL;
	}

	pthread_mutex_destroy(&ctx.lock);
	return ctx.db_new;
}

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
static int remove_zones(const knot_zonedb_t *db_new,
                              knot_zonedb_t *db_old)
{
	unsigned new_zone_count = db_new->count;
	const knot_zone_t **new_zones = knot_zonedb_zones(db_new);
	const knot_zone_t *old_zone = NULL;
	for (unsigned i = 0; i < new_zone_count; ++i) {

		/* try to find the new zone in the old DB
		 * if the pointers match, remove the zone from old DB
		 */
		old_zone = knot_zonedb_find_zone(db_old, knot_zone_name(new_zones[i]));
		if (old_zone == new_zones[i]) {
			/* Remove from zone db. */
			knot_zone_t * rm = knot_zonedb_remove_zone(db_old,
			                              knot_zone_name(old_zone));
			assert(rm == old_zone);
		}
	}

	return KNOT_EOK;
}

/*- public API functions ----------------------------------------------------*/

/*!
 * \brief Update zone database according to configuration.
 */
int zones_update_db_from_config(const conf_t *conf, knot_nameserver_t *ns,
                               knot_zonedb_t **db_old)
{
	/* Check parameters */
	if (conf == NULL || ns == NULL) {
		return KNOT_EINVAL;
	}

	/* Grab a pointer to the old database */
	if (ns->zone_db == NULL) {
		log_server_error("Missing zone database in nameserver structure"
		                 ".\n");
		return KNOT_ENOENT;
	}

	/* Insert all required zones to the new zone DB. */
	/*! \warning RCU must not be locked as some contents switching will
	             be required. */
	knot_zonedb_t *db_new = load_zonedb(ns, conf);
	if (db_new == NULL) {
		log_server_warning("Failed to load zones.\n");
		return KNOT_ENOMEM;
	} else {
		size_t loaded = knot_zonedb_zone_count(db_new);
		log_server_info("Loaded %zu out of %d zones.\n",
		                loaded, conf->zones_count);
		if (loaded != conf->zones_count) {
			log_server_warning("Not all the zones were loaded.\n");
		}
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

	/* Rebuild zone database search stack. */
	knot_zonedb_build_index(db_new);

	/*
	 * Remove all zones present in the new DB from the old DB.
	 * No new thread can access these zones in the old DB, as the
	 * databases are already switched.
	 *
	 * Beware - only the exact same zones (same pointer) may be removed.
	 * All other have been loaded again so that the old must be destroyed.
	 */
	int ret = remove_zones(db_new, *db_old);

	/* Unlock RCU, messing with any data will not affect us now */
	rcu_read_unlock();

	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}
