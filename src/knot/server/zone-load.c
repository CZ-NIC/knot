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

#include "knot/conf/conf.h"
#include "knot/server/zone-load.h"
#include "knot/server/zones.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonedb.h"
#include "libknot/dname.h"

/* Constants */

#define XFRIN_BOOTSTRAP_DELAY 2000 /*!< AXFR bootstrap avg. delay */

/*- zone file status --------------------------------------------------------*/

/*!
 * \brief Zone file status.
 */
typedef enum {
	ZONE_STATUS_NOT_FOUND = 0,  //!< Zone file does not exist.
	ZONE_STATUS_BOOSTRAP,       //!< Zone file does not exist, can boostrap.
	ZONE_STATUS_FOUND_NEW,      //!< Zone file exists, not loaded yet.
	ZONE_STATUS_FOUND_CURRENT,  //!< Zone file exists, same as loaded.
	ZONE_STATUS_FOUND_UPDATED,  //!< Zone file exists, newer than loaded.
} zone_status_t;

/*!
 * \brief Check if zone can be bootstrapped.
 */
static bool zone_can_boostrap(const conf_zone_t *conf)
{
	assert(conf);
	return  !EMPTY_LIST(conf->acl.xfr_in);
}

/*!
 * \brief Check zone file status.
 *
 * \param old_zone  Previous instance of the zone (can be NULL).
 * \param conf      Zone configuration.
 *
 * \return Zone status.
 */
static zone_status_t zone_file_status(const zone_t *old_zone,
                                      const conf_zone_t *conf)
{
	assert(conf);
	
	struct stat zf_stat = { 0 };
	int result = stat(conf->file, &zf_stat);

	if (result == -1) {
		return zone_can_boostrap(conf) ? ZONE_STATUS_BOOSTRAP \
		                               : ZONE_STATUS_NOT_FOUND;
	} if (old_zone == NULL) {
		return ZONE_STATUS_FOUND_NEW;
	} else if (old_zone->zonefile_mtime == zf_stat.st_mtime) {
		return ZONE_STATUS_FOUND_CURRENT;
	} else {
		return ZONE_STATUS_FOUND_UPDATED;
	}
}

/*- zone loading/updating ---------------------------------------------------*/

zone_t *load_zone_file(conf_zone_t *conf)
{
	return NULL;
}

/*!
 * \brief Log message about loaded zone (name and status).
 *
 * \param zone       Zone structure.
 * \param zone_name  Printable name of the zone.
 * \param status     Zone file status.
 */
static void log_zone_load_info(const zone_t *zone, const char *zone_name,
                               zone_status_t status)
{
	assert(zone);
	assert(zone_name);

	const char *action = NULL;

	switch (status) {
	case ZONE_STATUS_NOT_FOUND:     action = "not found";            break;
	case ZONE_STATUS_BOOSTRAP:      action = "will be bootstrapped"; break;
	case ZONE_STATUS_FOUND_NEW:     action = "will be loaded";       break;
	case ZONE_STATUS_FOUND_CURRENT: action = "is up-to-date";        break;
	case ZONE_STATUS_FOUND_UPDATED: action = "will be reloaded";     break;
	}
	assert(action);

	log_zone_info("Zone '%s' %s.\n", zone_name, action);
}

/*!
 * \brief Load or reload the zone.
 *
 * \param conf      Zone configuration.
 * \param server    Server.
 * \param old_zone  Already loaded zone (can be NULL).
 *
 * \return Error code, KNOT_EOK if successful.
 */
static zone_t *create_zone(conf_zone_t *conf, server_t *server, zone_t *old_zone)
{
	assert(conf);
	assert(server);
	
	zone_t *zone = zone_new(conf);
	if (!zone) {
		return NULL;
	}

	if (old_zone) {
		zone->contents = old_zone->contents;
	}

	zone_status_t zstatus = zone_file_status(old_zone, conf);

	switch (zstatus) {
	case ZONE_STATUS_FOUND_NEW:
	case ZONE_STATUS_FOUND_UPDATED:
		zone_events_schedule(zone, ZONE_EVENT_RELOAD, 1);
		break;
	case ZONE_STATUS_BOOSTRAP:
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, 1);
		break;
	case ZONE_STATUS_NOT_FOUND:
	case ZONE_STATUS_FOUND_CURRENT:
		break;
	default:
		assert(0);
	}

	int result = zone_events_setup(zone, server->workers, &server->sched);
	if (result != KNOT_EOK) {
		zone->conf = NULL;
		zone_free(&zone);
		return NULL;
	}

	log_zone_load_info(zone, conf->name, zstatus);

	return zone;
}

#if 0

/*!
 * \brief Load/reload the zone, apply journal, sign it and schedule XFR sync.
 *
 * \param[in]  old_zone  Old zone (if loaded).
 * \param[in]  conf      Zone configuration.
 * \param[in]  server    Name server structure.
 *
 * \return Updated zone on success, NULL otherwise.
 */
static zone_t* update_zone(zone_t *old_zone, conf_zone_t *conf, server_t *server)
{
	assert(conf);

	int result = KNOT_ERROR;

	// Load zone.
	zone_t *new_zone = create_zone(old_zone, conf, server);
	if (!new_zone) {
		return NULL;
	}

	bool new_content = (old_zone == NULL || old_zone->contents != new_zone->contents);

	result = zones_journal_apply(new_zone);
	if (result != KNOT_EOK && result != KNOT_ERANGE && result != KNOT_ENOENT) {
		log_zone_error("Zone '%s' failed to apply changes from journal - %s\n",
		               conf->name, knot_strerror(result));
		goto fail;
	}

	result = zones_do_diff_and_sign(new_zone, old_zone, new_content);
	if (result != KNOT_EOK) {
		if (result == KNOT_ESPACE) {
			log_zone_error("Zone '%s' journal size is too small to fit the changes.\n",
			               conf->name);
		} else {
			log_zone_error("Zone '%s' failed to store changes in the journal - %s\n",
			               conf->name, knot_strerror(result));
		}
		goto fail;
	}

fail:
	assert(new_zone);

	if (result == KNOT_EOK) {
		return new_zone;
	} else {
		/* Preserved zone, don't free the shared contents. */
		if (!new_content) {
			new_zone->contents = NULL;
		}

		/* Disconnect config, caller is responsible for it. */
		new_zone->conf = NULL;
		zone_free(&new_zone);
	}

	return NULL;
}

/*!
 * \brief Check zone configuration constraints.
 */
static int update_zone_postcond(zone_t *new_zone, const conf_t *config)
{
	/* Bootstrapped zone, no checks apply. */
	if (new_zone->contents == NULL) {
		return KNOT_EOK;
	}

	/* Check minimum EDNS0 payload if signed. (RFC4035/sec. 3) */
	if (knot_zone_contents_is_signed(new_zone->contents)) {
		unsigned edns_dnssec_min = EDNS_MIN_DNSSEC_PAYLOAD;
		if (config->max_udp_payload < edns_dnssec_min) {
			log_zone_warning("EDNS payload lower than %uB for "
			                 "DNSSEC-enabled zone '%s'.\n",
			                 edns_dnssec_min, new_zone->conf->name);
		}
	}

	/* Check NSEC3PARAM state if present. */
	int result = knot_zone_contents_load_nsec3param(new_zone->contents);
	if (result != KNOT_EOK) {
		log_zone_error("NSEC3 signed zone has invalid or no "
			       "NSEC3PARAM record.\n");
		return result;
	}

	return KNOT_EOK;
}

#endif

#if 0

/*! Thread entrypoint for loading zones. */
static int zone_loader_thread(dthread_t *thread)
{

		/* Update the zone. */
		zone = update_zone(old_zone, zone_config, ctx->server);
		if (zone == NULL) {
			conf_free_zone(zone_config);
			continue;
		}

		/* Check updated zone post-conditions. */
		int ret = update_zone_postcond(zone, ctx->config);

		/* Insert into database if properly loaded. */
		if (ret == KNOT_EOK) {
			pthread_mutex_lock(&ctx->lock);
			if (zone != NULL) {
				ret = knot_zonedb_insert(ctx->db_new, zone);
			}
			pthread_mutex_unlock(&ctx->lock);
		}

		/* Check for any failure. */
		if (ret != KNOT_EOK && zone) {
			/* Preserved zone, don't free the shared contents. */
			if (old_zone && old_zone->contents == zone->contents) {
				zone->contents = NULL;
			}

			zone_free(&zone);
		}
	}

	return KNOT_EOK;
}

#endif

/*!
 * \brief Create new zone database.
 * 
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param conf    New server configuration.
 * \param old_db  Old zone database (can be NULL).
 *
 * \return New zone database.
 */
static knot_zonedb_t *create_zonedb(const conf_t *conf, server_t *server)
{
	assert(conf);
	assert(server);
	
	knot_zonedb_t *db_old = server->zone_db;
	knot_zonedb_t *db_new = knot_zonedb_new(conf->zones_count);
	if (!db_new) {
		return NULL;
	}

	node_t *n = NULL;
	WALK_LIST(n, conf->zones) {
		conf_zone_t *zone_config = (conf_zone_t *)n;

		knot_dname_t *apex = knot_dname_from_str(zone_config->name);
		zone_t *old_zone = knot_zonedb_find(db_old, apex);
		knot_dname_free(&apex);

		zone_t *zone = create_zone(zone_config, server, old_zone);
		if (!zone) {
			log_server_error("Zone '%s' cannot be created.\n",
			                 zone_config->name);
			conf_free_zone(zone_config);
			continue;
		}

		knot_zonedb_insert(db_new, zone);
	}
	
	return db_new;
}

/*!
 * \brief Remove old zones and zone database.
 *
 * \note Zone may be preserved in the new zone database, in this case
 *       new and old zone share the contents. Shared content is not freed.
 *
 * \param db_new New zone database.
 * \param db_old Old zone database.
  */
static int remove_old_zonedb(const knot_zonedb_t *db_new, knot_zonedb_t *db_old)
{
	if (db_old == NULL) {
		return KNOT_EOK;
	}

	knot_zonedb_iter_t it;
	knot_zonedb_iter_begin(db_new, &it);

	while(!knot_zonedb_iter_finished(&it)) {
		zone_t *new_zone = knot_zonedb_iter_val(&it);
		zone_t *old_zone = knot_zonedb_find(db_old, new_zone->name);
		
		if (old_zone) {
			old_zone->contents = NULL;
		}

		knot_zonedb_iter_next(&it);
	}

	synchronize_rcu();

	knot_zonedb_deep_free(&db_old);

	return KNOT_EOK;
}

/*- public API functions ----------------------------------------------------*/

/*!
 * \brief Update zone database according to configuration.
 */
int load_zones_from_config(const conf_t *conf, struct server_t *server)
{
	/* Check parameters */
	if (conf == NULL || server == NULL) {
		return KNOT_EINVAL;
	}

	/* Freeze zone timers. */
	if (server->zone_db) {
		// TODO: ne, tohle nechceme
		//knot_zonedb_foreach(server->zone_db, zone_events_freeze);
	}

	/* Insert all required zones to the new zone DB. */
	/*! \warning RCU must not be locked as some contents switching will
	             be required. */
	knot_zonedb_t *db_new = create_zonedb(conf, server);
	if (db_new == NULL) {
		log_server_error("Failed to create new zone database.\n");
		return KNOT_ENOMEM;
	}

	/* Rebuild zone database search stack. */
	knot_zonedb_build_index(db_new);

	/* Switch the databases. */
	knot_zonedb_t *db_old = rcu_xchg_pointer(&server->zone_db, db_new);

	/* Wait for readers to finish reading old zone database. */
	synchronize_rcu();

	/* Thaw zone events now that the database is published. */
	if (server->zone_db) {
		knot_zonedb_foreach(server->zone_db, zone_events_start);
		// TODO: emit after loading
		//knot_zonedb_foreach(server->zone_db, zones_schedule_notify, server);
	}

	/*
	 * Remove all zones present in the new DB from the old DB.
	 * No new thread can access these zones in the old DB, as the
	 * databases are already switched.
	 */
	return remove_old_zonedb(db_new, db_old);
}
