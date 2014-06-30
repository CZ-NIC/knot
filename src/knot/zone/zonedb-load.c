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

#include <assert.h>
#include <sys/stat.h>

#include "knot/zone/zonedb-load.h"
#include "knot/zone/zone-load.h"
#include "knot/conf/conf.h"
#include "libknot/rrtype/soa.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zonedb.h"
#include "knot/server/server.h"
#include "libknot/dname.h"

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
	
	time_t mtime = zonefile_mtime(conf->file);

	if (mtime < 0) {
		// Zone file does not exist.
		if (old_zone) {
			// Deferred flush.
			return ZONE_STATUS_FOUND_CURRENT;
		} else {
			return zone_load_can_bootstrap(conf) ? ZONE_STATUS_BOOSTRAP \
			                                     : ZONE_STATUS_NOT_FOUND;
		}
	} else {
		// Zone file exists.
		if (old_zone == NULL) {
			return ZONE_STATUS_FOUND_NEW;
		} else if (old_zone->zonefile_mtime == mtime) {
			return ZONE_STATUS_FOUND_CURRENT;
		} else {
			return ZONE_STATUS_FOUND_UPDATED;
		}
	}
}

/*- zone loading/updating ---------------------------------------------------*/

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

	uint32_t serial = 0;
	if (zone->contents && zone->contents->apex) {
		const knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
		                                           KNOT_RRTYPE_SOA);
		serial = knot_soa_serial(soa);
	}

	log_zone_info("Zone '%s' %s (serial %u)\n", zone_name, action, serial);
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

	int result = zone_events_setup(zone, server->workers, &server->sched);
	if (result != KNOT_EOK) {
		zone->conf = NULL;
		zone_free(&zone);
		return NULL;
	}

	switch (zstatus) {
	case ZONE_STATUS_FOUND_NEW:
	case ZONE_STATUS_FOUND_UPDATED:
		/* Enqueueing makes the first zone load waitable. */
		zone_events_enqueue(zone, ZONE_EVENT_RELOAD);
		/* Replan DDNS processing if there are pending updates. */
		zone_events_replan_ddns(zone, old_zone);
		break;
	case ZONE_STATUS_BOOSTRAP:
		zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);
		break;
	case ZONE_STATUS_NOT_FOUND:
		break;
	case ZONE_STATUS_FOUND_CURRENT:
		assert(old_zone);
		zone->zonefile_mtime = old_zone->zonefile_mtime;
		zone->zonefile_serial = old_zone->zonefile_serial;
		zone_events_update(zone, old_zone);
		break;
	default:
		assert(0);
	}

	log_zone_load_info(zone, conf->name, zstatus);

	return zone;
}

/*!
 * \brief Create new zone database.
 * 
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param conf    New server configuration.
 * \param server  Server instance.
 *
 * \return New zone database.
 */
static knot_zonedb_t *create_zonedb(const conf_t *conf, server_t *server)
{
	assert(conf);
	assert(server);
	
	knot_zonedb_t *db_old = server->zone_db;
	knot_zonedb_t *db_new = knot_zonedb_new(hattrie_weight(conf->zones));
	if (!db_new) {
		return NULL;
	}

	hattrie_iter_t *it = hattrie_iter_begin(conf->zones, false);
	for (; !hattrie_iter_finished(it); hattrie_iter_next(it)) {

		conf_zone_t *zone_config = (conf_zone_t *)*hattrie_iter_val(it);

		knot_dname_t *apex = knot_dname_from_str(zone_config->name);
		zone_t *old_zone = knot_zonedb_find(db_old, apex);
		knot_dname_free(&apex, NULL);

		zone_t *zone = create_zone(zone_config, server, old_zone);
		if (!zone) {
			log_server_error("Zone '%s' cannot be created.\n",
			                 zone_config->name);
			conf_free_zone(zone_config);
			continue;
		}

		knot_zonedb_insert(db_new, zone);
	}
	hattrie_iter_free(it);
	
	return db_new;
}

/*!
 * \brief Schedule deletion of old zones, and free the zone db structure.
 *
 * \note Zone content may be preserved in the new zone database, in this case
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

	knot_zonedb_deep_free(&db_old);

	return KNOT_EOK;
}

/*- public API functions ----------------------------------------------------*/

/*!
 * \brief Update zone database according to configuration.
 */
int zonedb_reload(const conf_t *conf, struct server_t *server)
{
	/* Check parameters */
	if (conf == NULL || server == NULL) {
		return KNOT_EINVAL;
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
	knot_zonedb_t **db_current = &server->zone_db;
	knot_zonedb_t *db_old = rcu_xchg_pointer(db_current, db_new);

	/* Wait for readers to finish reading old zone database. */
	synchronize_rcu();

	/*
	 * Remove all zones present in the new DB from the old DB.
	 * No new thread can access these zones in the old DB, as the
	 * databases are already switched.
	 */
	return remove_old_zonedb(db_new, db_old);
}
