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
#include <urcu.h>

#include "knot/zone/zonedb-load.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zonedb.h"
#include "knot/zone/timers.h"
#include "knot/common/log.h"
#include "libknot/libknot.h"

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
 * \param conf      Zone configuration.
 * \param old_zone  Previous instance of the zone (can be NULL).
 *
 * \return Zone status.
 */
static zone_status_t zone_file_status(conf_t *conf, const zone_t *old_zone,
                                      const knot_dname_t *name)
{
	assert(conf);
	assert(name);

	char *zonefile = conf_zonefile(conf, name);
	time_t mtime;
	int ret = zonefile_exists(zonefile, &mtime);
	free(zonefile);

	// Zone file does not exist.
	if (ret != KNOT_EOK) {
		if (old_zone) {
			// Deferred flush.
			return ZONE_STATUS_FOUND_CURRENT;
		} else {
			return zone_load_can_bootstrap(conf, name) ?
			       ZONE_STATUS_BOOSTRAP : ZONE_STATUS_NOT_FOUND;
		}
	} else {
		if (old_zone == NULL) {
			return ZONE_STATUS_FOUND_NEW;
		} else if (old_zone->zonefile.exists && old_zone->zonefile.mtime == mtime) {
			return ZONE_STATUS_FOUND_CURRENT;
		} else {
			return ZONE_STATUS_FOUND_UPDATED;
		}
	}
}

/*!
 * \brief Log message about loaded zone (name and status).
 *
 * \param zone    Zone structure.
 * \param status  Zone file status.
 */
static void log_zone_load_info(const zone_t *zone, zone_status_t status)
{
	assert(zone);

	const char *action = NULL;

	switch (status) {
	case ZONE_STATUS_NOT_FOUND:     action = "not found";            break;
	case ZONE_STATUS_BOOSTRAP:      action = "will be bootstrapped"; break;
	case ZONE_STATUS_FOUND_NEW:     action = "will be loaded";       break;
	case ZONE_STATUS_FOUND_CURRENT: action = "is up-to-date";        break;
	case ZONE_STATUS_FOUND_UPDATED: action = "will be reloaded";     break;
	}
	assert(action);

	if (zone->contents && zone->contents->apex) {
		const knot_rdataset_t *soa = node_rdataset(zone->contents->apex,
		                                           KNOT_RRTYPE_SOA);
		uint32_t serial = knot_soa_serial(soa);
		log_zone_info(zone->name, "zone %s, serial %u", action, serial);
	} else {
		log_zone_info(zone->name, "zone %s", action);
	}
}

static zone_t *create_zone_from(const knot_dname_t *name, server_t *server)
{
	zone_t *zone = zone_new(name);
	if (!zone) {
		return NULL;
	}

	int result = zone_events_setup(zone, server->workers, &server->sched,
	                               server->timers_db);
	if (result != KNOT_EOK) {
		zone_free(&zone);
		return NULL;
	}

	return zone;
}

static void time_set_default(time_t *time, time_t value)
{
	assert(time);

	if (*time == 0) {
		*time = value;
	}
}

/*!
 * \brief Set default timers for new zones or invalidate if not valid.
 */
static void timers_sanitize(conf_t *conf, zone_t *zone)
{
	assert(conf);
	assert(zone);

	time_t now = time(NULL);

	// soa_expire always intact

	time_set_default(&zone->timers.last_flush, now);

	if (zone_is_slave(conf, zone)) {
		time_set_default(&zone->timers.last_refresh, now);
		time_set_default(&zone->timers.next_refresh, now);
	} else {
		zone->timers.last_refresh = 0;
		zone->timers.next_refresh = 0;
	}
}

static zone_t *create_zone_reload(conf_t *conf, const knot_dname_t *name,
                                  server_t *server, zone_t *old_zone)
{
	zone_t *zone = create_zone_from(name, server);
	if (!zone) {
		return NULL;
	}

	zone->contents = old_zone->contents;

	zone->timers = old_zone->timers;
	timers_sanitize(conf, zone);

	zone_status_t zstatus;
	if (zone_expired(zone)) {
		zstatus = ZONE_STATUS_FOUND_CURRENT;
	} else {
		zstatus = zone_file_status(conf, old_zone, name);
	}

	switch (zstatus) {
	case ZONE_STATUS_FOUND_UPDATED:
		/* Enqueueing makes the first zone load waitable. */
		zone_events_enqueue(zone, ZONE_EVENT_LOAD);
		/* Replan DDNS processing if there are pending updates. */
		zone_events_replan_ddns(zone, old_zone);
		break;
	case ZONE_STATUS_FOUND_CURRENT:
		zone->zonefile = old_zone->zonefile;
		/* Reuse events from old zone. */
		zone_events_update(conf, zone, old_zone);
		break;
	default:
		assert(0);
	}

	if (old_zone->control_update != NULL) {
		log_zone_warning(old_zone->name, "control transaction aborted");
		zone_control_clear(old_zone);
	}

	return zone;
}

static zone_t *create_zone_new(conf_t *conf, const knot_dname_t *name,
                               server_t *server)
{
	zone_t *zone = create_zone_from(name, server);
	if (!zone) {
		return NULL;
	}

	int ret = zone_timers_read(server->timers_db, name, &zone->timers);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		log_zone_error(zone->name, "failed to load persistent timers (%s)",
		               knot_strerror(ret));
		zone_free(&zone);
		return NULL;
	}

	timers_sanitize(conf, zone);

	zone_status_t zstatus = zone_file_status(conf, NULL, name);
	if (zone_expired(zone)) {
		assert(zone_is_slave(conf, zone));
		zstatus = ZONE_STATUS_BOOSTRAP;
	}

	switch (zstatus) {
	case ZONE_STATUS_FOUND_NEW:
		/* Enqueueing makes the first zone load waitable. */
		zone_events_enqueue(zone, ZONE_EVENT_LOAD);
		break;
	case ZONE_STATUS_BOOSTRAP:
		if (zone_events_get_time(zone, ZONE_EVENT_REFRESH) == 0) {
			// Plan immediate refresh if not already planned.
			zone_events_schedule(zone, ZONE_EVENT_REFRESH, ZONE_EVENT_NOW);
		}
		break;
	case ZONE_STATUS_NOT_FOUND:
		break;
	default:
		assert(0);
	}

	log_zone_load_info(zone, zstatus);

	return zone;
}

/*!
 * \brief Load or reload the zone.
 *
 * \param conf       Configuration.
 * \param server     Server.
 * \param old_zone   Already loaded zone (can be NULL).
 *
 * \return Error code, KNOT_EOK if successful.
 */
static zone_t *create_zone(conf_t *conf, const knot_dname_t *name, server_t *server,
                           zone_t *old_zone)
{
	assert(conf);
	assert(name);
	assert(server);

	if (old_zone) {
		return create_zone_reload(conf, name, server, old_zone);
	} else {
		return create_zone_new(conf, name, server);
	}
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
static knot_zonedb_t *create_zonedb(conf_t *conf, server_t *server)
{
	assert(conf);
	assert(server);

	knot_zonedb_t *db_old = server->zone_db;
	knot_zonedb_t *db_new = knot_zonedb_new(conf_id_count(conf, C_ZONE));
	if (!db_new) {
		return NULL;
	}

	for (conf_iter_t iter = conf_iter(conf, C_ZONE); iter.code == KNOT_EOK;
	     conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		zone_t *old_zone = knot_zonedb_find(db_old, conf_dname(&id));
		zone_t *zone = create_zone(conf, conf_dname(&id), server, old_zone);
		if (!zone) {
			log_zone_error(id.data, "zone cannot be created");
			continue;
		}

		conf_activate_modules(conf, zone->name, &zone->query_modules,
		                      &zone->query_plan);

		knot_zonedb_insert(db_new, zone);
	}

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
static void remove_old_zonedb(const knot_zonedb_t *db_new, knot_zonedb_t *db_old)
{
	if (db_old == NULL) {
		return;
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
}

static bool zone_exists(const knot_dname_t *zone, void *data)
{
	assert(zone);
	assert(data);

	knot_zonedb_t *db = data;

	return knot_zonedb_find(db, zone) != NULL;
}

void zonedb_reload(conf_t *conf, server_t *server)
{
	/* Check parameters */
	if (conf == NULL || server == NULL) {
		return;
	}

	/* Insert all required zones to the new zone DB. */
	knot_zonedb_t *db_new = create_zonedb(conf, server);
	if (db_new == NULL) {
		log_error("failed to create new zone database");
		return;
	}

	/* Rebuild zone database search stack. */
	knot_zonedb_build_index(db_new);

	/* Switch the databases. */
	knot_zonedb_t **db_current = &server->zone_db;
	knot_zonedb_t *db_old = rcu_xchg_pointer(db_current, db_new);

	/* Wait for readers to finish reading old zone database. */
	synchronize_rcu();

	/* Sweep the timer database. */
	int ret = zone_timers_sweep(server->timers_db, zone_exists, db_new);
	if (ret != KNOT_EOK) {
		log_warning("failed to clear persistent timers for removed zones (%s)",
		            knot_strerror(ret));
	}

	/*
	 * Remove all zones present in the new DB from the old DB.
	 * No new thread can access these zones in the old DB, as the
	 * databases are already switched.
	 */
	remove_old_zonedb(db_new, db_old);
}
