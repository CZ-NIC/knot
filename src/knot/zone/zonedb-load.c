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

#include "knot/conf/confio.h"
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
	ZONE_STATUS_BOOTSTRAP,      //!< Zone file does not exist, can bootstrap.
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
			       ZONE_STATUS_BOOTSTRAP : ZONE_STATUS_NOT_FOUND;
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
	case ZONE_STATUS_BOOTSTRAP:     action = "will be bootstrapped"; break;
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

static zone_t *create_zone_reload(conf_t *conf, const knot_dname_t *name,
                                  server_t *server, zone_t *old_zone)
{
	zone_t *zone = create_zone_from(name, server);
	if (!zone) {
		return NULL;
	}
	zone->contents = old_zone->contents;

	zone_status_t zstatus;
	if (zone_is_slave(conf, zone) && old_zone->flags & ZONE_EXPIRED) {
		zone->flags |= ZONE_EXPIRED;
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

static bool slave_event(zone_event_type_t event)
{
	return event == ZONE_EVENT_EXPIRE || event == ZONE_EVENT_REFRESH;
}

static int reuse_events(conf_t *conf, knot_db_t *timer_db, zone_t *zone)
{
	// Get persistent timers

	time_t timers[ZONE_EVENT_COUNT] = { 0 };
	int ret = read_zone_timers(timer_db, zone, timers);
	if (ret != KNOT_EOK) {
		return ret;
	}

	for (zone_event_type_t event = 0; event < ZONE_EVENT_COUNT; ++event) {
		if (timers[event] == 0) {
			// Timer unset.
			continue;
		}
		if (slave_event(event) && !zone_is_slave(conf, zone)) {
			// Slave-only event.
			continue;
		}

		if (event == ZONE_EVENT_EXPIRE && timers[event] <= time(NULL)) {
			zone->flags |= ZONE_EXPIRED;
			continue;
		}

		zone_events_schedule_at(zone, event, timers[event]);
	}

	return KNOT_EOK;
}

static zone_t *create_zone_new(conf_t *conf, const knot_dname_t *name,
                               server_t *server)
{
	zone_t *zone = create_zone_from(name, server);
	if (!zone) {
		return NULL;
	}

	int ret = reuse_events(conf, server->timers_db, zone);
	if (ret != KNOT_EOK) {
		log_zone_error(zone->name, "cannot read zone timers (%s)",
		               knot_strerror(ret));
		zone_free(&zone);
		return NULL;
	}

	zone_status_t zstatus = zone_file_status(conf, NULL, name);
	if (zone->flags & ZONE_EXPIRED) {
		assert(zone_is_slave(conf, zone));
		zstatus = ZONE_STATUS_BOOTSTRAP;
	}

	switch (zstatus) {
	case ZONE_STATUS_FOUND_NEW:
		/* Enqueueing makes the first zone load waitable. */
		zone_events_enqueue(zone, ZONE_EVENT_LOAD);
		break;
	case ZONE_STATUS_BOOTSTRAP:
		if (zone_events_get_time(zone, ZONE_EVENT_XFER) == 0) {
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

static void mark_changed_zones(knot_zonedb_t *zonedb, hattrie_t *changed)
{
	if (changed == NULL) {
		return;
	}

	hattrie_iter_t *it = hattrie_iter_begin(changed);
	for (; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		const knot_dname_t *name =
			(const knot_dname_t *)hattrie_iter_key(it, NULL);

		zone_t *zone = knot_zonedb_find(zonedb, name);
		if (zone != NULL) {
			conf_io_type_t type = (conf_io_type_t)(*hattrie_iter_val(it));
			assert(!(type & CONF_IO_TSET));
			zone->change_type = type;
		}
	}
	hattrie_iter_free(it);
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

	bool full = !(conf->io.flags & CONF_IO_FACTIVE) ||
	            (conf->io.flags & CONF_IO_FRLD_ZONES);

	/* Mark changed zones. */
	if (!full) {
		mark_changed_zones(server->zone_db, conf->io.zones);
	}

	for (conf_iter_t iter = conf_iter(conf, C_ZONE); iter.code == KNOT_EOK;
	     conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		const knot_dname_t *name = conf_dname(&id);

		zone_t *old_zone = knot_zonedb_find(db_old, name);
		if (old_zone != NULL && !full) {
			/* Reuse unchanged zone. */
			if (!(old_zone->change_type & CONF_IO_TRELOAD)) {
				knot_zonedb_insert(db_new, old_zone);
				continue;
			}
		}

		zone_t *zone = create_zone(conf, name, server, old_zone);
		if (zone == NULL) {
			log_zone_error(name, "zone cannot be created");
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
 * \param conf    New server configuration.
 * \param db_old  Old zone database to remove.
 * \param db_new  New zone database for comparison if full reload.
  */
static void remove_old_zonedb(conf_t *conf, knot_zonedb_t *db_old,
                              knot_zonedb_t *db_new)
{
	if (db_old == NULL) {
		return;
	}

	bool full = !(conf->io.flags & CONF_IO_FACTIVE) ||
	            (conf->io.flags & CONF_IO_FRLD_ZONES);

	knot_zonedb_iter_t it;
	knot_zonedb_iter_begin(db_old, &it);

	while (!knot_zonedb_iter_finished(&it)) {
		zone_t *zone = knot_zonedb_iter_val(&it);

		if (full) {
			/* Check if reloaded (reused contents). */
			if (knot_zonedb_find(db_new, zone->name)) {
				zone->contents = NULL;
			}
			/* Completely new zone. */
		} else {
			/* Check if reloaded (reused contents). */
			if (zone->change_type & CONF_IO_TRELOAD) {
				zone->contents = NULL;
				zone_free(&zone);
			/* Check if removed (drop also contents). */
			} else if (zone->change_type & CONF_IO_TUNSET) {
				zone_free(&zone);
			}
			/* Completely reused zone. */
		}

		knot_zonedb_iter_next(&it);
	}

	if (full) {
		knot_zonedb_deep_free(&db_old);
	} else {
		knot_zonedb_free(&db_old);
	}
}

void zonedb_reload(conf_t *conf, server_t *server)
{
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
	sweep_timer_db(server->timers_db, db_new);

	/* Remove old zone DB. */
	remove_old_zonedb(conf, db_old, db_new);
}
