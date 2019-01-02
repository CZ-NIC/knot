/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <assert.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/module.h"
#include "knot/events/replan.h"
#include "knot/zone/timers.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zone.h"
#include "knot/zone/zonedb-load.h"
#include "knot/zone/zonedb.h"
#include "knot/zone/zonefile.h"
#include "libknot/libknot.h"

static bool zone_file_updated(conf_t *conf, const zone_t *old_zone,
                              const knot_dname_t *zone_name)
{
	assert(conf);
	assert(zone_name);

	char *zonefile = conf_zonefile(conf, zone_name);
	time_t mtime;
	int ret = zonefile_exists(zonefile, &mtime);
	free(zonefile);

	return (ret == KNOT_EOK && old_zone != NULL &&
	        !(old_zone->zonefile.exists && old_zone->zonefile.mtime == mtime));
}

static zone_t *create_zone_from(const knot_dname_t *name, server_t *server)
{
	zone_t *zone = zone_new(name);
	if (!zone) {
		return NULL;
	}

	zone->journaldb = &server->journaldb;
	zone->kaspdb = &server->kaspdb;

	int result = zone_events_setup(zone, server->workers, &server->sched);
	if (result != KNOT_EOK) {
		zone_free(&zone);
		return NULL;
	}

	return zone;
}

/*!
 * \brief Set timer if unset (value is 0).
 */
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

	// replace SOA expire if we have better knowledge
	if (!zone_contents_is_empty(zone->contents)) {
		const knot_rdataset_t *soa = zone_soa(zone);
		zone->timers.soa_expire = knot_soa_expire(soa->rdata);
	}

	// assume now if we don't know when we flushed
	time_set_default(&zone->timers.last_flush, now);

	if (zone_is_slave(conf, zone)) {
		// assume now if we don't know
		time_set_default(&zone->timers.last_refresh, now);
		time_set_default(&zone->timers.next_refresh, now);
	} else {
		// invalidate if we don't have a master
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

	if (zone_file_updated(conf, old_zone, name) && !zone_expired(zone)) {
		replan_load_updated(zone, old_zone);
	} else {
		zone->zonefile = old_zone->zonefile;
		replan_load_current(conf, zone, old_zone);
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

	int ret = zone_timers_read(&server->timerdb, name, &zone->timers);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		log_zone_error(zone->name, "failed to load persistent timers (%s)",
		               knot_strerror(ret));
		zone_free(&zone);
		return NULL;
	}

	timers_sanitize(conf, zone);

	if (zone_expired(zone)) {
		// expired => force bootstrap, no load attempt
		log_zone_info(zone->name, "zone will be bootstrapped");
		assert(zone_is_slave(conf, zone));
		replan_load_bootstrap(conf, zone);
	} else {
		log_zone_info(zone->name, "zone will be loaded");
		replan_load_new(zone); // if load fails, fallback to bootstrap
	}

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

static void mark_changed_zones(knot_zonedb_t *zonedb, trie_t *changed)
{
	if (changed == NULL) {
		return;
	}

	trie_it_t *it = trie_it_begin(changed);
	for (; !trie_it_finished(it); trie_it_next(it)) {
		const knot_dname_t *name =
			(const knot_dname_t *)trie_it_key(it, NULL);

		zone_t *zone = knot_zonedb_find(zonedb, name);
		if (zone != NULL) {
			conf_io_type_t type = (conf_io_type_t)(*trie_it_val(it));
			assert(!(type & CONF_IO_TSET));
			zone->change_type = type;
		}
	}
	trie_it_free(it);
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
	knot_zonedb_t *db_new = knot_zonedb_new();
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

	knot_zonedb_iter_t *it = knot_zonedb_iter_begin(db_old);

	while (!knot_zonedb_iter_finished(it)) {
		zone_t *zone = knot_zonedb_iter_val(it);

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

		knot_zonedb_iter_next(it);
	}

	knot_zonedb_iter_free(it);

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

	/* Switch the databases. */
	knot_zonedb_t **db_current = &server->zone_db;
	knot_zonedb_t *db_old = rcu_xchg_pointer(db_current, db_new);

	/* Wait for readers to finish reading old zone database. */
	synchronize_rcu();

	/* Remove old zone DB. */
	remove_old_zonedb(conf, db_old, db_new);
}
