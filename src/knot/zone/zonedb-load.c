/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <unistd.h>
#include <urcu.h>

#include "knot/common/log.h"
#include "knot/conf/module.h"
#include "knot/events/replan.h"
#include "knot/journal/journal_metadata.h"
#include "knot/zone/catalog.h"
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

	if (old_zone == NULL) {
		return false;
	}

	char *zonefile = conf_zonefile(conf, zone_name);
	struct timespec mtime;
	int ret = zonefile_exists(zonefile, &mtime);
	free(zonefile);

	if (ret == KNOT_EOK) {
		return !(old_zone->zonefile.exists &&
		         old_zone->zonefile.mtime.tv_sec == mtime.tv_sec &&
		         old_zone->zonefile.mtime.tv_nsec == mtime.tv_nsec);
	} else {
		return old_zone->zonefile.exists;
	}
}

static zone_t *create_zone_from(const knot_dname_t *name, server_t *server)
{
	zone_t *zone = zone_new(name);
	if (!zone) {
		return NULL;
	}

	zone->journaldb = &server->journaldb;
	zone->kaspdb = &server->kaspdb;
	zone->catalog = &server->catalog;
	zone->catalog_upd = &server->catalog_upd;

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
	zone_set_flag(zone, zone_get_flag(old_zone, ZONE_IS_CATALOG | ZONE_IS_CAT_MEMBER, false));

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

static void zone_purge(conf_t *conf, zone_t *zone, server_t *server)
{
	(void)zone_timers_sweep(&server->timerdb, (sweep_cb)knot_dname_cmp, zone->name);

	conf_val_t sync = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
	if (conf_int(&sync) > -1) {
		char *zonefile = conf_zonefile(conf, zone->name);
		(void)unlink(zonefile);
		free(zonefile);
	}

	(void)journal_scrape_with_md(zone_journal(zone), true);
	if (knot_lmdb_open(zone->kaspdb) == KNOT_EOK) {
		(void)kasp_db_delete_all(zone->kaspdb, zone->name);
	}

	log_zone_notice(zone->name, "zone purged");
}

static zone_contents_t *zone_expire(zone_t *zone)
{
	zone->timers.next_refresh = time(NULL);
	return zone_switch_contents(zone, NULL);
}

static bool check_open_catalog(catalog_t *cat)
{
	if (knot_lmdb_exists(&cat->db)) {
		int ret = catalog_open(cat);
		if (ret != KNOT_EOK) {
			log_error("failed to open existing zone catalog");
		} else {
			return true;
		}
	}
	return false;
}

static zone_t *reuse_member_zone(zone_t *zone, server_t *server, conf_t *conf,
                                 list_t *expired_contents)
{
	if (!zone_get_flag(zone, ZONE_IS_CAT_MEMBER, false)) {
		return NULL;
	}

	catalog_upd_val_t *upd = catalog_update_get(&server->catalog_upd, zone->name, true);
	if (upd != NULL) {
		if (upd->just_reconf) {
			zone_purge(conf, zone, server);
			knot_sem_wait(&zone->cow_lock);
			ptrlist_add(expired_contents, zone_expire(zone), NULL);
			knot_sem_post(&zone->cow_lock);
		} else {
			return NULL; // zone to be removed
		}
	}

	zone_t *newzone = create_zone(conf, zone->name, server, zone);
	if (newzone == NULL) {
		log_zone_error(zone->name, "zone cannot be created");
	} else {
		assert(zone_get_flag(newzone, ZONE_IS_CAT_MEMBER, false));
		conf_activate_modules(conf, server, newzone->name, &newzone->query_modules,
		                      &newzone->query_plan);
	}
	return newzone;
}

// cold start of knot: add unchanged member zone to zonedb
static zone_t *reuse_cold_zone(const knot_dname_t *zname, server_t *server, conf_t *conf)
{
	catalog_upd_val_t *upd = catalog_update_get(&server->catalog_upd, zname, true);
	if (upd != NULL && !upd->just_reconf) {
		return NULL; // zone will be removed immediately
	}

	zone_t *zone = create_zone(conf, zname, server, NULL);
	if (zone == NULL) {
		log_zone_error(zname, "zone cannot be created");
	} else {
		zone_set_flag(zone, ZONE_IS_CAT_MEMBER);
		conf_activate_modules(conf, server, zone->name, &zone->query_modules,
		                      &zone->query_plan);
	}
	return zone;
}

static zone_t *add_member_zone(catalog_upd_val_t *val, knot_zonedb_t *check,
                               server_t *server, conf_t *conf)
{
	if (val->just_reconf) {
		return NULL;
	}

	if (knot_zonedb_find(check, val->member) != NULL) {
		log_zone_warning(val->member, "zone already configured, skipping creation");
		return NULL;
	}

	zone_t *zone = create_zone(conf, val->member, server, NULL);
	if (zone == NULL) {
		log_zone_error(val->member, "zone cannot be created");
		catalog_del2(conf->catalog, val);
	} else {
		zone_set_flag(zone, ZONE_IS_CAT_MEMBER);
		conf_activate_modules(conf, server, zone->name, &zone->query_modules,
		                      &zone->query_plan);
		log_zone_info(val->member, "zone added from catalog");
	}
	return zone;
}

/*!
 * \brief Create new zone database.
 *
 * Zones that should be retained are just added from the old database to the
 * new. New zones are loaded.
 *
 * \param conf              New server configuration.
 * \param server            Server instance.
 * \param expired_contents  Out: ptrlist of zone_contents_t to be deep freed after sync RCU.
 *
 * \return New zone database.
 */
static knot_zonedb_t *create_zonedb(conf_t *conf, server_t *server, list_t *expired_contents)
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

		conf_activate_modules(conf, server, zone->name, &zone->query_modules,
		                      &zone->query_plan);

		knot_zonedb_insert(db_new, zone);
	}

	if (db_old != NULL) {
		knot_zonedb_iter_t *it = knot_zonedb_iter_begin(db_old);
		while (!knot_zonedb_iter_finished(it)) {
			zone_t *newzone = reuse_member_zone(knot_zonedb_iter_val(it),
			                                    server, conf, expired_contents);
			if (newzone != NULL) {
				knot_zonedb_insert(db_new, newzone);
			}
			knot_zonedb_iter_next(it);
		}
		knot_zonedb_iter_free(it);
	} else if (check_open_catalog(&server->catalog)) {
		catalog_foreach(&server->catalog) {
			const knot_dname_t *member = NULL;
			catalog_curval(&server->catalog, &member, NULL, NULL);
			zone_t *zone = reuse_cold_zone(member, server, conf);
			if (zone != NULL) {
				knot_zonedb_insert(db_new, zone);
			}
		}
	}

	catalog_commit_cleanup(&server->catalog);

	catalog_it_t *it = catalog_it_begin(&server->catalog_upd, false);
	int catret = 1;
	if (!catalog_it_finished(it)) {
		catret = catalog_begin(&server->catalog);
	}
	while (!catalog_it_finished(it) && catret == KNOT_EOK) {
		catalog_upd_val_t *val = catalog_it_val(it);
		if (val->just_reconf || knot_zonedb_find(db_new, val->member) == NULL) {
			// ^ warning for existing zone later in add_member_zone()
			catret = catalog_add2(&server->catalog, val);
		}
		catalog_it_next(it);
	}
	catalog_it_free(it);
	if (catret == KNOT_EOK) {
		catret = catalog_commit(&server->catalog);
	}

	it = catalog_it_begin(&server->catalog_upd, false);
	while (!catalog_it_finished(it) && catret == KNOT_EOK) {
		zone_t *zone = add_member_zone(catalog_it_val(it), db_new, server, conf);
		if (zone != NULL) {
			knot_zonedb_insert(db_new, zone);
		}
		catalog_it_next(it);
	}
	catalog_it_free(it);
	if (catret < 0) {
		log_error("failed to process zone catalog (%s)", knot_strerror(catret));
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
 * \param server  Server context.
  */
static void remove_old_zonedb(conf_t *conf, knot_zonedb_t *db_old,
                              server_t *server)
{
	catalog_commit_cleanup(&server->catalog);

	knot_zonedb_t *db_new = server->zone_db;

	bool full = !(conf->io.flags & CONF_IO_FACTIVE) ||
	            (conf->io.flags & CONF_IO_FRLD_ZONES);

	if (db_old == NULL) {
		goto catalog_only;
	}

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

catalog_only:
	; /* Remove deleted cataloged zones from conf. */
	catalog_it_t *cat_it = catalog_it_begin(&server->catalog_upd, true);
	int catret = 1;
	if (!catalog_it_finished(cat_it)) {
		catret = catalog_begin(&server->catalog);
	}
	while (!catalog_it_finished(cat_it)) {
		catalog_upd_val_t *upd = catalog_it_val(cat_it);
		if (!upd->just_reconf) {
			catalog_del(&server->catalog, upd->member);
			zone_t *zone = knot_zonedb_find(db_old, upd->member);
			if (zone != NULL) {
				zone_purge(conf, zone, server);
			}
		}
		catalog_it_next(cat_it);
	}
	catalog_it_free(cat_it);
	if (catret == KNOT_EOK) {
		catret = catalog_commit(&server->catalog);
	}
	if (catret < 0) {
		log_error("failed to process zone catalog (%s)", knot_strerror(catret));
	}

	/* Clear catalog changes. No need to use mutex as this is done from main
	 * thread while all zone events are paused. */
	catalog_update_clear(&server->catalog_upd);

	if (full) {
		knot_zonedb_deep_free(&db_old, false);
	} else {
		knot_zonedb_free(&db_old);
	}
}

void zonedb_reload(conf_t *conf, server_t *server)
{
	if (conf == NULL || server == NULL) {
		return;
	}

	list_t contents_tofree;
	init_list(&contents_tofree);

	/* Insert all required zones to the new zone DB. */
	knot_zonedb_t *db_new = create_zonedb(conf, server, &contents_tofree);
	if (db_new == NULL) {
		log_error("failed to create new zone database");
		return;
	}

	/* Switch the databases. */
	knot_zonedb_t **db_current = &server->zone_db;
	knot_zonedb_t *db_old = rcu_xchg_pointer(db_current, db_new);

	/* Wait for readers to finish reading old zone database. */
	synchronize_rcu();

	ptrlist_free_custom(&contents_tofree, NULL, (ptrlist_free_cb)zone_contents_deep_free);

	/* Remove old zone DB. */
	remove_old_zonedb(conf, db_old, server);
}

int zone_reload_modules(conf_t *conf, server_t *server, const knot_dname_t *zone_name)
{
	zone_t **zone = knot_zonedb_find_ptr(server->zone_db, zone_name);
	if (zone == NULL) {
		return KNOT_ENOENT;
	}
	assert(knot_dname_is_equal((*zone)->name, zone_name));

	zone_events_freeze_blocking(*zone);
	knot_sem_wait(&(*zone)->cow_lock);

	zone_t *newzone = create_zone(conf, zone_name, server, *zone);
	if (newzone == NULL) {
		return KNOT_ENOMEM;
	}
	conf_activate_modules(conf, server, newzone->name, &newzone->query_modules,
	                      &newzone->query_plan);

	zone_t *oldzone = rcu_xchg_pointer(zone, newzone);
	synchronize_rcu();

	assert(newzone->contents == oldzone->contents);
	oldzone->contents = NULL; // contents have been re-used by newzone

	knot_sem_post(&oldzone->cow_lock);
	zone_free(&oldzone);

	return KNOT_EOK;
}
