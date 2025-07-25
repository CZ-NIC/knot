/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <unistd.h>
#include <urcu.h>

#include "knot/catalog/generate.h"
#include "knot/common/log.h"
#include "knot/conf/module.h"
#include "knot/events/replan.h"
#include "knot/journal/journal_metadata.h"
#include "knot/zone/digest.h"
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

static void zone_get_catalog_group(conf_t *conf, zone_t *zone)
{
	conf_val_t val = conf_zone_get(conf, C_CATALOG_GROUP, zone->name);
	if (val.code == KNOT_EOK) {
		zone->catalog_group = conf_str(&val);
	}
}

static zone_t *create_zone_from(const knot_dname_t *name, server_t *server)
{
	zone_t *zone = zone_new(name);
	if (!zone) {
		return NULL;
	}

	zone->server = server;

	int result = zone_events_setup(zone, server->workers, &server->sched);
	if (result != KNOT_EOK) {
		zone_free(&zone);
		return NULL;
	}

	return zone;
}

static void replan_events(conf_t *conf, zone_t *zone, zone_t *old_zone)
{
	bool conf_updated = (old_zone->change_type & CONF_IO_TRELOAD);

	conf_val_t digest = conf_zone_get(conf, C_ZONEMD_GENERATE, zone->name);
	if (zone->contents != NULL && !zone_contents_digest_exists(zone->contents, conf_opt(&digest), true)) {
		conf_updated = true;
	}

	zone->events.ufrozen = old_zone->events.ufrozen;
	if ((zone_file_updated(conf, old_zone, zone->name) || conf_updated) && !zone_expired(zone)) {
		replan_load_updated(zone, old_zone);
	} else {
		zone->zonefile = old_zone->zonefile;
		memcpy(&zone->notifailed, &old_zone->notifailed, sizeof(zone->notifailed));
		memset(&old_zone->notifailed, 0, sizeof(zone->notifailed));
		replan_load_current(conf, zone, old_zone);
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
	zone_set_flag(zone, zone_get_flag(old_zone, ~0, false));

	zone->timers = old_zone->timers;
	zone_timers_sanitize(conf, zone);

	if (old_zone->control_update != NULL) {
		log_zone_warning(old_zone->name, "control transaction aborted");
		zone_control_clear(old_zone);
	}

	zone->cat_members = old_zone->cat_members;
	old_zone->cat_members = NULL;

	zone->catalog_gen = old_zone->catalog_gen;
	old_zone->catalog_gen = NULL;

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
	if (ret != KNOT_EOK && ret != KNOT_ENODB && ret != KNOT_ENOENT) {
		log_zone_error(zone->name, "failed to load persistent timers (%s)",
		               knot_strerror(ret));
		zone_free(&zone);
		return NULL;
	}

	zone_timers_sanitize(conf, zone);

	conf_val_t role_val = conf_zone_get(conf, C_CATALOG_ROLE, name);
	unsigned role = conf_opt(&role_val);
	if (role == CATALOG_ROLE_MEMBER) {
		conf_val_t catz = conf_zone_get(conf, C_CATALOG_ZONE, name);
		assert(catz.code == KNOT_EOK); // conf consistency checked in conf/tools.c
		zone->catalog_gen = knot_dname_copy(conf_dname(&catz), NULL);
		if (zone->timers.catalog_member == 0) {
			zone->timers.catalog_member = time(NULL);
			ret = zone_timers_write(&zone->server->timerdb, zone->name,
			                        &zone->timers);
		}
		if (ret != KNOT_EOK || zone->catalog_gen == NULL) {
			log_zone_error(zone->name, "failed to initialize catalog member zone (%s)",
			               knot_strerror(KNOT_ENOMEM));
			zone_free(&zone);
			return NULL;
		}
	} else if (role == CATALOG_ROLE_GENERATE) {
		zone->cat_members = catalog_update_new();
		if (zone->cat_members == NULL) {
			log_zone_error(zone->name, "failed to initialize catalog zone (%s)",
			               knot_strerror(KNOT_ENOMEM));
			zone_free(&zone);
			return NULL;
		}
		zone_set_flag(zone, ZONE_IS_CATALOG);
	} else if (role == CATALOG_ROLE_INTERPRET) {
		ret = catalog_open(&server->catalog);
		if (ret != KNOT_EOK) {
			log_error("failed to open catalog database (%s)", knot_strerror(ret));
		}
		zone_set_flag(zone, ZONE_IS_CATALOG);
	}

	if (zone_expired(zone)) {
		// expired => force bootstrap, no load attempt
		log_zone_info(zone->name, "zone will be bootstrapped");
		assert(zone_is_slave(conf, zone));
		replan_load_bootstrap(conf, zone);
		zone->started = true;
	} else {
		log_zone_info(zone->name, "zone will be loaded");
		// if load fails, fallback to bootstrap
		replan_load_new(zone, role == CATALOG_ROLE_GENERATE);
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

	zone_t *z;

	if (old_zone) {
		z = create_zone_reload(conf, name, server, old_zone);
	} else {
		z = create_zone_new(conf, name, server);
	}

	if (z != NULL) {
		zone_get_catalog_group(conf, z);
	}

	return z;
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
			conf_io_type_t type = conf_io_trie_val(it);
			assert(!(type & CONF_IO_TSET));
			zone->change_type = type;
		}
	}
	trie_it_free(it);
}

static void zone_purge(conf_t *conf, zone_t *zone)
{
	(void)selective_zone_purge(conf, zone, PURGE_ZONE_ALL);
}

static zone_contents_t *zone_expire(zone_t *zone)
{
	zone->timers.next_expire = time(NULL);
	zone->timers.next_refresh = zone->timers.next_expire;
	return zone_switch_contents(zone, NULL);
}

static bool check_open_catalog(catalog_t *cat)
{
	int ret = knot_lmdb_exists(&cat->db);
	switch (ret) {
	case KNOT_ENODB:
		return false;
	case KNOT_EOK:
		ret = catalog_open(cat);
		if (ret == KNOT_EOK) {
			return true;
		}
		// FALLTHROUGH
	default:
		log_error("failed to open persistent zone catalog");
	}
	return false;
}

static zone_t *reuse_member_zone(zone_t *zone, server_t *server, conf_t *conf,
                                 reload_t mode, list_t *expired_contents)
{
	if (!zone_get_flag(zone, ZONE_IS_CAT_MEMBER, false)) {
		return NULL;
	}

	catalog_upd_val_t *upd = catalog_update_get(&server->catalog_upd, zone->name);
	if (upd != NULL) {
		switch (upd->type) {
		case CAT_UPD_UNIQ:
			zone_purge(conf, zone);
			knot_sem_wait(&zone->cow_lock);
			ptrlist_add(expired_contents, zone_expire(zone), NULL);
			knot_sem_post(&zone->cow_lock);
			// FALLTHROUGH
		case CAT_UPD_PROP:
			zone->change_type = CONF_IO_TRELOAD;
			break; // reload the member zone
		case CAT_UPD_INVALID:
		case CAT_UPD_MINOR:
			if (mode & (RELOAD_COMMIT | RELOAD_CATALOG)) {
				return zone; // reuse the member zone
			} else {
				break; // reload the member zone
			}
		case CAT_UPD_REM:
			return NULL; // remove the member zone
		case CAT_UPD_ADD: // cannot add existing member
		default:
			assert(0);
			return NULL;
		}
	} else if (mode & (RELOAD_COMMIT | RELOAD_CATALOG)) {
		return zone; // reuse the member zone
	}

	zone_t *newzone = create_zone(conf, zone->name, server, zone);
	if (newzone == NULL) {
		log_zone_error(zone->name, "zone cannot be created");
	} else {
		assert(zone_get_flag(newzone, ZONE_IS_CAT_MEMBER, false));
		int ret = conf_activate_modules(conf, server, newzone->name,
		                                &newzone->query_modules,
		                                &newzone->query_plan);
		if (ret != KNOT_EOK) {
			log_zone_error(newzone->name, "zone cannot be activated (%s)",
			               knot_strerror(ret));
			newzone->contents = NULL;
			zone_free(&newzone);
			return NULL;
		}
	}

	return newzone;
}

// cold start of knot: add unchanged member zone to zonedb
static zone_t *reuse_cold_zone(const knot_dname_t *zname, server_t *server, conf_t *conf)
{
	catalog_upd_val_t *upd = catalog_update_get(&server->catalog_upd, zname);
	if (upd != NULL && upd->type == CAT_UPD_REM) {
		return NULL; // zone will be removed immediately
	}

	zone_t *zone = create_zone(conf, zname, server, NULL);
	if (zone == NULL) {
		log_zone_error(zname, "zone cannot be created");
	} else {
		zone_set_flag(zone, ZONE_IS_CAT_MEMBER);
		int ret = conf_activate_modules(conf, server, zone->name,
		                                &zone->query_modules,
		                                &zone->query_plan);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "zone cannot be activated (%s)",
			               knot_strerror(ret));
			zone->contents = NULL;
			zone_free(&zone);
			return NULL;
		}
	}

	return zone;
}

typedef struct {
	knot_zonedb_t *zonedb;
	server_t *server;
	conf_t *conf;
} reuse_cold_zone_ctx_t;

static int reuse_cold_zone_cb(const knot_dname_t *member, _unused_ const knot_dname_t *owner,
                              const knot_dname_t *catz, _unused_ const char *group,
                              void *ctx)
{
	reuse_cold_zone_ctx_t *rcz = ctx;

	zone_t *catz_z = knot_zonedb_find(rcz->zonedb, catz);
	if (catz_z == NULL || !(catz_z->flags & ZONE_IS_CATALOG)) {
		log_zone_warning(member, "orphaned catalog member zone, ignoring");
		return KNOT_EOK;
	}

	zone_t *zone = reuse_cold_zone(member, rcz->server, rcz->conf);
	if (zone == NULL) {
		return KNOT_ENOMEM;
	}
	return knot_zonedb_insert(rcz->zonedb, zone);
}

static zone_t *add_member_zone(catalog_upd_val_t *val, knot_zonedb_t *check,
                               server_t *server, conf_t *conf)
{
	if (val->type != CAT_UPD_ADD) {
		return NULL;
	}

	if (knot_zonedb_find(check, val->member) != NULL) {
		log_zone_error(val->member, "zone already configured, ignoring");
		return NULL;
	}

	zone_t *zone = create_zone(conf, val->member, server, NULL);
	if (zone == NULL) {
		log_zone_error(val->member, "zone cannot be created");
	} else {
		zone_set_flag(zone, ZONE_IS_CAT_MEMBER);
		int ret = conf_activate_modules(conf, server, zone->name,
		                                &zone->query_modules,
		                                &zone->query_plan);
		if (ret != KNOT_EOK) {
			log_zone_error(zone->name, "zone cannot be activated (%s)",
			               knot_strerror(ret));
			zone->contents = NULL;
			zone_free(&zone);
			return NULL;
		}
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
 * \param mode              Reload mode.
 * \param expired_contents  Out: ptrlist of zone_contents_t to be deep freed after sync RCU.
 *
 * \return New zone database.
 */
static knot_zonedb_t *create_zonedb(conf_t *conf, server_t *server, reload_t mode,
                                    list_t *expired_contents)
{
	assert(conf);
	assert(server);

	knot_zonedb_t *db_old = server->zone_db;
	knot_zonedb_t *db_new = knot_zonedb_new();
	if (!db_new) {
		return NULL;
	}

	/* Mark changed zones during dynamic configuration. */
	if (mode == RELOAD_COMMIT) {
		mark_changed_zones(db_old, conf->io.zones);
	}

	/* Process regular zones from the configuration. */
	for (conf_iter_t iter = conf_iter(conf, C_ZONE); iter.code == KNOT_EOK;
	     conf_iter_next(conf, &iter)) {
		conf_val_t id = conf_iter_id(conf, &iter);
		const knot_dname_t *name = conf_dname(&id);

		zone_t *old_zone = knot_zonedb_find(db_old, name);
		if (old_zone != NULL && (mode & (RELOAD_COMMIT | RELOAD_CATALOG))) {
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
		} else {
			int ret = conf_activate_modules(conf, server, zone->name,
			                                &zone->query_modules,
			                                &zone->query_plan);
			if (ret != KNOT_EOK) {
				log_zone_error(zone->name, "zone cannot be activated (%s)",
				               knot_strerror(ret));
				zone->contents = NULL;
				zone_free(&zone);
				continue;
			}
		}

		knot_zonedb_insert(db_new, zone);
	}

	/* Purge decataloged zones before catalog removals are commited. */
	catalog_it_t *cat_it = catalog_it_begin(&server->catalog_upd);
	while (!catalog_it_finished(cat_it)) {
		catalog_upd_val_t *upd = catalog_it_val(cat_it);
		if (upd->type == CAT_UPD_REM) {
			zone_t *zone = knot_zonedb_find(db_old, upd->member);
			if (zone != NULL) {
				zone->change_type = CONF_IO_TUNSET;
				zone_purge(conf, zone);
			}
		}
		catalog_it_next(cat_it);
	}
	catalog_it_free(cat_it);

	int ret = catalog_update_commit(&server->catalog_upd, &server->catalog);
	if (ret != KNOT_EOK) {
		log_error("catalog, failed to apply changes (%s)", knot_strerror(ret));
		return db_new;
	}

	/* Process existing catalog member zones. */
	if (db_old != NULL) {
		knot_zonedb_iter_t *it = knot_zonedb_iter_begin(db_old);
		while (!knot_zonedb_iter_finished(it)) {
			zone_t *newzone = reuse_member_zone(knot_zonedb_iter_val(it),
			                                    server, conf, mode,
			                                    expired_contents);
			if (newzone != NULL) {
				knot_zonedb_insert(db_new, newzone);
			}
			knot_zonedb_iter_next(it);
		}
		knot_zonedb_iter_free(it);
	} else if (check_open_catalog(&server->catalog)) {
		reuse_cold_zone_ctx_t rcz = { db_new, server, conf };
		ret = catalog_apply(&server->catalog, NULL, reuse_cold_zone_cb, &rcz, false);
		if (ret != KNOT_EOK) {
			log_error("catalog, failed to load member zones (%s)", knot_strerror(ret));
		}
	}

	/* Process new catalog member zones. */
	catalog_it_t *it = catalog_it_begin(&server->catalog_upd);
	while (!catalog_it_finished(it)) {
		catalog_upd_val_t *val = catalog_it_val(it);
		zone_t *zone = add_member_zone(val, db_new, server, conf);
		if (zone != NULL) {
			knot_zonedb_insert(db_new, zone);
		}
		catalog_it_next(it);
	}
	catalog_it_free(it);

	it = knot_zonedb_iter_begin(db_new);
	while (!knot_zonedb_iter_finished(it)) {
		zone_t *z = knot_zonedb_iter_val(it);
		conf_val_t val = conf_zone_get(conf, C_REVERSE_GEN, z->name);
		while (val.code == KNOT_EOK) {
			const knot_dname_t *forw_name = conf_dname(&val);
			zone_t *forw = knot_zonedb_find(db_new, forw_name);
			if (forw == NULL) {
				knot_dname_txt_storage_t forw_str;
				(void)knot_dname_to_str(forw_str, forw_name, sizeof(forw_str));
				log_zone_warning(z->name, "zone to reverse %s does not exist",
				                 forw_str);
			} else {
				ptrlist_add(&z->reverse_from, forw, NULL);
				zone_local_notify_subscribe(forw, z);
			}
			conf_val_next(&val);
		}
		knot_zonedb_iter_next(it);
	}
	knot_zonedb_iter_free(it);

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
                              server_t *server, reload_t mode)
{
	catalog_commit_cleanup(&server->catalog);

	knot_zonedb_t *db_new = server->zone_db;

	if (db_old == NULL) {
		goto catalog_only;
	}

	knot_zonedb_iter_t *it = knot_zonedb_iter_begin(db_old);
	while (!knot_zonedb_iter_finished(it)) {
		zone_t *zone = knot_zonedb_iter_val(it);
		if (mode & (RELOAD_FULL | RELOAD_ZONES)) {
			/* Check if reloaded (reused contents). */
			zone_t *new_zone = knot_zonedb_find(db_new, zone->name);
			if (new_zone != NULL) {
				replan_events(conf, new_zone, zone);
				zone->contents = NULL;
			}
			/* Completely new zone. */
		} else {
			/* Check if reloaded (reused contents). */
			if (zone->change_type & CONF_IO_TRELOAD) {
				zone_t *new_zone = knot_zonedb_find(db_new, zone->name);
				assert(new_zone);
				replan_events(conf, new_zone, zone);
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

	/* Clear catalog changes. No need to use mutex as this is done from main
	 * thread while all zone events are paused. */
	catalog_update_clear(&server->catalog_upd);

	if (mode & (RELOAD_FULL | RELOAD_ZONES)) {
		knot_zonedb_deep_free(&db_old, false);
	} else {
		knot_zonedb_free(&db_old);
	}
}

// UBSAN type punning workaround
static void zone_contents_deep_free_wrap(void *contents)
{
	zone_contents_deep_free((zone_contents_t *)contents);
}

void zonedb_reload(conf_t *conf, server_t *server, reload_t mode)
{
	if (conf == NULL || server == NULL) {
		return;
	}

	if (mode == RELOAD_COMMIT) {
		assert(conf->io.flags & CONF_IO_FACTIVE);
		if (conf->io.flags & CONF_IO_FRLD_ZONES) {
			mode = RELOAD_ZONES;
		}
	}

	list_t contents_tofree;
	init_list(&contents_tofree);

	catalog_update_finalize(&server->catalog_upd, &server->catalog, conf);
	size_t cat_upd_size = trie_weight(server->catalog_upd.upd);
	if (cat_upd_size > 0) {
		log_info("catalog, updating, %zu changes", cat_upd_size);
	}

	/* Insert all required zones to the new zone DB. */
	knot_zonedb_t *db_new = create_zonedb(conf, server, mode, &contents_tofree);
	if (db_new == NULL) {
		log_error("failed to create new zone database");
		return;
	}

	catalogs_generate(db_new, server->zone_db);

	/* Switch the databases. */
	knot_zonedb_t **db_current = &server->zone_db;
	knot_zonedb_t *db_old = rcu_xchg_pointer(db_current, db_new);

	/* Wait for readers to finish reading old zone database. */
	synchronize_rcu();

	ptrlist_free_custom(&contents_tofree, NULL, zone_contents_deep_free_wrap);

	/* Remove old zone DB. */
	remove_old_zonedb(conf, db_old, server, mode);
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
		knot_sem_post(&(*zone)->cow_lock);
		return KNOT_ENOMEM;
	}
	knot_sem_wait(&newzone->cow_lock);
	int ret = conf_activate_modules(conf, server, newzone->name,
	                                &newzone->query_modules,
	                                &newzone->query_plan);
	if (ret != KNOT_EOK) {
		log_zone_error(newzone->name, "zone cannot be activated (%s)",
		               knot_strerror(ret));
		knot_sem_post(&newzone->cow_lock);
		knot_sem_post(&(*zone)->cow_lock);
		newzone->contents = NULL;
		zone_free(&newzone);
		return ret;
	}

	zone_t *oldzone = rcu_xchg_pointer(zone, newzone);
	synchronize_rcu();

	replan_events(conf, newzone, oldzone);

	assert(newzone->contents == oldzone->contents);
	oldzone->contents = NULL; // contents have been re-used by newzone

	knot_sem_post(&newzone->cow_lock);
	knot_sem_post(&oldzone->cow_lock);
	zone_free(&oldzone);

	return KNOT_EOK;
}
