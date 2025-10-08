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
	bool conf_updated = false;
	conf_val_t digest = conf_zone_get(conf, C_ZONEMD_GENERATE, zone->name);
	if (zone->contents != NULL && !zone_contents_digest_exists(zone->contents, conf_opt(&digest), true)) {
		conf_updated = true;
	}

	zone->events.ufrozen = old_zone->events.ufrozen;
	if ((zone_file_updated(conf, old_zone, zone->name) || conf_updated) && !zone_expired(zone)) {
		zone_notifailed_clear(zone);
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

static void zone_purge(conf_t *conf, zone_t *zone)
{
	(void)selective_zone_purge(conf, zone, PURGE_ZONE_ALL);
}

static zone_contents_t *zone_expire(zone_t *zone, bool zonedb_cow)
{
	if (!zonedb_cow) {
		zone->timers.next_expire = time(NULL);
		zone->timers.next_refresh = zone->timers.next_expire;
	}
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
                                 list_t *expired_contents)
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
			ptrlist_add(expired_contents, zone_expire(zone, false), NULL);
			knot_sem_post(&zone->cow_lock);
			// FALLTHROUGH
		case CAT_UPD_PROP:
		case CAT_UPD_MINOR:
		case CAT_UPD_INVALID:
			break; // reload the member zone
		case CAT_UPD_ADD:
			assert(0); // cannot add existing member
			// FALLTHROUGH
		case CAT_UPD_REM:
		default:
			return NULL; // remove the member zone
		}
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

static zone_t *add_member_zone(catalog_upd_val_t *val, knot_zonedb_t *db_new,
                               server_t *server, conf_t *conf)
{
	if (val->type != CAT_UPD_ADD) {
		return NULL;
	}

	if (knot_zonedb_find(db_new, val->member) != NULL) {
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

static void reg_reverse(conf_t *conf, knot_zonedb_t *db_new, zone_t *zone)
{
	if (zone == NULL) {
		return;
	}

	zone_include_t *n;
	WALK_LIST(n, zone->include_from) {
		zone_local_notify_unsubscribe(n->include, zone);
	}
	zone_includes_clear(zone);

	zone_include_method_t method = ZONE_INCLUDE_REVERSE;
	conf_val_t val = conf_zone_get(conf, C_REVERSE_GEN, zone->name);
	if (val.code != KNOT_EOK) {
		method = ZONE_INCLUDE_FLATTEN;
		val = conf_zone_get(conf, C_INCLUDE_FROM, zone->name);
	}
	while (val.code == KNOT_EOK) {
		const knot_dname_t *forw_name = conf_dname(&val);
		zone_t *forw = knot_zonedb_find(db_new, forw_name);
		if (forw == NULL) {
			knot_dname_txt_storage_t forw_str;
			(void)knot_dname_to_str(forw_str, forw_name, sizeof(forw_str));
			log_zone_warning(zone->name, "zone to reverse %s does not exist",
			                 forw_str);
		} else {
			(void)zone_includes_add(zone, forw, method);
			zone_local_notify_subscribe(forw, zone);
		}
		conf_val_next(&val);
	}
}

static void unreg_reverse(zone_t *zone)
{
	if (zone == NULL) {
		return;
	}

	zone_include_t *in;
	WALK_LIST(in, zone->include_from) {
		zone_local_notify_unsubscribe(in->include, zone);
	}
	zone_includes_clear(zone);

	ptrnode_t *n;
	WALK_LIST(n, zone->internal_notify) {
		zone_t *reverse = n->d;
		zone_includes_rem(reverse, zone);
	}
	ptrlist_free(&zone->internal_notify, NULL);
}

static bool same_group(zone_t *old_z, zone_t *new_z)
{
	if (old_z == NULL || new_z == NULL) {
		return false;
	}

	if (old_z->catalog_group == NULL || new_z->catalog_group == NULL) {
		return (old_z->catalog_group == new_z->catalog_group);
	} else {
		return (strcmp(old_z->catalog_group, new_z->catalog_group) == 0);
	}
}

static zone_t *get_zone(conf_t *conf, const knot_dname_t *name, server_t *server,
                        zone_t *old_zone)
{
	zone_t *zone = create_zone(conf, name, server, old_zone);
	if (zone == NULL) {
		log_zone_error(name, "zone cannot be created");
		return NULL;
	} else {
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

static knot_zonedb_t *create_zonedb_commit(conf_t *conf, server_t *server)
{
	knot_zonedb_t *db_old = server->zone_db; // If NULL, zonedb is beeing initialized.
	knot_zonedb_t *db_new = (db_old != NULL) ? knot_zonedb_cow(db_old) : knot_zonedb_new();
	if (db_new == NULL) {
		return NULL;
	}

	if (conf->io.zones != NULL) {
		trie_it_t *trie_it = trie_it_begin(conf->io.zones);
		for (; !trie_it_finished(trie_it); trie_it_next(trie_it)) {
			const knot_dname_t *name = (const knot_dname_t *)trie_it_key(trie_it, NULL);
			conf_io_type_t type = conf_io_trie_val(trie_it);
			if (type & CONF_IO_TSET) {
				zone_t *zone = get_zone(conf, name, server, NULL);
				if (zone == NULL) {
					continue;
				}
				knot_zonedb_insert(db_new, zone);
				catalog_generate_add(conf, zone, db_new, false);
				reg_reverse(conf, db_new, zone);
			} else if (type & CONF_IO_TUNSET) {
				zone_t *zone = knot_zonedb_find(db_new, name);
				unreg_reverse(zone);
				knot_zonedb_del(db_new, name);
				catalog_generate_rem(conf, zone, db_new);
			} else {
				zone_t *zone = knot_zonedb_find(db_new, name);
				zone_t *old = knot_zonedb_find(db_old, name);
				if (!same_group(old, zone)) {
					catalog_generate_add(conf, zone, db_new, true);
				}
				reg_reverse(conf, db_new, zone);
			}
		}
		trie_it_free(trie_it);
	}

	return db_new;
}

static knot_zonedb_t *create_zonedb_catalog(conf_t *conf, server_t *server,
                                            list_t *expired_contents)
{
	knot_zonedb_t *db_old = server->zone_db;
	assert(db_old); // At least a catalog zone must be present.
	knot_zonedb_t *db_new = knot_zonedb_cow(db_old);
	if (db_new == NULL) {
		return NULL;
	}

	/* Purge decataloged zones before commit - when configuration is available. */
	catalog_it_t *cat_it = catalog_it_begin(&server->catalog_upd);
	for (; !catalog_it_finished(cat_it); catalog_it_next(cat_it)) {
		catalog_upd_val_t *upd = catalog_it_val(cat_it);
		if (upd->type == CAT_UPD_REM) {
			zone_t *zone = knot_zonedb_find(db_old, upd->member);
			if (zone != NULL) {
				zone_purge(conf, zone);
			}
		}
	}
	catalog_it_free(cat_it);

	int ret = catalog_update_commit(&server->catalog_upd, &server->catalog);
	if (ret != KNOT_EOK) {
		log_error("catalog, failed to apply changes (%s)", knot_strerror(ret));
		return db_new;
	}

	/* Process the catalog update. */
	cat_it = catalog_it_begin(&server->catalog_upd);
	for (; !catalog_it_finished(cat_it); catalog_it_next(cat_it)) {
		catalog_upd_val_t *upd = catalog_it_val(cat_it);
		zone_t *zone = NULL;
		switch (upd->type) {
		case CAT_UPD_ADD:
			zone = add_member_zone(upd, db_new, server, conf);
			knot_zonedb_insert(db_new, zone);
			catalog_generate_add(conf, zone, db_new, false);
			reg_reverse(conf, db_new, zone);
			break;
		case CAT_UPD_REM:
			zone = knot_zonedb_find(db_new, upd->member);
			unreg_reverse(zone);
			knot_zonedb_del(db_new, upd->member);
			catalog_generate_rem(conf, zone, db_new);
			break;
		case CAT_UPD_UNIQ:
		case CAT_UPD_PROP:
			zone = knot_zonedb_find(db_new, upd->member);
			if (upd->type == CAT_UPD_UNIQ && zone != NULL) {
				zone_purge(conf, zone);
				knot_sem_wait(&zone->cow_lock);
				ptrlist_add(expired_contents, zone_expire(zone, true), NULL);
				knot_sem_post(&zone->cow_lock);
			}
			zone_t *old = knot_zonedb_find(db_old, upd->member);
			if (!same_group(old, zone)) {
				catalog_generate_add(conf, zone, db_new, true);
			}
			reg_reverse(conf, db_new, zone);
			break;
		default:
			break;
		}
	}
	catalog_it_free(cat_it);

	return db_new;
}

static knot_zonedb_t *create_zonedb_full(conf_t *conf, server_t *server,
                                         list_t *expired_contents)
{
	knot_zonedb_t *db_old = server->zone_db;
	knot_zonedb_t *db_new = knot_zonedb_new();
	if (db_new == NULL) {
		return NULL;
	}

	for (conf_iter_t it = conf_iter(conf, C_ZONE); it.code == KNOT_EOK;
	     conf_iter_next(conf, &it)) {
		conf_val_t id = conf_iter_id(conf, &it);
		const knot_dname_t *name = conf_dname(&id);
		zone_t *old_zone = knot_zonedb_find(db_old, name);
		zone_t *zone = get_zone(conf, name, server, old_zone);
		if (zone == NULL) {
			continue;
		}
		knot_zonedb_insert(db_new, zone);
	}

	/* Purge decataloged zones before commit - when configuration is available. */
	catalog_it_t *cat_it = catalog_it_begin(&server->catalog_upd);
	for (; !catalog_it_finished(cat_it); catalog_it_next(cat_it)) {
		catalog_upd_val_t *upd = catalog_it_val(cat_it);
		if (upd->type == CAT_UPD_REM) {
			zone_t *zone = knot_zonedb_find(db_old, upd->member);
			if (zone != NULL) {
				zone_purge(conf, zone);
			}
		}
	}
	catalog_it_free(cat_it);

	int ret = catalog_update_commit(&server->catalog_upd, &server->catalog);
	if (ret != KNOT_EOK) {
		log_error("catalog, failed to apply changes (%s)", knot_strerror(ret));
		return db_new;
	}

	/* Process existing catalog member zones. */
	if (db_old != NULL) {
		knot_zonedb_iter_t *db_it = knot_zonedb_iter_begin(db_old);
		for (; !knot_zonedb_iter_finished(db_it); knot_zonedb_iter_next(db_it)) {
			zone_t *newzone = reuse_member_zone(knot_zonedb_iter_val(db_it),
			                                    server, conf, expired_contents);
			if (newzone != NULL) {
				knot_zonedb_insert(db_new, newzone);
			}
		}
		knot_zonedb_iter_free(db_it);
	} else if (check_open_catalog(&server->catalog)) {
		reuse_cold_zone_ctx_t rcz = { db_new, server, conf };
		ret = catalog_apply(&server->catalog, NULL, reuse_cold_zone_cb, &rcz, false);
		if (ret != KNOT_EOK) {
			log_error("catalog, failed to load member zones (%s)", knot_strerror(ret));
		}
	}

	/* Process new catalog member zones. */
	cat_it = catalog_it_begin(&server->catalog_upd);
	for (; !catalog_it_finished(cat_it); catalog_it_next(cat_it)) {
		catalog_upd_val_t *val = catalog_it_val(cat_it);
		zone_t *zone = add_member_zone(val, db_new, server, conf);
		if (zone != NULL) {
			knot_zonedb_insert(db_new, zone);
		}
	}
	catalog_it_free(cat_it);

	/* Update generated catalogs - remove members. */
	if (db_old != NULL) {
		knot_zonedb_iter_t *db_it = knot_zonedb_iter_begin(db_old);
		for (; !knot_zonedb_iter_finished(db_it); knot_zonedb_iter_next(db_it)) {
			zone_t *zone = knot_zonedb_iter_val(db_it);
			if (knot_zonedb_find(db_new, zone->name) == NULL) {
				catalog_generate_rem(conf, zone, db_new);
			}
		}
		knot_zonedb_iter_free(db_it);
	}

	/* Update generated catalogs - add members, updated reversed zones. */
	knot_zonedb_iter_t *db_it = knot_zonedb_iter_begin(db_new);
	for (; !knot_zonedb_iter_finished(db_it); knot_zonedb_iter_next(db_it)) {
		zone_t *zone = knot_zonedb_iter_val(db_it);
		zone_t *old = knot_zonedb_find(db_old, zone->name);
		if (old == NULL) {
			catalog_generate_add(conf, zone, db_new, false);
		} else if (!same_group(old, zone)) {
			catalog_generate_add(conf, zone, db_new, true);
		}
		reg_reverse(conf, db_new, zone);
	}
	knot_zonedb_iter_free(db_it);

	return db_new;
}

/*!
 * \brief Create new zone database.
 *
 * Zones that should be retained are just added from the old database to the new
 * one or directly reused if incremental update. New zones are loaded.
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
	switch (mode) {
	case RELOAD_COMMIT:
		return create_zonedb_commit(conf, server);
	case RELOAD_CATALOG:
		return create_zonedb_catalog(conf, server, expired_contents);
	default:
		return create_zonedb_full(conf, server, expired_contents);
	}
}

static void remove_old_zonedb_commit(conf_t *conf, knot_zonedb_t *db_old, server_t *server)
{
	knot_zonedb_t *db_new = server->zone_db;

	assert(conf->io.flags & CONF_IO_FACTIVE);
	bool reload_zones = conf->io.flags & CONF_IO_FRLD_ZONES;

	if (conf->io.zones != NULL) {
		trie_it_t *trie_it = trie_it_begin(conf->io.zones);
		for (; !trie_it_finished(trie_it); trie_it_next(trie_it)) {
			const knot_dname_t *name = (const knot_dname_t *)trie_it_key(trie_it, NULL);
			conf_io_type_t type = conf_io_trie_val(trie_it);
			if (type & CONF_IO_TUNSET) {
				zone_t *zone = knot_zonedb_find(db_old, name);
				zone_free(&zone);
			} else if (!reload_zones && (type & CONF_IO_TRELOAD)) {
				int ret = zone_reload_modules(conf, server, name);
				if (ret != KNOT_EOK) {
					log_zone_error(name, "failed to reload modules (%s)",
					               knot_strerror(ret));
				}
				zone_t *zone = knot_zonedb_find(db_new, name);
				zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
			}
		}
		trie_it_free(trie_it);
	}

	if (reload_zones) {
		knot_zonedb_iter_t *db_it = knot_zonedb_iter_begin(db_new);
		for (; !knot_zonedb_iter_finished(db_it); knot_zonedb_iter_next(db_it)) {
			knot_dname_storage_t name;
			if (knot_dname_store(name, ((zone_t *)knot_zonedb_iter_val(db_it))->name) == 0) {
				continue;
			}
			int ret = zone_reload_modules(conf, server, name);
			if (ret != KNOT_EOK) {
				log_zone_error(name, "failed to reload modules (%s)",
				               knot_strerror(ret));
			}
			zone_t *zone = knot_zonedb_find(db_new, name);
			zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
		}
		knot_zonedb_iter_free(db_it);
	}

	trie_cow_commit(db_new->cow, NULL, NULL);
	db_new->cow = NULL;

	if (db_old != NULL && db_old->cow != NULL) {
		free(db_old);
	}
}

static void remove_old_zonedb_catalog(conf_t *conf, knot_zonedb_t *db_old, server_t *server)
{
	assert(db_old);
	knot_zonedb_t *db_new = server->zone_db;

	catalog_commit_cleanup(&server->catalog);

	catalog_it_t *cat_it = catalog_it_begin(&server->catalog_upd);
	for (; !catalog_it_finished(cat_it); catalog_it_next(cat_it)) {
		catalog_upd_val_t *upd = catalog_it_val(cat_it);
		zone_t *zone = NULL;
		switch (upd->type) {
		case CAT_UPD_REM:
			zone = knot_zonedb_find(db_old, upd->member);
			zone_free(&zone);
			break;
		case CAT_UPD_UNIQ:
		case CAT_UPD_PROP:
			; int ret = zone_reload_modules(conf, server, upd->member);
			if (ret != KNOT_EOK) {
				log_zone_error(upd->member, "failed to reload modules (%s)",
				               knot_strerror(ret));
			}
			zone = knot_zonedb_find(db_new, upd->member);
			zone_events_schedule_now(zone, ZONE_EVENT_LOAD);
			break;
		default:
			break;
		}
	}
	catalog_it_free(cat_it);

	/* Clear catalog changes. No need to use mutex as this is done from main
	 * thread while all zone events are paused. */
	catalog_update_clear(&server->catalog_upd);

	trie_cow_commit(db_new->cow, NULL, NULL);
	db_new->cow = NULL;

	free(db_old);
}

static void remove_old_zonedb_full(conf_t *conf, knot_zonedb_t *db_old, server_t *server)
{
	knot_zonedb_t *db_new = server->zone_db;

	catalog_commit_cleanup(&server->catalog);

	if (db_old != NULL) {
		knot_zonedb_iter_t *db_it = knot_zonedb_iter_begin(db_old);
		for (; !knot_zonedb_iter_finished(db_it); knot_zonedb_iter_next(db_it)) {
			zone_t *zone = knot_zonedb_iter_val(db_it);
			zone_t *new_zone = knot_zonedb_find(db_new, zone->name);
			if (new_zone != NULL) {
				/* Reload reused zone. */
				replan_events(conf, new_zone, zone);
				zone->contents = NULL;
			}
		}
		knot_zonedb_iter_free(db_it);
	}

	/* Clear catalog changes. No need to use mutex as this is done from main
	 * thread while all zone events are paused. */
	catalog_update_clear(&server->catalog_upd);

	knot_zonedb_deep_free(&db_old, false);
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
 * \param mode    Reload mode.
  */
static void remove_old_zonedb(conf_t *conf, knot_zonedb_t *db_old,
                              server_t *server, reload_t mode)
{
	switch (mode) {
	case RELOAD_COMMIT:
		remove_old_zonedb_commit(conf, db_old, server);
		break;
	case RELOAD_CATALOG:
		remove_old_zonedb_catalog(conf, db_old, server);
		break;
	default:
		remove_old_zonedb_full(conf, db_old, server);
		break;
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

	list_t contents_tofree;
	init_list(&contents_tofree);

	if (mode != RELOAD_COMMIT) {
		catalog_update_finalize(&server->catalog_upd, &server->catalog, conf);
		size_t cat_upd_size = trie_weight(server->catalog_upd.upd);
		if (cat_upd_size > 0) {
			log_info("catalog, updating, %zu changes", cat_upd_size);
		}
	}

	/* Insert all required zones to the new zone DB. */
	knot_zonedb_t *db_new = create_zonedb(conf, server, mode, &contents_tofree);
	if (db_new == NULL) {
		log_error("failed to create new zone database");
		return;
	}

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
