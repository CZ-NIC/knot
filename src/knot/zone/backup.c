/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "contrib/files.h"
#include "knot/zone/backup.h"
#include "knot/catalog/catalog_db.h"
#include "knot/common/log.h"
#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/kasp/keystore.h"
#include "knot/journal/journal_metadata.h"
#include "libdnssec/error.h"
#include "contrib/files.h"
#include "contrib/string.h"

static void _backup_swap(zone_backup_ctx_t *ctx, void **local, void **remote)
{
	if (ctx->restore_mode) {
		void *temp = *local;
		*local = *remote;
		*remote = temp;
	}
}

#define BACKUP_SWAP(ctx, from, to) _backup_swap((ctx), (void **)&(from), (void **)&(to))

#define BACKUP_LOCKFILE(ctx, lockfile_name) \
	size_t _backup_dir_len = strlen((ctx)->backup_dir); \
	char lockfile_name[_backup_dir_len + 22]; \
	sprintf(lockfile_name, "%s/knot.backup.lockfile", (ctx)->backup_dir);

int zone_backup_init(bool restore_mode, const char *backup_dir,
                     size_t kasp_db_size, size_t timer_db_size, size_t journal_db_size,
                     size_t catalog_db_size, zone_backup_ctx_t **out_ctx)
{
	if (backup_dir == NULL || out_ctx == NULL) {
		return KNOT_EINVAL;
	}

	size_t backup_dir_len = strlen(backup_dir) + 1;

	zone_backup_ctx_t *ctx = malloc(sizeof(*ctx) + backup_dir_len);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->restore_mode = restore_mode;
	ctx->backup_global = false;
	ctx->readers = 1;
	ctx->backup_dir = (char *)(ctx + 1);
	memcpy(ctx->backup_dir, backup_dir, backup_dir_len);

	BACKUP_LOCKFILE(ctx, lockfile);
	if (mkdir(backup_dir, S_IRWXU|S_IRWXG) != 0 && errno != EEXIST) {
		free(ctx);
		return knot_map_errno();
	}
	ctx->lock_file = open(lockfile, O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
	if (ctx->lock_file < 0) {
		free(ctx);
		// Make the reported error better understandable than KNOT_EEXIST.
		return errno == EEXIST ? KNOT_EBUSY : knot_map_errno();
	}

	pthread_mutex_init(&ctx->readers_mutex, NULL);

	char db_dir[backup_dir_len + 16];
	(void)snprintf(db_dir, sizeof(db_dir), "%s/keys", backup_dir);
	knot_lmdb_init(&ctx->bck_kasp_db, db_dir, kasp_db_size, 0, "keys_db");

	(void)snprintf(db_dir, sizeof(db_dir), "%s/timers", backup_dir);
	knot_lmdb_init(&ctx->bck_timer_db, db_dir, timer_db_size, 0, NULL);

	(void)snprintf(db_dir, sizeof(db_dir), "%s/journal", backup_dir);
	knot_lmdb_init(&ctx->bck_journal, db_dir, journal_db_size, 0, NULL);

	(void)snprintf(db_dir, sizeof(db_dir), "%s/catalog", backup_dir);
	knot_lmdb_init(&ctx->bck_catalog, db_dir, catalog_db_size, 0, NULL);

	*out_ctx = ctx;
	return KNOT_EOK;
}

void zone_backup_deinit(zone_backup_ctx_t *ctx)
{
	if (ctx == NULL) {
		return;
	}

	pthread_mutex_lock(&ctx->readers_mutex);
	assert(ctx->readers > 0);
	size_t left = --ctx->readers;
	pthread_mutex_unlock(&ctx->readers_mutex);

	if (left == 0) {
		knot_lmdb_deinit(&ctx->bck_catalog);
		knot_lmdb_deinit(&ctx->bck_journal);
		knot_lmdb_deinit(&ctx->bck_timer_db);
		knot_lmdb_deinit(&ctx->bck_kasp_db);
		pthread_mutex_destroy(&ctx->readers_mutex);

		close(ctx->lock_file);
		BACKUP_LOCKFILE(ctx, lockfile);
		unlink(lockfile);

		zone_backups_rem(ctx);

		free(ctx);
	}
}

void zone_backups_init(zone_backup_ctxs_t *ctxs)
{
	init_list(&ctxs->ctxs);
	pthread_mutex_init(&ctxs->mutex, NULL);
}

void zone_backups_deinit(zone_backup_ctxs_t *ctxs)
{
	zone_backup_ctx_t *ctx, *nxt;
	WALK_LIST_DELSAFE(ctx, nxt, ctxs->ctxs) {
		log_warning("backup to '%s' in progress, terminating, will be incomplete",
		            ctx->backup_dir);
		ctx->readers = 1; // ensure full deinit
		zone_backup_deinit(ctx);
	}
	pthread_mutex_destroy(&ctxs->mutex);
}

void zone_backups_add(zone_backup_ctxs_t *ctxs, zone_backup_ctx_t *ctx)
{
	pthread_mutex_lock(&ctxs->mutex);
	add_tail(&ctxs->ctxs, (node_t *)ctx);
	pthread_mutex_unlock(&ctxs->mutex);
}

static zone_backup_ctxs_t *get_ctxs_trick(zone_backup_ctx_t *ctx)
{
	node_t *n = (node_t *)ctx;
	while (n->prev != NULL) {
		n = n->prev;
	}
	return (zone_backup_ctxs_t *)n;
}

void zone_backups_rem(zone_backup_ctx_t *ctx)
{
	zone_backup_ctxs_t *ctxs = get_ctxs_trick(ctx);
	pthread_mutex_lock(&ctxs->mutex);
	rem_node((node_t *)ctx);
	pthread_mutex_unlock(&ctxs->mutex);
}

static char *dir_file(const char *dir_name, const char *file_name)
{
	const char *basename = strrchr(file_name, '/');
	if (basename == NULL) {
		basename = file_name;
	} else {
		basename++;
	}

	return sprintf_alloc("%s/%s", dir_name, basename);
}

static int backup_key(key_params_t *parm, dnssec_keystore_t *from, dnssec_keystore_t *to)
{
	dnssec_key_t *key = NULL;
	int ret = dnssec_key_new(&key);
	if (ret != DNSSEC_EOK) {
		return knot_error_from_libdnssec(ret);
	}
	dnssec_key_set_algorithm(key, parm->algorithm);

	ret = dnssec_keystore_get_private(from, parm->id, key);
	if (ret == DNSSEC_EOK) {
		ret = dnssec_keystore_set_private(to, key);
	}

	dnssec_key_free(key);
	return knot_error_from_libdnssec(ret);
}

static conf_val_t get_zone_policy(conf_t *conf, const knot_dname_t *zone)
{
	conf_val_t policy;

	// Global modules don't use DNSSEC policy so check zone modules only.
	conf_val_t modules = conf_zone_get(conf, C_MODULE, zone);
	while (modules.code == KNOT_EOK) {
		conf_mod_id_t *mod_id = conf_mod_id(&modules);
		if (mod_id != NULL && strcmp(mod_id->name + 1, "mod-onlinesign") == 0) {
			policy = conf_mod_get(conf, C_POLICY, mod_id);
			conf_id_fix_default(&policy);
			conf_free_mod_id(mod_id);
			return policy;
		}
		conf_free_mod_id(mod_id);
		conf_val_next(&modules);
	}

	// Use default policy if none is configured.
	policy = conf_zone_get(conf, C_DNSSEC_POLICY, zone);
	conf_id_fix_default(&policy);
	return policy;
}

#define LOG_FAIL(action) log_zone_warning(zone->name, "%s, %s failed (%s)", ctx->restore_mode ? "restore" : "backup", (action), knot_strerror(ret))

static int backup_keystore(conf_t *conf, zone_t *zone, zone_backup_ctx_t *ctx)
{
	dnssec_keystore_t *from = NULL, *to = NULL;

	conf_val_t policy_id = get_zone_policy(conf, zone->name);

	unsigned backend_type = 0;
	int ret = zone_init_keystore(conf, &policy_id, &from, &backend_type);
	if (ret != KNOT_EOK) {
		LOG_FAIL("keystore init");
		return ret;
	}
	if (backend_type == KEYSTORE_BACKEND_PKCS11) {
		log_zone_warning(zone->name, "private keys from PKCS#11 aren't subject of backup/restore");
		(void)dnssec_keystore_deinit(from);
		return KNOT_EOK;
	}

	char kasp_dir[strlen(ctx->backup_dir) + 6];
	(void)snprintf(kasp_dir, sizeof(kasp_dir), "%s/keys", ctx->backup_dir);
	ret = keystore_load("keys", KEYSTORE_BACKEND_PEM, kasp_dir, &to);
	if (ret != KNOT_EOK) {
		LOG_FAIL("keystore load");
		goto done;
	}

	BACKUP_SWAP(ctx, from, to);

	list_t key_params;
	init_list(&key_params);
	ret = kasp_db_list_keys(zone->kaspdb, zone->name, &key_params);
	ret = (ret == KNOT_ENOENT ? KNOT_EOK : ret);
	if (ret != KNOT_EOK) {
		LOG_FAIL("keystore list");
		goto done;
	}
	ptrnode_t *n;
	WALK_LIST(n, key_params) {
		key_params_t *parm = n->d;
		if (ret == KNOT_EOK && !parm->is_pub_only) {
			ret = backup_key(parm, from, to);
		}
		free_key_params(parm);
	}
	if (ret != KNOT_EOK) {
		LOG_FAIL("key copy");
	}
	ptrlist_deep_free(&key_params, NULL);

done:
	(void)dnssec_keystore_deinit(to);
	(void)dnssec_keystore_deinit(from);
	return ret;
}

int zone_backup(conf_t *conf, zone_t *zone)
{
	zone_backup_ctx_t *ctx = zone->backup_ctx;
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	if (ctx->backup_zonefile) {
		char *local_zf = conf_zonefile(conf, zone->name);
		char *backup_zf = dir_file(ctx->backup_dir, local_zf);

		if (ctx->restore_mode) {
			ret = make_path(local_zf, S_IRWXU | S_IRWXG);
			if (ret == KNOT_EOK) {
				ret = copy_file(local_zf, backup_zf);
			}
		} else {
			conf_val_t val = conf_zone_get(conf, C_ZONEFILE_SYNC, zone->name);
			bool can_flush = (conf_int(&val) > -1);

			if (can_flush) {
				if (zone->contents != NULL) {
					ret = zone_dump_to_dir(conf, zone, ctx->backup_dir);
				} else {
					log_zone_notice(zone->name, "empty zone, skipping zone file backup");
				}
			} else {
				ret = copy_file(backup_zf, local_zf);
			}
		}

		free(backup_zf);
		free(local_zf);
		if (ret != KNOT_EOK) {
			LOG_FAIL("zone file");
			goto done;
		}
	}

	knot_lmdb_db_t *kasp_from = zone->kaspdb, *kasp_to = &ctx->bck_kasp_db;
	BACKUP_SWAP(ctx, kasp_from, kasp_to);

	if (knot_lmdb_exists(kasp_from)) {
		ret = kasp_db_backup(zone->name, kasp_from, kasp_to);
		if (ret != KNOT_EOK) {
			LOG_FAIL("KASP database");
			goto done;
		}

		ret = backup_keystore(conf, zone, ctx);
		if (ret != KNOT_EOK) {
			goto done;
		}
	}

	if (ctx->backup_journal) {
		knot_lmdb_db_t *j_from = zone->journaldb, *j_to = &ctx->bck_journal;
		BACKUP_SWAP(ctx, j_from, j_to);

		ret = journal_copy_with_md(j_from, j_to, zone->name);
	} else if (ctx->restore_mode) {
		ret = journal_scrape_with_md(zone_journal(zone), true);
	}
	if (ret != KNOT_EOK) {
		LOG_FAIL("journal");
		goto done;
	}

	ret = knot_lmdb_open(&ctx->bck_timer_db);
	if (ret != KNOT_EOK) {
		LOG_FAIL("timers open");
		goto done;
	}
	if (ctx->restore_mode) {
		ret = zone_timers_read(&ctx->bck_timer_db, zone->name, &zone->timers);
		zone_timers_sanitize(conf, zone);
	} else {
		ret = zone_timers_write(&ctx->bck_timer_db, zone->name, &zone->timers);
	}
	if (ret != KNOT_EOK) {
		LOG_FAIL("timers");
	}

done:
	zone_backup_deinit(ctx);
	zone->backup_ctx = NULL;
	return ret;
}

int global_backup(zone_backup_ctx_t *ctx, catalog_t *catalog,
                  const knot_dname_t *zone_only)
{
	knot_lmdb_db_t *cat_from = &catalog->db, *cat_to = &ctx->bck_catalog;
	BACKUP_SWAP(ctx, cat_from, cat_to);
	return catalog_copy(cat_from, cat_to, zone_only, !ctx->restore_mode);
}
