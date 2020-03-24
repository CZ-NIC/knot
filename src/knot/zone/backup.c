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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/stat.h>

#include "knot/zone/backup.h"

#include "knot/dnssec/kasp/kasp_zone.h"
#include "knot/dnssec/kasp/keystore.h"

static inline void _backup_swap(zone_backup_ctx_t *ctx, void **local, void **remote)
{
	if (ctx->restore_mode) {
		void *temp = *local;
		*local = *remote;
		*remote = temp;
	}
}

#define BACKUP_SWAP(ctx, from, to) _backup_swap((ctx), (void **)&(from), (void **)&(to))

int zone_backup_init(size_t zone_count, const char *backup_dir, size_t kasp_db_size, zone_backup_ctx_t **out_ctx)
{
	if (backup_dir == NULL || out_ctx == NULL) {
		return KNOT_EINVAL;
	}
	if (zone_count < 1) {
		return KNOT_ENOZONE;
	}
	size_t backup_dir_len = strlen(backup_dir) + 1;

	zone_backup_ctx_t *ctx = malloc(sizeof(*ctx) + backup_dir_len);
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}
	ctx->zones_left = zone_count;
	ctx->backup_dir = (char *)(ctx + 1);
	memcpy(ctx->backup_dir, backup_dir, backup_dir_len);
	pthread_mutex_init(&ctx->zones_left_mutex, NULL);

	struct stat st = {0};
	if (stat(backup_dir, &st) == -1) {
	    mkdir(backup_dir, 0777);
	}

	char kasp_dir[backup_dir_len + 6];
	snprintf(kasp_dir, sizeof(kasp_dir), "%s/keys", backup_dir);
	knot_lmdb_init(&ctx->bck_kasp_db, kasp_dir, kasp_db_size, 0, "keys_db");

	*out_ctx = ctx;
	return KNOT_EOK;
}

void zone_backup_free(zone_backup_ctx_t *ctx)
{
	if (ctx != NULL) {
		knot_lmdb_deinit(&ctx->bck_kasp_db);
		pthread_mutex_destroy(&ctx->zones_left_mutex);
		free(ctx);
	}
}

static int backup_key(key_params_t *parm, dnssec_keystore_t *from, dnssec_keystore_t *to)
{
	dnssec_key_t *key = NULL;
	int ret = dnssec_key_new(&key);
	if (ret != KNOT_EOK) {
		return knot_error_from_libdnssec(ret);
	}
	dnssec_key_set_algorithm(key, parm->algorithm);

	ret = dnssec_keystore_export(from, parm->id, key);
	if (ret == 0 /* DNSSEC_EOK */) {
		ret = dnssec_keystore_unexport(to, key);
	}

	dnssec_key_free(key);
	return knot_error_from_libdnssec(ret);
}

static int backup_keystore(conf_t *conf, zone_t *zone, zone_backup_ctx_t *ctx)
{
	dnssec_keystore_t *from = NULL, *to = NULL;

	conf_val_t policy_id = conf_zone_get(conf, C_DNSSEC_POLICY, zone->name); // TODO what if configured onlinesign module?
	int ret = zone_init_keystore(conf, &policy_id, &from);
	if (ret != KNOT_EOK) {
		return ret;
	}

	char kasp_dir[strlen(ctx->backup_dir) + 6];
	snprintf(kasp_dir, sizeof(kasp_dir), "%s/keys", ctx->backup_dir);
	ret = keystore_load("keys", KEYSTORE_BACKEND_PEM, kasp_dir, &to); // TODO what if PKCS#11 is configured?
	if (ret != KNOT_EOK) {
		goto done;
	}

	BACKUP_SWAP(ctx, from, to);

	list_t key_params;
	init_list(&key_params);
	ret = kasp_db_list_keys(zone->kaspdb, zone->name, &key_params);
	ret = (ret == KNOT_ENOENT ? KNOT_EOK : ret);
	if (ret != KNOT_EOK) {
		goto done;
	}
	ptrnode_t *n;
	WALK_LIST(n, key_params) {
		if (ret == KNOT_EOK) {
			ret = backup_key(n->d, from, to);
			free_key_params(n->d);
		}
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

	knot_lmdb_db_t *kasp_from = zone->kaspdb, *kasp_to = &ctx->bck_kasp_db;
	BACKUP_SWAP(ctx, kasp_from, kasp_to);

	int ret = kasp_db_backup(zone->name, kasp_from, kasp_to);
	if (ret != KNOT_EOK) {
		goto done;
	}

	ret = backup_keystore(conf, zone, ctx);

done:
	pthread_mutex_lock(&ctx->zones_left_mutex);
	size_t left = ctx->zones_left--;
	pthread_mutex_unlock(&ctx->zones_left_mutex);
	if (left == 1) {
		zone_backup_free(ctx);
	}
	zone->backup_ctx = NULL;
	return ret;
}
