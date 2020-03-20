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

#include "knot/zone/backup.h"

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

	char temp[backup_dir_len + 16];
	snprintf(temp, sizeof(temp), "%s/keys", backup_dir);
	knot_lmdb_init(&ctx->bck_kasp_db, temp, kasp_db_size, 0, "keys_db");

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

int zone_backup(zone_t *zone)
{
	zone_backup_ctx_t *ctx = zone->backup_ctx;
	if (ctx == NULL) {
		return KNOT_EINVAL;
	}

	int ret = kasp_db_backup(zone->name, zone->kaspdb, &ctx->bck_kasp_db);

	pthread_mutex_lock(&ctx->zones_left_mutex);
	size_t left = ctx->zones_left--;
	pthread_mutex_unlock(&ctx->zones_left_mutex);
	if (left == 1) {
		zone_backup_free(ctx);
	}
	zone->backup_ctx = NULL;
	return ret;
}
