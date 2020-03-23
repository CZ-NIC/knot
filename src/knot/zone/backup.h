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

#pragma once

#include <pthread.h>
#include <stdint.h>

#include "knot/dnssec/kasp/kasp_db.h"
#include "knot/zone/zone.h"

typedef struct zone_backup_ctx {
	ssize_t zones_left;
	pthread_mutex_t zones_left_mutex;
	char *backup_dir;
	knot_lmdb_db_t bck_kasp_db;
} zone_backup_ctx_t;

int zone_backup_init(size_t zone_count, const char *backup_dir, size_t kasp_db_size, zone_backup_ctx_t **out_ctx);

void zone_backup_free(zone_backup_ctx_t *ctx);

int zone_backup(conf_t *conf, zone_t *zone);
