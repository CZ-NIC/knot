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
	bool restore_mode;                  // if true, this is not a backup, but restore
	bool backup_journal;                // if true, also backup journal
	bool backup_zonefile;               // if true, also backup zone contents to a zonefile (default on)
	bool backup_global;                 // perform global backup for all zones
	ssize_t readers;                    // when decremented to 0, all zones done, free this context
	pthread_mutex_t readers_mutex;      // mutex covering readers counter
	char *backup_dir;                   // path of directory to backup to / restore from
	knot_lmdb_db_t bck_kasp_db;         // backup KASP db
	knot_lmdb_db_t bck_timer_db;        // backup timer DB
	knot_lmdb_db_t bck_journal;         // backup journal DB
	knot_lmdb_db_t bck_catalog;         // backup catalog DB
	int lock_file;                      // lock file preventing simultaneous backups to same directory
} zone_backup_ctx_t;

int zone_backup_init(bool restore_mode, const char *backup_dir,
                     size_t kasp_db_size, size_t timer_db_size, size_t journal_db_size,
                     size_t catalog_db_size, zone_backup_ctx_t **out_ctx);

void zone_backup_deinit(zone_backup_ctx_t *ctx);

int zone_backup(conf_t *conf, zone_t *zone);

int global_backup(zone_backup_ctx_t *ctx, catalog_t *catalog,
                  const knot_dname_t *zone_only);
