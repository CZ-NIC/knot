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

/*! \bref Backup format versions. */
typedef enum {
	BACKUP_FORMAT_1 = 1,           // in Knot DNS 3.0.x, no label file
	BACKUP_FORMAT_2 = 2,           // in Knot DNS 3.1.x
	BACKUP_FORMAT_TERM,
} knot_backup_format_t;

typedef struct zone_backup_ctx {
	node_t n;                           // ability to be put into list_t
	bool restore_mode;                  // if true, this is not a backup, but restore
	bool forced;                        // if true, the force flag has been set
	bool backup_zonefile;               // if true, also backup zone contents to a zonefile (default on)
	bool backup_journal;                // if true, also backup journal (default off)
	bool backup_timers;                 // if true, also backup timers (default on)
	bool backup_kaspdb;                 // if true, also backup KASP database (default on)
	bool backup_catalog;                // if true, also backup zone catalog (default on)
	bool backup_global;                 // perform global backup for all zones
	ssize_t readers;                    // when decremented to 0, all zones done, free this context
	pthread_mutex_t readers_mutex;      // mutex covering readers counter
	char *backup_dir;                   // path of directory to backup to / restore from
	knot_lmdb_db_t bck_kasp_db;         // backup KASP db
	knot_lmdb_db_t bck_timer_db;        // backup timer DB
	knot_lmdb_db_t bck_journal;         // backup journal DB
	knot_lmdb_db_t bck_catalog;         // backup catalog DB
	bool failed;                        // true if an error occurred in processing of any zone
	knot_backup_format_t backup_format; // the backup format version used
	time_t init_time;                   // time when the current backup operation has started
	int zone_count;                     // count of backed up zones
} zone_backup_ctx_t;

typedef struct {
	list_t ctxs;
	pthread_mutex_t mutex;
} zone_backup_ctxs_t;

int zone_backup_init(bool restore_mode, bool forced, const char *backup_dir,
                     size_t kasp_db_size, size_t timer_db_size, size_t journal_db_size,
                     size_t catalog_db_size, zone_backup_ctx_t **out_ctx);

int zone_backup_deinit(zone_backup_ctx_t *ctx);

int zone_backup(conf_t *conf, zone_t *zone);

int global_backup(zone_backup_ctx_t *ctx, catalog_t *catalog,
                  const knot_dname_t *zone_only);

void zone_backups_init(zone_backup_ctxs_t *ctxs);
void zone_backups_deinit(zone_backup_ctxs_t *ctxs);
void zone_backups_add(zone_backup_ctxs_t *ctxs, zone_backup_ctx_t *ctx);
void zone_backups_rem(zone_backup_ctx_t *ctx);
