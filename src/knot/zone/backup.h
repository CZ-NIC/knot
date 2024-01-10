/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

/*! \bref Backup components list. */
typedef enum {
	BACKUP_PARAM_ZONEFILE = 1 << 0, // backup zone contents to a zonefile
	BACKUP_PARAM_JOURNAL =  1 << 1, // backup journal
	BACKUP_PARAM_TIMERS =   1 << 2, // backup timers
	BACKUP_PARAM_KASPDB =   1 << 3, // backup KASP database (incl. keys)
	BACKUP_PARAM_KEYSONLY = 1 << 4, // backup keys (without KASP db)
	BACKUP_PARAM_CATALOG =  1 << 5, // backup zone catalog
	BACKUP_PARAM_QUIC =     1 << 6, // backup QUIC server key and certificate
} knot_backup_params_t;

/*! \bref Default set of components for backup. */
#define BACKUP_PARAM_DFLT_B (BACKUP_PARAM_ZONEFILE | BACKUP_PARAM_TIMERS | \
                             BACKUP_PARAM_KASPDB | BACKUP_PARAM_CATALOG | \
                             BACKUP_PARAM_QUIC)

/*! \bref Default set of components for restore. */
#define BACKUP_PARAM_DFLT_R (BACKUP_PARAM_ZONEFILE | BACKUP_PARAM_TIMERS | \
                             BACKUP_PARAM_KASPDB | BACKUP_PARAM_CATALOG)

/*! \bref Backup components done in event. */
#define BACKUP_PARAM_EVENT  (BACKUP_PARAM_ZONEFILE | BACKUP_PARAM_JOURNAL | \
                             BACKUP_PARAM_TIMERS | BACKUP_PARAM_KASPDB | \
                             BACKUP_PARAM_CATALOG)

typedef struct {
        const char *name;
        knot_backup_params_t param;
        char filter;
        char neg_filter;
} backup_filter_list_t;

typedef struct zone_backup_ctx {
	node_t n;                           // ability to be put into list_t
	bool restore_mode;                  // if true, this is not a backup, but restore
	bool forced;                        // if true, the force flag has been set
	knot_backup_params_t backup_params; // bit-mapped list of backup components
	knot_backup_params_t in_backup;     // bit-mapped list of components available in backup
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

extern const backup_filter_list_t backup_filters[];

int zone_backup_init(bool restore_mode, knot_backup_params_t filters, bool forced,
                     const char *backup_dir,
                     size_t kasp_db_size, size_t timer_db_size, size_t journal_db_size,
                     size_t catalog_db_size, zone_backup_ctx_t **out_ctx);

int zone_backup_deinit(zone_backup_ctx_t *ctx);

int zone_backup(conf_t *conf, zone_t *zone);

int global_backup(zone_backup_ctx_t *ctx, catalog_t *catalog,
                  const knot_dname_t *zone_only);
int zone_backup_keysonly(zone_backup_ctx_t *ctx, conf_t *conf, zone_t *zone);

void zone_backups_init(zone_backup_ctxs_t *ctxs);
void zone_backups_deinit(zone_backup_ctxs_t *ctxs);
void zone_backups_add(zone_backup_ctxs_t *ctxs, zone_backup_ctx_t *ctx);
void zone_backups_rem(zone_backup_ctx_t *ctx);

int backup_quic(zone_backup_ctx_t *ctx, bool quic_on);
