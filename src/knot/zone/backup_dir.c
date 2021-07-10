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

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "knot/zone/backup_dir.h"

#include "contrib/files.h"
#include "contrib/getline.h"
#include "knot/common/log.h"

#define LABEL_FILE "knot_backup.label"
#define LOCK_FILE  "lock.knot_backup"

#define LABEL_FILE_HEAD         "label: Knot DNS Backup\n"
#define LABEL_FILE_FORMAT       "backup_format: %d\n"
#define LABEL_FILE_TIME_FORMAT  "%Y-%m-%d %H:%M:%S %Z"

#define FNAME_MAX (MAX(sizeof(LABEL_FILE), sizeof(LOCK_FILE)))
#define PREPARE_PATH(var, file) \
		char var[path_size(ctx)]; \
		get_full_path(ctx, file, var);

static const char *label_file_name = LABEL_FILE;
static const char *lock_file_name =  LOCK_FILE;
static const char *label_file_head = LABEL_FILE_HEAD;

static void get_full_path(zone_backup_ctx_t *ctx, const char *filename, char *full_path)
{
	(void)sprintf(full_path, "%s/%s", ctx->backup_dir, filename);
}

static size_t path_size(zone_backup_ctx_t *ctx)
{
	// The \0 terminator is already included in the sizeof()/FNAME_MAX value,
	// thus the sum covers one additional char for '/'.
	return (strlen(ctx->backup_dir) + 1 + FNAME_MAX);
}

static int make_label_file(zone_backup_ctx_t *ctx)
{
	PREPARE_PATH(label_path, label_file_name);

	FILE *file = fopen(label_path, "w");
	if (file == NULL) {
		return knot_map_errno();
	}

	// Prepare the server identity.
	conf_val_t val = conf_get(conf(), C_SRV, C_IDENT);
	const char *ident = conf_str(&val);
	if (ident == NULL || ident[0] == '\0') {
		ident = conf()->hostname;
	}

	// Prepare the timestamps.
	char started_time[64], finished_time[64];
	struct tm tm;

	localtime_r(&ctx->init_time, &tm);
	strftime(started_time, sizeof(started_time), LABEL_FILE_TIME_FORMAT, &tm);

	time_t now = time(NULL);
	localtime_r(&now, &tm);
	strftime(finished_time, sizeof(finished_time), LABEL_FILE_TIME_FORMAT, &tm);

	// Print the label contents.
	int ret = fprintf(file,
	              "%s"
	              LABEL_FILE_FORMAT
	              "server_identity: %s\n"
	              "started_time: %s\n"
	              "finished_time: %s\n"
	              "knot_version: %s\n"
	              "parameters: +%szonefile +%sjournal +%stimers +%skaspdb +%scatalog "
	                  "+backupdir %s\n"
	              "zone_count: %d\n",
	              label_file_head,
	              ctx->backup_format, ident, started_time, finished_time, PACKAGE_VERSION,
	              ctx->backup_zonefile ? "" : "no",
	              ctx->backup_journal ? "" : "no",
	              ctx->backup_timers ? "" : "no",
	              ctx->backup_kaspdb ? "" : "no",
	              ctx->backup_catalog ? "" : "no",
	              ctx->backup_dir,
	              ctx->zone_count);

	ret = (ret < 0) ? knot_map_errno() : KNOT_EOK;

	fclose(file);
	return ret;
}

static int get_backup_format(zone_backup_ctx_t *ctx)
{
	PREPARE_PATH(label_path, label_file_name);

	int ret = KNOT_EMALF;

	struct stat sb;
	if (stat(label_path, &sb) != 0) {
		ret = knot_map_errno();
		if (ret == KNOT_ENOENT) {
			if (ctx->forced) {
				ctx->backup_format = BACKUP_FORMAT_1;
				ret = KNOT_EOK;
			} else {
				ret = KNOT_EMALF;
			}
		}
		return ret;
	}

	// getline() from an empty file results in EAGAIN, therefore avoid doing so.
	if (!S_ISREG(sb.st_mode) || sb.st_size == 0) {
		return ret;
	}

	FILE *file = fopen(label_path, "r");
	if (file == NULL) {
		return knot_map_errno();
	}

	char *line = NULL;
	size_t line_size = 0;

	// Check for the header line first.
	if (knot_getline(&line, &line_size, file) == -1) {
		ret = knot_map_errno();
		goto done;
	}

	if (strcmp(line, label_file_head) != 0) {
		goto done;
	}

	while (knot_getline(&line, &line_size, file) != -1) {
		int value;
		if (sscanf(line, LABEL_FILE_FORMAT, &value) != 0) {
			if (value >= BACKUP_FORMAT_TERM) {
				ret = KNOT_ENOTSUP;
			} else if (value > BACKUP_FORMAT_1) {
				ctx->backup_format = value;
				ret = KNOT_EOK;
			}
			break;
		}
	}

done:
	free(line);
	fclose(file);
	return ret;
}

int backupdir_init(zone_backup_ctx_t *ctx)
{
	int ret;
	struct stat sb;

	// Make sure the source/target backup directory exists.
	if (ctx->restore_mode) {
		if (stat(ctx->backup_dir, &sb) != 0) {
			return knot_map_errno();
		}
		if (!S_ISDIR(sb.st_mode)) {
			return KNOT_ENOTDIR;
		}
	} else {
		ret = make_dir(ctx->backup_dir, S_IRWXU|S_IRWXG, true);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	char full_path[path_size(ctx)];

	// Check for existence of a label file and the backup format used.
	if (ctx->restore_mode) {
		ret = get_backup_format(ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		get_full_path(ctx, label_file_name, full_path);
		if (stat(full_path, &sb) == 0) {
			return KNOT_EEXIST;
		}
	}

	// Make (or check for existence of) a lock file.
	get_full_path(ctx, lock_file_name, full_path);
	if (ctx->restore_mode) {
		// Just check.
		if (stat(full_path, &sb) == 0) {
			return KNOT_EBUSY;
		}
	} else {
		// Create it (which also checks for its existence).
		int lock_file = open(full_path, O_CREAT|O_EXCL, S_IRUSR|S_IWUSR);
		if (lock_file < 0) {
			// Make the reported error better understandable than KNOT_EEXIST.
			return errno == EEXIST ? KNOT_EBUSY : knot_map_errno();
		}
		close(lock_file);
	}

	return KNOT_EOK;
}

int backupdir_deinit(zone_backup_ctx_t *ctx)
{
	int ret = KNOT_EOK;

	if (!ctx->restore_mode && !ctx->failed) {
		// Create the label file first.
		ret = make_label_file(ctx);
		if (ret == KNOT_EOK) {
			// Remove the lock file only when the label file has been created.
			PREPARE_PATH(lock_path, lock_file_name);
			unlink(lock_path);
		} else {
			log_error("failed to create a backup label in %s", (ctx)->backup_dir);
		}
	}

	return ret;
}
