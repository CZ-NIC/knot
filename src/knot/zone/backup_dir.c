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
#define LABEL_FILE_PARAMS       "parameters: "
#define LABEL_FILE_BACKUPDIR    "backupdir "
#define LABEL_FILE_TIME_FORMAT  "%Y-%m-%d %H:%M:%S %Z"

#define FNAME_MAX (MAX(sizeof(LABEL_FILE), sizeof(LOCK_FILE)))
#define PREPARE_PATH(var, file) \
		size_t var_size = path_size(ctx); \
		char var[var_size]; \
		get_full_path(ctx, file, var, var_size);

#define PARAMS_MAX_LENGTH  128 // At least longest params string without
                               // '+backupdir' ... (incl. \0) plus 1 for assert().

static const char *label_file_name = LABEL_FILE;
static const char *lock_file_name =  LOCK_FILE;
static const char *label_file_head = LABEL_FILE_HEAD;

static void get_full_path(zone_backup_ctx_t *ctx, const char *filename,
                          char *full_path, size_t full_path_size)
{
	(void)snprintf(full_path, full_path_size, "%s/%s", ctx->backup_dir, filename);
}

static size_t path_size(zone_backup_ctx_t *ctx)
{
	// The \0 terminator is already included in the sizeof()/FNAME_MAX value,
	// thus the sum covers one additional char for '/'.
	return (strlen(ctx->backup_dir) + 1 + FNAME_MAX);
}

static void print_params(char *buf, knot_backup_params_t params)
{
	int remain = PARAMS_MAX_LENGTH;
	for (const backup_filter_list_t *item = backup_filters;
	     item->name != NULL; item++) {
		int n = snprintf(buf, remain, "+%s%s ",
		                 (params & item->param) ? "" : "no",
		                 item->name);
		buf += n;
		remain -= n;
	}
	assert(remain > 1);
}

static knot_backup_params_t parse_params(const char *str)
{
	knot_backup_params_t params = 0;

	// Checking for positive filters only, negative assumed otherwise.
	while ((str = strchr(str, '+')) != NULL) {
		str++;
		for (const backup_filter_list_t *item = backup_filters;
		     item->name != NULL; item++) {
			if (strncmp(str, item->name,
			            strlen(item->name)) == 0) {
				params |= item->param;
				break;
			}
		}
		// Avoid getting fooled by the backup directory path.
		if (strncmp(str, LABEL_FILE_BACKUPDIR,
		            sizeof(LABEL_FILE_BACKUPDIR) - 1) == 0) {
			break;
		}
	}

	return params;
}

static int make_label_file(zone_backup_ctx_t *ctx)
{
	PREPARE_PATH(label_path, label_file_name);

	FILE *file = fopen(label_path, "w");
	if (file == NULL) {
		return knot_map_errno();
	}

	// Prepare the server identity.
	const char *ident = conf()->cache.srv_ident;

	// Prepare the timestamps.
	char started_time[64], finished_time[64];
	struct tm tm;

	localtime_r(&ctx->init_time, &tm);
	strftime(started_time, sizeof(started_time), LABEL_FILE_TIME_FORMAT, &tm);

	time_t now = time(NULL);
	localtime_r(&now, &tm);
	strftime(finished_time, sizeof(finished_time), LABEL_FILE_TIME_FORMAT, &tm);

	// Print the label contents.
	char params_str[PARAMS_MAX_LENGTH];
	print_params(params_str, ctx->backup_params);
	int ret = fprintf(file,
	              "%s"
	              LABEL_FILE_FORMAT
	              "server_identity: %s\n"
	              "started_time: %s\n"
	              "finished_time: %s\n"
	              "knot_version: %s\n"
	              LABEL_FILE_PARAMS "%s+" LABEL_FILE_BACKUPDIR "%s\n"
	              "zone_count: %d\n",
	              label_file_head,
	              ctx->backup_format, ident, started_time, finished_time, PACKAGE_VERSION,
	              params_str, ctx->backup_dir,
	              ctx->zone_count);

	ret = (ret < 0) ? knot_map_errno() : KNOT_EOK;

	fclose(file);
	return ret;
}

static int get_backup_format(zone_backup_ctx_t *ctx)
{
	PREPARE_PATH(label_path, label_file_name);

	int ret;

	struct stat sb;
	if (stat(label_path, &sb) != 0) {
		ret = knot_map_errno();
		if (ret == KNOT_ENOENT) {
			if (ctx->forced) {
				ctx->backup_format = BACKUP_FORMAT_1;
				// No contents info available, it's user's responsibility here.
				// Set backup components existing in BACKUP_FORMAT_1 only.
				ctx->in_backup = BACKUP_PARAM_ZONEFILE | BACKUP_PARAM_JOURNAL |
				                 BACKUP_PARAM_TIMERS | BACKUP_PARAM_KASPDB |
				                 BACKUP_PARAM_CATALOG;
				ret = KNOT_EOK;
			} else {
				ret = KNOT_EMALF;
			}
		}
		return ret;
	}

	// getline() from an empty file results in EAGAIN, therefore avoid doing so.
	if (!S_ISREG(sb.st_mode) || sb.st_size == 0) {
		return KNOT_EMALF;
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
		ret = KNOT_EMALF;
		goto done;
	}

	unsigned int remain = 3; // Bit-mapped "punch card" for lines to get data from.
	while (remain > 0 && knot_getline(&line, &line_size, file) != -1) {
		int value;
		if (sscanf(line, LABEL_FILE_FORMAT, &value) != 0) {
			if (value >= BACKUP_FORMAT_TERM) {
				ret = KNOT_ENOTSUP;
				goto done;
			} else if (value <= BACKUP_FORMAT_1) {
				ret = KNOT_EMALF;
				goto done;
			} else {
				ctx->backup_format = value;
				remain &= ~1;
				continue;
			}
		}
		if (strncmp(line, LABEL_FILE_PARAMS, sizeof(LABEL_FILE_PARAMS) - 1) == 0) {
			ctx->in_backup = parse_params(line + sizeof(LABEL_FILE_PARAMS) - 1);
			remain &= ~2;
		}
	}

	ret = (remain == 0) ? KNOT_EOK : KNOT_EMALF;

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
		ret = make_dir(ctx->backup_dir, S_IRWXU | S_IRWXG, true);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	size_t full_path_size = path_size(ctx);
	char full_path[full_path_size];

	// Check for existence of a label file, the backup format used, and available data.
	if (ctx->restore_mode) {
		ret = get_backup_format(ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		get_full_path(ctx, label_file_name, full_path, full_path_size);
		if (stat(full_path, &sb) == 0) {
			return KNOT_EEXIST;
		}
	}

	// Make (or check for existence of) a lock file.
	get_full_path(ctx, lock_file_name, full_path, full_path_size);
	if (ctx->restore_mode) {
		// Just check.
		if (stat(full_path, &sb) == 0) {
			return KNOT_EBUSY;
		}
	} else {
		// Create it (which also checks for its existence).
		int lock_file = open(full_path, O_CREAT | O_EXCL,
		                     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
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
