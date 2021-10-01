/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/ctl/commands.h"
#include "knot/conf/conf.h"
#include "knot/conf/confdb.h"
#include "knot/conf/tools.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-load.h"
#include "contrib/macros.h"
#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "contrib/openbsd/strlcat.h"
#include "utils/knotc/commands.h"

#define CMD_EXIT		"exit"

#define CMD_STATUS		"status"
#define CMD_STOP		"stop"
#define CMD_RELOAD		"reload"
#define CMD_STATS		"stats"

#define CMD_ZONE_CHECK		"zone-check"
#define CMD_ZONE_STATUS		"zone-status"
#define CMD_ZONE_RELOAD		"zone-reload"
#define CMD_ZONE_REFRESH	"zone-refresh"
#define CMD_ZONE_RETRANSFER	"zone-retransfer"
#define CMD_ZONE_NOTIFY		"zone-notify"
#define CMD_ZONE_FLUSH		"zone-flush"
#define CMD_ZONE_BACKUP		"zone-backup"
#define CMD_ZONE_RESTORE	"zone-restore"
#define CMD_ZONE_SIGN		"zone-sign"
#define CMD_ZONE_KEYS_LOAD	"zone-keys-load"
#define CMD_ZONE_KEY_ROLL	"zone-key-rollover"
#define CMD_ZONE_KSK_SBM	"zone-ksk-submitted"
#define CMD_ZONE_FREEZE		"zone-freeze"
#define CMD_ZONE_THAW		"zone-thaw"
#define CMD_ZONE_XFR_FREEZE	"zone-xfr-freeze"
#define CMD_ZONE_XFR_THAW	"zone-xfr-thaw"

#define CMD_ZONE_READ		"zone-read"
#define CMD_ZONE_BEGIN		"zone-begin"
#define CMD_ZONE_COMMIT		"zone-commit"
#define CMD_ZONE_ABORT		"zone-abort"
#define CMD_ZONE_DIFF		"zone-diff"
#define CMD_ZONE_GET		"zone-get"
#define CMD_ZONE_SET		"zone-set"
#define CMD_ZONE_UNSET		"zone-unset"
#define CMD_ZONE_PURGE		"zone-purge"
#define CMD_ZONE_STATS		"zone-stats"

#define CMD_CONF_INIT		"conf-init"
#define CMD_CONF_CHECK		"conf-check"
#define CMD_CONF_IMPORT		"conf-import"
#define CMD_CONF_EXPORT		"conf-export"
#define CMD_CONF_LIST		"conf-list"
#define CMD_CONF_READ		"conf-read"
#define CMD_CONF_BEGIN		"conf-begin"
#define CMD_CONF_COMMIT		"conf-commit"
#define CMD_CONF_ABORT		"conf-abort"
#define CMD_CONF_DIFF		"conf-diff"
#define CMD_CONF_GET		"conf-get"
#define CMD_CONF_SET		"conf-set"
#define CMD_CONF_UNSET		"conf-unset"

#define CTL_LOG_STR		"failed to control"

#define CTL_SEND(type, data) \
	ret = knot_ctl_send(args->ctl, (type), (data)); \
	if (ret != KNOT_EOK) { \
		log_error(CTL_LOG_STR" (%s)", knot_strerror(ret)); \
		return ret; \
	}

#define CTL_SEND_DATA CTL_SEND(KNOT_CTL_TYPE_DATA, &data)
#define CTL_SEND_BLOCK CTL_SEND(KNOT_CTL_TYPE_BLOCK, NULL)

static int check_args(cmd_args_t *args, int min, int max)
{
	if (max == 0 && args->argc > 0) {
		log_error("command doesn't take arguments");
		return KNOT_EINVAL;
	} else if (min == max && args->argc != min) {
		log_error("command requires %i arguments", min);
		return KNOT_EINVAL;
	} else if (args->argc < min) {
		log_error("command requires at least %i arguments", min);
		return KNOT_EINVAL;
	} else if (max > 0 && args->argc > max) {
		log_error("command takes at most %i arguments", max);
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

static int check_conf_args(cmd_args_t *args)
{
	// Mask relevant flags.
	cmd_flag_t flags = args->desc->flags;
	flags &= CMD_FOPT_ITEM | CMD_FREQ_ITEM | CMD_FOPT_DATA;

	switch (args->argc) {
	case 0:
		if (flags == CMD_FNONE || (flags & CMD_FOPT_ITEM)) {
			return KNOT_EOK;
		}
		break;
	case 1:
		if (flags & (CMD_FOPT_ITEM | CMD_FREQ_ITEM)) {
			return KNOT_EOK;
		}
		break;
	default:
		if (flags != CMD_FNONE) {
			return KNOT_EOK;
		}
		break;
	}

	log_error("invalid number of arguments");

	return KNOT_EINVAL;
}

static int get_conf_key(const char *key, knot_ctl_data_t *data)
{
	// Get key0.
	const char *key0 = key;

	// Check for id.
	char *id = strchr(key, '[');
	if (id != NULL) {
		// Separate key0 and id.
		*id++ = '\0';

		// Check for id end.
		char *id_end = id;
		while ((id_end = strchr(id_end, ']')) != NULL) {
			// Check for escaped character.
			if (*(id_end - 1) != '\\') {
				break;
			}
			id_end++;
		}

		// Check for unclosed id.
		if (id_end == NULL) {
			log_error("(missing bracket after identifier) %s", id);
			return KNOT_EINVAL;
		}

		// Separate id and key1.
		*id_end = '\0';

		key = id_end + 1;

		// Key1 or nothing must follow.
		if (*key != '.' && *key != '\0') {
			log_error("(unexpected token) %s", key);
			return KNOT_EINVAL;
		}
	}

	// Check for key1.
	char *key1 = strchr(key, '.');
	if (key1 != NULL) {
		// Separate key0/id and key1.
		*key1++ = '\0';

		if (*key1 == '\0') {
			log_error("(missing item specification)");
			return KNOT_EINVAL;
		}
	}

	(*data)[KNOT_CTL_IDX_SECTION] = key0;
	(*data)[KNOT_CTL_IDX_ITEM] = key1;
	(*data)[KNOT_CTL_IDX_ID] = id;

	return KNOT_EOK;
}

static void format_data(ctl_cmd_t cmd, knot_ctl_type_t data_type,
                        knot_ctl_data_t *data, bool *empty)
{
	const char *error = (*data)[KNOT_CTL_IDX_ERROR];
	const char *flags = (*data)[KNOT_CTL_IDX_FLAGS];
	const char *key0  = (*data)[KNOT_CTL_IDX_SECTION];
	const char *key1  = (*data)[KNOT_CTL_IDX_ITEM];
	const char *id    = (*data)[KNOT_CTL_IDX_ID];
	const char *zone  = (*data)[KNOT_CTL_IDX_ZONE];
	const char *owner = (*data)[KNOT_CTL_IDX_OWNER];
	const char *ttl   = (*data)[KNOT_CTL_IDX_TTL];
	const char *type  = (*data)[KNOT_CTL_IDX_TYPE];
	const char *value = (*data)[KNOT_CTL_IDX_DATA];

	const char *sign = NULL;
	if (ctl_has_flag(flags, CTL_FLAG_ADD)) {
		sign = CTL_FLAG_ADD;
	} else if (ctl_has_flag(flags, CTL_FLAG_REM)) {
		sign = CTL_FLAG_REM;
	}

	switch (cmd) {
	case CTL_STATUS:
		if (error != NULL) {
			printf("error: (%s)%s%s", error,
			       (type != NULL) ? " "  : "",
			       (type != NULL) ? type : "");
		} else if (value != NULL) {
			printf("%s", value);
			*empty = false;
		}
		break;
	case CTL_STOP:
	case CTL_RELOAD:
	case CTL_CONF_BEGIN:
	case CTL_CONF_ABORT:
		// Only error message is expected here.
		if (error != NULL) {
			printf("error: (%s)", error);
		}
		break;
	case CTL_ZONE_STATUS:
	case CTL_ZONE_RELOAD:
	case CTL_ZONE_REFRESH:
	case CTL_ZONE_RETRANSFER:
	case CTL_ZONE_NOTIFY:
	case CTL_ZONE_FLUSH:
	case CTL_ZONE_BACKUP:
	case CTL_ZONE_RESTORE:
	case CTL_ZONE_SIGN:
	case CTL_ZONE_KEYS_LOAD:
	case CTL_ZONE_KEY_ROLL:
	case CTL_ZONE_KSK_SBM:
	case CTL_ZONE_FREEZE:
	case CTL_ZONE_THAW:
	case CTL_ZONE_BEGIN:
	case CTL_ZONE_COMMIT:
	case CTL_ZONE_ABORT:
	case CTL_ZONE_PURGE:
		if (data_type == KNOT_CTL_TYPE_DATA) {
			printf("%s%s%s%s%s%s%s%s",
			       (!(*empty)     ? "\n"      : ""),
			       (error != NULL ? "error: " : ""),
			       (zone  != NULL ? "["       : ""),
			       (zone  != NULL ? zone      : ""),
			       (zone  != NULL ? "]"       : ""),
			       (error != NULL ? " ("      : ""),
			       (error != NULL ? error     : ""),
			       (error != NULL ? ")"       : ""));
			*empty = false;
		}
		if (cmd == CTL_ZONE_STATUS && type != NULL) {
			printf("%s %s: %s",
			       (data_type != KNOT_CTL_TYPE_DATA ? " |" : ""),
			       type, value);
		}
		break;
	case CTL_CONF_COMMIT: // Can return a check error context.
	case CTL_CONF_LIST:
	case CTL_CONF_READ:
	case CTL_CONF_DIFF:
	case CTL_CONF_GET:
	case CTL_CONF_SET:
	case CTL_CONF_UNSET:
		if (data_type == KNOT_CTL_TYPE_DATA) {
			printf("%s%s%s%s%s%s%s%s%s%s%s%s",
			       (!(*empty)     ? "\n"       : ""),
			       (error != NULL ? "error: (" : ""),
			       (error != NULL ? error      : ""),
			       (error != NULL ? ") "       : ""),
			       (sign  != NULL ? sign       : ""),
			       (key0  != NULL ? key0       : ""),
			       (id    != NULL ? "["        : ""),
			       (id    != NULL ? id         : ""),
			       (id    != NULL ? "]"        : ""),
			       (key1  != NULL ? "."        : ""),
			       (key1  != NULL ? key1       : ""),
			       (value != NULL ? " ="       : ""));
			*empty = false;
		}
		if (value != NULL) {
			printf(" %s", value);
		}
		break;
	case CTL_ZONE_READ:
	case CTL_ZONE_DIFF:
	case CTL_ZONE_GET:
	case CTL_ZONE_SET:
	case CTL_ZONE_UNSET:
		printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
		       (!(*empty)     ? "\n"       : ""),
		       (error != NULL ? "error: (" : ""),
		       (error != NULL ? error      : ""),
		       (error != NULL ? ") "       : ""),
		       (zone  != NULL ? "["        : ""),
		       (zone  != NULL ? zone       : ""),
		       (zone  != NULL ? "] "       : ""),
		       (sign  != NULL ? sign       : ""),
		       (owner != NULL ? owner      : ""),
		       (ttl   != NULL ? " "        : ""),
		       (ttl   != NULL ? ttl        : ""),
		       (type  != NULL ? " "        : ""),
		       (type  != NULL ? type       : ""),
		       (value != NULL ? " "        : ""),
		       (value != NULL ? value      : ""));
		*empty = false;
		break;
	case CTL_STATS:
	case CTL_ZONE_STATS:
		printf("%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
		       (!(*empty)     ? "\n"       : ""),
		       (error != NULL ? "error: (" : ""),
		       (error != NULL ? error      : ""),
		       (error != NULL ? ") "       : ""),
		       (zone  != NULL ? "["        : ""),
		       (zone  != NULL ? zone       : ""),
		       (zone  != NULL ? "] "       : ""),
		       (key0  != NULL ? key0       : ""),
		       (key1  != NULL ? "."        : ""),
		       (key1  != NULL ? key1       : ""),
		       (id    != NULL ? "["        : ""),
		       (id    != NULL ? id         : ""),
		       (id    != NULL ? "]"        : ""),
		       (value != NULL ? " = "      : ""),
		       (value != NULL ? value      : ""));
		*empty = false;
		break;
	default:
		assert(0);
	}
}

static void format_block(ctl_cmd_t cmd, bool failed, bool empty)
{
	switch (cmd) {
	case CTL_STATUS:
		printf("%s\n", (failed || !empty) ? "" : "Running");
		break;
	case CTL_STOP:
		printf("%s\n", failed ? "" : "Stopped");
		break;
	case CTL_RELOAD:
		printf("%s\n", failed ? "" : "Reloaded");
		break;
	case CTL_CONF_BEGIN:
	case CTL_CONF_COMMIT:
	case CTL_CONF_ABORT:
	case CTL_CONF_SET:
	case CTL_CONF_UNSET:
	case CTL_ZONE_RELOAD:
	case CTL_ZONE_REFRESH:
	case CTL_ZONE_RETRANSFER:
	case CTL_ZONE_NOTIFY:
	case CTL_ZONE_FLUSH:
	case CTL_ZONE_BACKUP:
	case CTL_ZONE_RESTORE:
	case CTL_ZONE_SIGN:
	case CTL_ZONE_KEYS_LOAD:
	case CTL_ZONE_KEY_ROLL:
	case CTL_ZONE_KSK_SBM:
	case CTL_ZONE_FREEZE:
	case CTL_ZONE_THAW:
	case CTL_ZONE_XFR_FREEZE:
	case CTL_ZONE_XFR_THAW:
	case CTL_ZONE_BEGIN:
	case CTL_ZONE_COMMIT:
	case CTL_ZONE_ABORT:
	case CTL_ZONE_SET:
	case CTL_ZONE_UNSET:
	case CTL_ZONE_PURGE:
		printf("%s\n", failed ? "" : "OK");
		break;
	case CTL_ZONE_STATUS:
	case CTL_ZONE_READ:
	case CTL_ZONE_DIFF:
	case CTL_ZONE_GET:
	case CTL_CONF_LIST:
	case CTL_CONF_READ:
	case CTL_CONF_DIFF:
	case CTL_CONF_GET:
	case CTL_ZONE_STATS:
	case CTL_STATS:
		printf("%s", empty ? "" : "\n");
		break;
	default:
		assert(0);
	}
}

static int ctl_receive(cmd_args_t *args)
{
	bool failed = false;
	bool empty = true;

	while (true) {
		knot_ctl_type_t type;
		knot_ctl_data_t data;

		int ret = knot_ctl_receive(args->ctl, &type, &data);
		if (ret != KNOT_EOK) {
			log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
			return ret;
		}

		switch (type) {
		case KNOT_CTL_TYPE_END:
			log_error(CTL_LOG_STR" (%s)", knot_strerror(KNOT_EMALF));
			return KNOT_EMALF;
		case KNOT_CTL_TYPE_BLOCK:
			format_block(args->desc->cmd, failed, empty);
			return failed ? KNOT_ERROR : KNOT_EOK;
		case KNOT_CTL_TYPE_DATA:
		case KNOT_CTL_TYPE_EXTRA:
			format_data(args->desc->cmd, type, &data, &empty);
			break;
		default:
			assert(0);
			return KNOT_EINVAL;
		}

		if (data[KNOT_CTL_IDX_ERROR] != NULL) {
			failed = true;
		}
	}

	return KNOT_EOK;
}

static int cmd_ctl(cmd_args_t *args)
{
	int ret = check_args(args, 0, (args->desc->cmd == CTL_STATUS ? 1 : 0));
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->flags,
		[KNOT_CTL_IDX_TYPE] = args->argc > 0 ? args->argv[0] : NULL
	};

	CTL_SEND_DATA
	CTL_SEND_BLOCK

	return ctl_receive(args);
}

static int set_stats_items(cmd_args_t *args, knot_ctl_data_t *data)
{
	int min_args, max_args;
	switch (args->desc->cmd) {
	case CTL_STATS:      min_args = 0; max_args = 1; break;
	case CTL_ZONE_STATS: min_args = 1; max_args = 2; break;
	default:
		assert(0);
		return KNOT_EINVAL;
	}

	// Check the number of arguments.
	int ret = check_args(args, min_args, max_args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	int idx = 0;

	// Set ZONE name.
	if (args->argc > idx && args->desc->cmd == CTL_ZONE_STATS) {
		if (strcmp(args->argv[idx], "--") != 0) {
			(*data)[KNOT_CTL_IDX_ZONE] = args->argv[idx];
		}
		idx++;
	}

	if (args->argc > idx) {
		(*data)[KNOT_CTL_IDX_SECTION] = args->argv[idx];

		char *item = strchr(args->argv[idx], '.');
		if (item != NULL) {
			// Separate section and item.
			*item++ = '\0';
			(*data)[KNOT_CTL_IDX_ITEM] = item;
		}
	}

	return KNOT_EOK;
}

static int cmd_stats_ctl(cmd_args_t *args)
{
	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->flags,
	};

	int ret = set_stats_items(args, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	CTL_SEND_DATA
	CTL_SEND_BLOCK

	return ctl_receive(args);
}

static int zone_exec(cmd_args_t *args, int (*fcn)(const knot_dname_t *, void *),
                     void *data)
{
	bool failed = false;

	// Process specified zones.
	if (args->argc > 0) {
		knot_dname_storage_t id;

		for (int i = 0; i < args->argc; i++) {
			if (knot_dname_from_str(id, args->argv[i], sizeof(id)) == NULL) {
				log_zone_str_error(args->argv[i], "invalid name");
				failed = true;
				continue;
			}
			knot_dname_to_lower(id);

			if (!conf_rawid_exists(conf(), C_ZONE, id, knot_dname_size(id))) {
				log_zone_error(id, "%s", knot_strerror(KNOT_ENOZONE));
				failed = true;
				continue;
			}

			if (fcn(id, data) != KNOT_EOK) {
				failed = true;
			}
		}
	// Process all configured zones.
	} else {
		for (conf_iter_t iter = conf_iter(conf(), C_ZONE);
		     iter.code == KNOT_EOK; conf_iter_next(conf(), &iter)) {
			conf_val_t val = conf_iter_id(conf(), &iter);
			const knot_dname_t *id = conf_dname(&val);

			if (fcn(id, data) != KNOT_EOK) {
				failed = true;
			}
		}
	}

	return failed ? KNOT_ERROR : KNOT_EOK;
}

static int zone_check(const knot_dname_t *dname, void *data)
{
	cmd_args_t *args = data;

	zone_contents_t *contents = NULL;
	int ret = zone_load_contents(conf(), dname, &contents, args->force);
	zone_contents_deep_free(contents);
	return ret;
}

static int cmd_zone_check(cmd_args_t *args)
{
	return zone_exec(args, zone_check, args);
}

static int cmd_zone_key_roll_ctl(cmd_args_t *args)
{
	int ret = check_args(args, 2, 2);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->flags,
		[KNOT_CTL_IDX_ZONE] = args->argv[0],
		[KNOT_CTL_IDX_TYPE] = args->argv[1],
	};

	CTL_SEND_DATA
	CTL_SEND_BLOCK

	return ctl_receive(args);
}

static int cmd_zone_ctl(cmd_args_t *args)
{
	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->flags,
	};

	// Check the number of arguments.
	int ret = check_args(args, (args->desc->flags & CMD_FREQ_ZONE) ? 1 : 0, -1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (args->desc->cmd == CTL_ZONE_PURGE && !args->force) {
		log_error("force option required!");
		return KNOT_EDENIED;
	}

	// Ignore all zones argument.
	if (args->argc == 1 && strcmp(args->argv[0], "--") == 0) {
		args->argc = 0;
	}

	if (args->argc == 0) {
		CTL_SEND_DATA
	}
	for (int i = 0; i < args->argc; i++) {
		data[KNOT_CTL_IDX_ZONE] = args->argv[i];

		CTL_SEND_DATA
	}

	CTL_SEND_BLOCK

	return ctl_receive(args);
}

#define MAX_FILTERS 12

typedef struct {
	const char *name;
	char id;
	bool with_data; // Only ONE filter of each filter_desc_t may have data!
} filter_desc_t;

const filter_desc_t zone_flush_filters[MAX_FILTERS] = {
	{ "+outdir", CTL_FILTER_FLUSH_OUTDIR, true },
};

const filter_desc_t zone_backup_filters[MAX_FILTERS] = {
	{ "+backupdir",   CTL_FILTER_BACKUP_OUTDIR,      true },
	{ "+zonefile",    CTL_FILTER_BACKUP_ZONEFILE,   false },
	{ "+nozonefile",  CTL_FILTER_BACKUP_NOZONEFILE, false },
	{ "+journal",     CTL_FILTER_BACKUP_JOURNAL,    false },
	{ "+nojournal",   CTL_FILTER_BACKUP_NOJOURNAL,  false },
	{ "+timers",      CTL_FILTER_BACKUP_TIMERS,     false },
	{ "+notimers",    CTL_FILTER_BACKUP_NOTIMERS,   false },
	{ "+kaspdb",      CTL_FILTER_BACKUP_KASPDB,     false },
	{ "+nokaspdb",    CTL_FILTER_BACKUP_NOKASPDB,   false },
	{ "+catalog",     CTL_FILTER_BACKUP_CATALOG,    false },
	{ "+nocatalog",   CTL_FILTER_BACKUP_NOCATALOG,  false },
};

const filter_desc_t zone_status_filters[MAX_FILTERS] = {
	{ "+role",        CTL_FILTER_STATUS_ROLE },
	{ "+serial",      CTL_FILTER_STATUS_SERIAL },
	{ "+transaction", CTL_FILTER_STATUS_TRANSACTION },
	{ "+freeze",      CTL_FILTER_STATUS_FREEZE },
	{ "+catalog",     CTL_FILTER_STATUS_CATALOG },
	{ "+events",      CTL_FILTER_STATUS_EVENTS },
};

const filter_desc_t zone_purge_filters[MAX_FILTERS] = {
	{ "+expire",   CTL_FILTER_PURGE_EXPIRE },
	{ "+zonefile", CTL_FILTER_PURGE_ZONEFILE },
	{ "+journal",  CTL_FILTER_PURGE_JOURNAL },
	{ "+timers",   CTL_FILTER_PURGE_TIMERS },
	{ "+kaspdb",   CTL_FILTER_PURGE_KASPDB },
	{ "+catalog",  CTL_FILTER_PURGE_CATALOG },
	{ "+orphan",   CTL_FILTER_PURGE_ORPHAN },
};

const filter_desc_t null_filter = { 0 };

static const filter_desc_t *get_filter(ctl_cmd_t cmd, const char *filter_name)
{
	const filter_desc_t *fd = NULL;
	switch (cmd) {
	case CTL_ZONE_FLUSH:
		fd = zone_flush_filters;
		break;
	case CTL_ZONE_BACKUP:
	case CTL_ZONE_RESTORE:
		fd = zone_backup_filters;
		break;
	case CTL_ZONE_STATUS:
		fd = zone_status_filters;
		break;
	case CTL_ZONE_PURGE:
		fd = zone_purge_filters;
		break;
	default:
		return &null_filter;
	}
	for (size_t i = 0; i < MAX_FILTERS && fd[i].name != NULL; i++) {
		if (strcmp(fd[i].name, filter_name) == 0) {
			return &fd[i];
		}
	}
	return &null_filter;
}

static int cmd_zone_filter_ctl(cmd_args_t *args)
{
	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->flags,
	};

	if (args->desc->cmd == CTL_ZONE_PURGE && !args->force) {
		log_error("force option required!");
		return KNOT_EDENIED;
	}

	char filter_buff[MAX_FILTERS + 1] = { 0 };

	// First, process the filters.
	for (int i = 0; i < args->argc; i++) {
		if (args->argv[i][0] == '+') {
			if (data[KNOT_CTL_IDX_FILTER] == NULL) {
				data[KNOT_CTL_IDX_FILTER] = filter_buff;
			}
			char filter_id[2] = { get_filter(args->desc->cmd, args->argv[i])->id, 0 };
			if (filter_id[0] == '\0') {
				log_error("unknown filter: %s", args->argv[i]);
				return KNOT_EINVAL;
			}
			if (strchr(filter_buff, filter_id[0]) == NULL) {
				assert(strlen(filter_buff) < MAX_FILTERS);
				strlcat(filter_buff, filter_id, sizeof(filter_buff));
			}
			if (get_filter(args->desc->cmd, args->argv[i])->with_data) {
				data[KNOT_CTL_IDX_DATA] = args->argv[++i];
			}
		}
	}

	// Second, process zones.
	int ret;
	int sentzones = 0;
	bool twodash = false;
	for (int i = 0; i < args->argc; i++) {
		// Skip filters.
		if (args->argv[i][0] == '+') {
			if (get_filter(args->desc->cmd, args->argv[i])->with_data) {
				i++;
			}
			continue;
		}

		if (strcmp(args->argv[i], "--") != 0) {
			data[KNOT_CTL_IDX_ZONE] = args->argv[i];
			CTL_SEND_DATA
			sentzones++;
		} else {
			twodash = true;
		}
	}

	if ((args->desc->flags & CMD_FREQ_ZONE) && sentzones == 0 && !twodash) {
		log_error("zone must be specified (or -- for all zones)");
		return KNOT_EDENIED;
	}

	if (sentzones == 0) {
		CTL_SEND_DATA
	}
	CTL_SEND_BLOCK

	return ctl_receive(args);
}

static int set_rdata(cmd_args_t *args, int pos, char *rdata, size_t rdata_len)
{
	rdata[0] = '\0';

	for (int i = pos; i < args->argc; i++) {
		if (i > pos && strlcat(rdata, " ", rdata_len) >= rdata_len) {
			return KNOT_ESPACE;
		}
		if (strlcat(rdata, args->argv[i], rdata_len) >= rdata_len) {
			return KNOT_ESPACE;
		}
	}

	return KNOT_EOK;
}

static int set_node_items(cmd_args_t *args, knot_ctl_data_t *data, char *rdata,
                          size_t rdata_len)
{
	int min_args, max_args;
	switch (args->desc->cmd) {
	case CTL_ZONE_READ:
	case CTL_ZONE_GET:   min_args = 1; max_args =  3; break;
	case CTL_ZONE_DIFF:  min_args = 1; max_args =  1; break;
	case CTL_ZONE_SET:   min_args = 3; max_args = -1; break;
	case CTL_ZONE_UNSET: min_args = 2; max_args = -1; break;
	default:
		assert(0);
		return KNOT_EINVAL;
	}

	// Check the number of arguments.
	int ret = check_args(args, min_args, max_args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	int idx = 0;

	// Set ZONE name.
	assert(args->argc > idx);
	if (strcmp(args->argv[idx], "--") != 0) {
		(*data)[KNOT_CTL_IDX_ZONE] = args->argv[idx];
	}
	idx++;

	// Set OWNER name if specified.
	if (args->argc > idx) {
		(*data)[KNOT_CTL_IDX_OWNER] = args->argv[idx];
		idx++;
	}

	// Set TTL only with an editing operation.
	if (args->argc > idx) {
		uint32_t num;
		uint16_t type;
		if (knot_rrtype_from_string(args->argv[idx], &type) != 0 &&
		    str_to_u32(args->argv[idx], &num) == KNOT_EOK) {
			switch (args->desc->cmd) {
			case CTL_ZONE_SET:
			case CTL_ZONE_UNSET:
				(*data)[KNOT_CTL_IDX_TTL] = args->argv[idx];
				idx++;
				break;
			default:
				break;
			}
		}
	}

	// Set record TYPE if specified.
	if (args->argc > idx) {
		(*data)[KNOT_CTL_IDX_TYPE] = args->argv[idx];
		idx++;
	}

	// Set record DATA if specified.
	if (args->argc > idx) {
		ret = set_rdata(args, idx, rdata, rdata_len);
		if (ret != KNOT_EOK) {
			return ret;
		}
		(*data)[KNOT_CTL_IDX_DATA] = rdata;
	}

	return KNOT_EOK;
}

static int cmd_zone_node_ctl(cmd_args_t *args)
{
	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->flags,
	};

	char rdata[65536]; // Maximum item size in libknot control interface.

	int ret = set_node_items(args, &data, rdata, sizeof(rdata));
	if (ret != KNOT_EOK) {
		return ret;
	}

	CTL_SEND_DATA
	CTL_SEND_BLOCK

	return ctl_receive(args);
}

static int cmd_conf_init(cmd_args_t *args)
{
	int ret = check_args(args, 0, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = conf_db_check(conf(), &conf()->read_txn);
	if ((ret >= KNOT_EOK || ret == KNOT_CONF_EVERSION)) {
		if (ret != KNOT_EOK && !args->force) {
			log_error("use force option to overwrite the existing "
			          "destination and ensure the server is not running!");
			return KNOT_EDENIED;
		}

		ret = conf_import(conf(), "", false, false);
	}

	if (ret == KNOT_EOK) {
		log_info("OK");
	} else {
		log_error("init (%s)", knot_strerror(ret));
	}

	return ret;
}

static int conf_check_group(const yp_item_t *group, const uint8_t *id, size_t id_len)
{
	knotd_conf_check_extra_t extra = {
		.conf = conf(),
		.txn = &conf()->read_txn,
		.check = true
	};
	knotd_conf_check_args_t args = {
		.id = id,
		.id_len = id_len,
		.extra = &extra
	};

	bool non_empty = false;
	bool error = false;

	// Check the group sub-items.
	for (yp_item_t *item = group->sub_items; item->name != NULL; item++) {
		args.item = item;

		conf_val_t bin;
		conf_db_get(conf(), &conf()->read_txn, group->name, item->name,
		            id, id_len, &bin);
		if (bin.code == KNOT_ENOENT) {
			continue;
		} else if (bin.code != KNOT_EOK) {
			log_error("failed to read the configuration DB (%s)",
			          knot_strerror(bin.code));
			return bin.code;
		}

		non_empty = true;

		// Check the item value(s).
		size_t values = conf_val_count(&bin);
		for (size_t i = 1; i <= values; i++) {
			conf_val(&bin);
			args.data = bin.data;
			args.data_len = bin.len;

			int ret = conf_exec_callbacks(&args);
			if (ret != KNOT_EOK) {
				log_error("config, item '%s%s%s%s.%s' (%s)",
				          group->name + 1,
				          (id != NULL ? "[" : ""),
				          (id != NULL ? (const char *)id  : ""),
				          (id != NULL ? "]" : ""),
				          item->name + 1,
				          args.err_str);
				error = true;
			}
			if (values > 1) {
				conf_val_next(&bin);
			}
		}
	}

	// Check the group item itself.
	if (id != NULL || non_empty) {
		args.item = group;
		args.data = NULL;
		args.data_len = 0;

		int ret = conf_exec_callbacks(&args);
		if (ret != KNOT_EOK) {
			log_error("config, section '%s%s%s%s' (%s)",
			          group->name + 1,
			          (id != NULL ? "[" : ""),
			          (id != NULL ? (const char *)id  : ""),
			          (id != NULL ? "]" : ""),
			          args.err_str);
			error = true;
		}
	}

	return error ? KNOT_ESEMCHECK : KNOT_EOK;
}

static int cmd_conf_check(cmd_args_t *args) // Similar to conf_io_check().
{
	int ret = check_args(args, 0, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (conf()->filename == NULL) { // Config file already checked.
		for (yp_item_t *item = conf()->schema; item->name != NULL; item++) {
			// Skip include item.
			if (item->type != YP_TGRP) {
				continue;
			}

			// Group without identifiers.
			if (!(item->flags & YP_FMULTI)) {
				ret = conf_check_group(item, NULL, 0);
				if (ret != KNOT_EOK) {
					return ret;
				}
				continue;
			}

			conf_iter_t iter;
			ret = conf_db_iter_begin(conf(), &conf()->read_txn, item->name, &iter);
			if (ret == KNOT_ENOENT) {
				continue;
			} else if (ret != KNOT_EOK) {
				log_error("failed to read the configuration DB (%s)",
				          knot_strerror(ret));
				return ret;
			}

			while (ret == KNOT_EOK) {
				const uint8_t *id;
				size_t id_len;
				ret = conf_db_iter_id(conf(), &iter, &id, &id_len);
				if (ret != KNOT_EOK) {
					conf_db_iter_finish(conf(), &iter);
					log_error("failed to read the configuration DB (%s)",
					          knot_strerror(ret));
					return ret;
				}

				// Check the group with this identifier.
				ret = conf_check_group(item, id, id_len);
				if (ret != KNOT_EOK) {
					conf_db_iter_finish(conf(), &iter);
					return ret;
				}

				ret = conf_db_iter_next(conf(), &iter);
			}
			if (ret != KNOT_EOF) {
				log_error("failed to read the configuration DB (%s)",
				          knot_strerror(ret));
				return ret;
			}
		}
	}

	log_info("Configuration is valid");

	return KNOT_EOK;
}

static int cmd_conf_import(cmd_args_t *args)
{
	int ret = check_args(args, 1, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = conf_db_check(conf(), &conf()->read_txn);
	if ((ret >= KNOT_EOK || ret == KNOT_CONF_EVERSION)) {
		if (ret != KNOT_EOK && !args->force) {
			log_error("use force option to overwrite the existing "
			          "destination and ensure the server is not running!");
			return KNOT_EDENIED;
		}

		log_debug("importing confdb from file '%s'", args->argv[0]);

		ret = conf_import(conf(), args->argv[0], true, false);
	}

	if (ret == KNOT_EOK) {
		log_info("OK");
	} else {
		log_error("import (%s)", knot_strerror(ret));
	}

	return ret;
}

static int cmd_conf_export(cmd_args_t *args)
{
	int ret = check_args(args, 0, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Stdout is the default output file.
	const char *file_name = NULL;
	if (args->argc > 0) {
		file_name = args->argv[0];
		log_debug("exporting confdb into file '%s'", file_name);
	}

	ret = conf_export(conf(), file_name, YP_SNONE);

	if (ret == KNOT_EOK) {
		if (args->argc > 0) {
			log_info("OK");
		}
	} else {
		log_error("export (%s)", knot_strerror(ret));
	}

	return ret;
}

static int cmd_conf_ctl(cmd_args_t *args)
{
	// Check the number of arguments.
	int ret = check_conf_args(args);
	if (ret != KNOT_EOK) {
		return ret;
	}

	char flags[16] = "";
	strlcat(flags, args->flags, sizeof(flags));
	if (args->desc->flags & CMD_FLIST_SCHEMA) {
		strlcat(flags, CTL_FLAG_LIST_SCHEMA, sizeof(flags));
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = flags,
	};

	// Send the command without parameters.
	if (args->argc == 0) {
		CTL_SEND_DATA
	// Set the first item argument.
	} else {
		ret = get_conf_key(args->argv[0], &data);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Send if only one argument or item without values.
		if (args->argc == 1 || !(args->desc->flags & CMD_FOPT_DATA)) {
			CTL_SEND_DATA
		}
	}

	// Send the item values or the other items.
	for (int i = 1; i < args->argc; i++) {
		if (args->desc->flags & CMD_FOPT_DATA) {
			data[KNOT_CTL_IDX_DATA] = args->argv[i];
		} else {
			ret = get_conf_key(args->argv[i], &data);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		CTL_SEND_DATA
	}

	CTL_SEND_BLOCK

	return ctl_receive(args);
}

const cmd_desc_t cmd_table[] = {
	{ CMD_EXIT,            NULL,              CTL_NONE },

	{ CMD_STATUS,          cmd_ctl,           CTL_STATUS,          CMD_FOPT_DATA},
	{ CMD_STOP,            cmd_ctl,           CTL_STOP },
	{ CMD_RELOAD,          cmd_ctl,           CTL_RELOAD },
	{ CMD_STATS,           cmd_stats_ctl,     CTL_STATS },

	{ CMD_ZONE_CHECK,      cmd_zone_check,        CTL_NONE,            CMD_FOPT_ZONE | CMD_FREAD },
	{ CMD_ZONE_STATUS,     cmd_zone_filter_ctl,   CTL_ZONE_STATUS,     CMD_FOPT_ZONE },
	{ CMD_ZONE_RELOAD,     cmd_zone_ctl,          CTL_ZONE_RELOAD,     CMD_FOPT_ZONE },
	{ CMD_ZONE_REFRESH,    cmd_zone_ctl,          CTL_ZONE_REFRESH,    CMD_FOPT_ZONE },
	{ CMD_ZONE_RETRANSFER, cmd_zone_ctl,          CTL_ZONE_RETRANSFER, CMD_FOPT_ZONE },
	{ CMD_ZONE_NOTIFY,     cmd_zone_ctl,          CTL_ZONE_NOTIFY,     CMD_FOPT_ZONE },
	{ CMD_ZONE_FLUSH,      cmd_zone_filter_ctl,   CTL_ZONE_FLUSH,      CMD_FOPT_ZONE },
	{ CMD_ZONE_BACKUP,     cmd_zone_filter_ctl,   CTL_ZONE_BACKUP,     CMD_FOPT_ZONE },
	{ CMD_ZONE_RESTORE,    cmd_zone_filter_ctl,   CTL_ZONE_RESTORE,    CMD_FOPT_ZONE },
	{ CMD_ZONE_SIGN,       cmd_zone_ctl,          CTL_ZONE_SIGN,       CMD_FOPT_ZONE },
	{ CMD_ZONE_KEYS_LOAD,  cmd_zone_ctl,          CTL_ZONE_KEYS_LOAD,  CMD_FOPT_ZONE },
	{ CMD_ZONE_KEY_ROLL,   cmd_zone_key_roll_ctl, CTL_ZONE_KEY_ROLL,   CMD_FREQ_ZONE },
	{ CMD_ZONE_KSK_SBM,    cmd_zone_ctl,          CTL_ZONE_KSK_SBM,    CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_FREEZE,     cmd_zone_ctl,          CTL_ZONE_FREEZE,     CMD_FOPT_ZONE },
	{ CMD_ZONE_THAW,       cmd_zone_ctl,          CTL_ZONE_THAW,       CMD_FOPT_ZONE },
	{ CMD_ZONE_XFR_FREEZE, cmd_zone_ctl,          CTL_ZONE_XFR_FREEZE, CMD_FOPT_ZONE },
	{ CMD_ZONE_XFR_THAW,   cmd_zone_ctl,          CTL_ZONE_XFR_THAW,   CMD_FOPT_ZONE },

	{ CMD_ZONE_READ,       cmd_zone_node_ctl,   CTL_ZONE_READ,       CMD_FREQ_ZONE },
	{ CMD_ZONE_BEGIN,      cmd_zone_ctl,        CTL_ZONE_BEGIN,      CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_COMMIT,     cmd_zone_ctl,        CTL_ZONE_COMMIT,     CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_ABORT,      cmd_zone_ctl,        CTL_ZONE_ABORT,      CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_DIFF,       cmd_zone_node_ctl,   CTL_ZONE_DIFF,       CMD_FREQ_ZONE },
	{ CMD_ZONE_GET,        cmd_zone_node_ctl,   CTL_ZONE_GET,        CMD_FREQ_ZONE },
	{ CMD_ZONE_SET,        cmd_zone_node_ctl,   CTL_ZONE_SET,        CMD_FREQ_ZONE },
	{ CMD_ZONE_UNSET,      cmd_zone_node_ctl,   CTL_ZONE_UNSET,      CMD_FREQ_ZONE },
	{ CMD_ZONE_PURGE,      cmd_zone_filter_ctl, CTL_ZONE_PURGE,      CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_STATS,      cmd_stats_ctl,       CTL_ZONE_STATS,      CMD_FREQ_ZONE },

	{ CMD_CONF_INIT,       cmd_conf_init,     CTL_NONE,            CMD_FWRITE },
	{ CMD_CONF_CHECK,      cmd_conf_check,    CTL_NONE,            CMD_FREAD  | CMD_FREQ_MOD },
	{ CMD_CONF_IMPORT,     cmd_conf_import,   CTL_NONE,            CMD_FWRITE | CMD_FOPT_MOD },
	{ CMD_CONF_EXPORT,     cmd_conf_export,   CTL_NONE,            CMD_FREAD  | CMD_FOPT_MOD },
	{ CMD_CONF_LIST,       cmd_conf_ctl,      CTL_CONF_LIST,       CMD_FOPT_ITEM | CMD_FLIST_SCHEMA },
	{ CMD_CONF_READ,       cmd_conf_ctl,      CTL_CONF_READ,       CMD_FOPT_ITEM },
	{ CMD_CONF_BEGIN,      cmd_conf_ctl,      CTL_CONF_BEGIN },
	{ CMD_CONF_COMMIT,     cmd_conf_ctl,      CTL_CONF_COMMIT },
	{ CMD_CONF_ABORT,      cmd_conf_ctl,      CTL_CONF_ABORT },
	{ CMD_CONF_DIFF,       cmd_conf_ctl,      CTL_CONF_DIFF,       CMD_FOPT_ITEM | CMD_FREQ_TXN },
	{ CMD_CONF_GET,        cmd_conf_ctl,      CTL_CONF_GET,        CMD_FOPT_ITEM | CMD_FREQ_TXN },
	{ CMD_CONF_SET,        cmd_conf_ctl,      CTL_CONF_SET,        CMD_FREQ_ITEM | CMD_FOPT_DATA | CMD_FREQ_TXN | CMD_FLIST_SCHEMA},
	{ CMD_CONF_UNSET,      cmd_conf_ctl,      CTL_CONF_UNSET,      CMD_FOPT_ITEM | CMD_FOPT_DATA | CMD_FREQ_TXN },
	{ NULL }
};

static const cmd_help_t cmd_help_table[] = {
	{ CMD_EXIT,            "",                                           "Exit interactive mode." },
	{ "",                  "",                                           "" },
	{ CMD_STATUS,          "[<detail>]",                                 "Check if the server is running." },
	{ CMD_STOP,            "",                                           "Stop the server if running." },
	{ CMD_RELOAD,          "",                                           "Reload the server configuration and modified zones." },
	{ CMD_STATS,           "[<module>[.<counter>]]",                     "Show global statistics counter(s)." },
	{ "",                  "",                                           "" },
	{ CMD_ZONE_CHECK,      "[<zone>...]",                                "Check if the zone can be loaded. (*)" },
	{ CMD_ZONE_STATUS,     "[<zone>...] [<filter>...]",                  "Show the zone status." },
	{ CMD_ZONE_RELOAD,     "[<zone>...]",                                "Reload a zone from a disk. (#)" },
	{ CMD_ZONE_REFRESH,    "[<zone>...]",                                "Force slave zone refresh. (#)" },
	{ CMD_ZONE_NOTIFY,     "[<zone>...]",                                "Send a NOTIFY message to all configured remotes. (#)" },
	{ CMD_ZONE_RETRANSFER, "[<zone>...]",                                "Force slave zone retransfer (no serial check). (#)" },
	{ CMD_ZONE_FLUSH,      "[<zone>...] [<filter>...]",                  "Flush zone journal into the zone file. (#)" },
	{ CMD_ZONE_BACKUP,     "[<zone>...] [<filter>...] +backupdir <dir>", "Backup zone data and metadata. (#)" },
	{ CMD_ZONE_RESTORE,    "[<zone>...] [<filter>...] +backupdir <dir>", "Restore zone data and metadata. (#)" },
	{ CMD_ZONE_SIGN,       "[<zone>...]",                                "Re-sign the automatically signed zone. (#)" },
	{ CMD_ZONE_KEYS_LOAD,  "[<zone>...]",                                "Re-load keys from KASP database, sign the zone. (#)" },
	{ CMD_ZONE_KEY_ROLL,   " <zone> ksk|zsk",                            "Trigger immediate key rollover. (#)" },
	{ CMD_ZONE_KSK_SBM,    " <zone>...",                                 "When KSK submission, confirm parent's DS presence. (#)" },
	{ CMD_ZONE_FREEZE,     "[<zone>...]",                                "Temporarily postpone automatic zone-changing events. (#)" },
	{ CMD_ZONE_THAW,       "[<zone>...]",                                "Dismiss zone freeze. (#)" },
	{ CMD_ZONE_XFR_FREEZE, "[<zone>...]",                                "Temporarily disable outgoing AXFR/IXFR. (#)" },
	{ CMD_ZONE_XFR_THAW,   "[<zone>...]",                                "Dismiss outgoing XFR freeze. (#)" },
	{ "",                  "",                                           "" },
	{ CMD_ZONE_READ,       "<zone> [<owner> [<type>]]",                  "Get zone data that are currently being presented." },
	{ CMD_ZONE_BEGIN,      "<zone>...",                                  "Begin a zone transaction." },
	{ CMD_ZONE_COMMIT,     "<zone>...",                                  "Commit the zone transaction." },
	{ CMD_ZONE_ABORT,      "<zone>...",                                  "Abort the zone transaction." },
	{ CMD_ZONE_DIFF,       "<zone>",                                     "Get zone changes within the transaction." },
	{ CMD_ZONE_GET,        "<zone> [<owner> [<type>]]",                  "Get zone data within the transaction." },
	{ CMD_ZONE_SET,        "<zone>  <owner> [<ttl>] <type> <rdata>",     "Add zone record within the transaction." },
	{ CMD_ZONE_UNSET,      "<zone>  <owner> [<type> [<rdata>]]",         "Remove zone data within the transaction." },
	{ CMD_ZONE_PURGE,      "<zone>... [<filter>...]",                    "Purge zone data, zone file, journal, timers, and KASP data. (#)" },
	{ CMD_ZONE_STATS,      "<zone> [<module>[.<counter>]]",              "Show zone statistics counter(s)."},
	{ "",                  "",                                           "" },
	{ CMD_CONF_INIT,       "",                                           "Initialize the confdb. (*)" },
	{ CMD_CONF_CHECK,      "",                                           "Check the server configuration. (*)" },
	{ CMD_CONF_IMPORT,     " <filename>",                                "Import a config file into the confdb. (*)" },
	{ CMD_CONF_EXPORT,     "[<filename>]",                               "Export the confdb into a config file or stdout. (*)" },
	{ CMD_CONF_LIST,       "[<item>...]",                                "List the confdb sections or section items." },
	{ CMD_CONF_READ,       "[<item>...]",                                "Get the item from the active confdb." },
	{ CMD_CONF_BEGIN,      "",                                           "Begin a writing confdb transaction." },
	{ CMD_CONF_COMMIT,     "",                                           "Commit the confdb transaction." },
	{ CMD_CONF_ABORT,      "",                                           "Rollback the confdb transaction." },
	{ CMD_CONF_DIFF,       "[<item>...]",                                "Get the item difference within the transaction." },
	{ CMD_CONF_GET,        "[<item>...]",                                "Get the item data within the transaction." },
	{ CMD_CONF_SET,        " <item>  [<data>...]",                       "Set the item data within the transaction." },
	{ CMD_CONF_UNSET,      "[<item>] [<data>...]",                       "Unset the item data within the transaction." },
	{ NULL }
};

void print_commands(void)
{
	printf("\nActions:\n");

	for (const cmd_help_t *cmd = cmd_help_table; cmd->name != NULL; cmd++) {
		printf(" %-18s %-38s %s\n", cmd->name, cmd->params, cmd->desc);
	}

	printf("\n"
	       "Note:\n"
	       " Use @ owner to denote the zone name.\n"
	       " Empty or '--' <zone> parameter means all zones or all zones with a transaction.\n"
	       " Type <item> parameter in the form of <section>[<identifier>].<name>.\n"
	       " (*) indicates a local operation which requires a configuration.\n"
	       " (#) indicates an optionally blocking operation.\n"
	       " The '-b' and '-f' options can be placed right after the command name.\n");
}
