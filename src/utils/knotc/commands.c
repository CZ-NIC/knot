/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/ctl/commands.h"
#include "knot/conf/conf.h"
#include "knot/conf/confdb.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-load.h"
#include "contrib/macros.h"
#include "contrib/string.h"
#include "utils/knotc/commands.h"
#include "utils/knotc/estimator.h"

#define CMD_STATUS		"status"
#define CMD_STOP		"stop"
#define CMD_RELOAD		"reload"

#define CMD_ZONE_CHECK		"zone-check"
#define CMD_ZONE_MEMSTATS	"zone-memstats"
#define CMD_ZONE_STATUS		"zone-status"
#define CMD_ZONE_RELOAD		"zone-reload"
#define CMD_ZONE_REFRESH	"zone-refresh"
#define CMD_ZONE_RETRANSFER	"zone-retransfer"
#define CMD_ZONE_FLUSH		"zone-flush"
#define CMD_ZONE_SIGN		"zone-sign"

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

static int check_args(cmd_args_t *args, unsigned count)
{
	if (args->argc == count) {
		return KNOT_EOK;
	}

	log_error("command requires %u arguments", count);

	return KNOT_EINVAL;
}

static int check_conf_args(cmd_args_t *args)
{
	// Mask relevant flags.
	cmd_conf_flag_t flags = args->desc->flags;
	flags &= CMD_CONF_FOPT_ITEM | CMD_CONF_FREQ_ITEM | CMD_CONF_FOPT_DATA;

	switch (args->argc) {
	case 0:
		if (flags == CMD_CONF_FNONE || (flags & CMD_CONF_FOPT_ITEM)) {
			return KNOT_EOK;
		}
		break;
	case 1:
		if (flags & (CMD_CONF_FOPT_ITEM | CMD_CONF_FREQ_ITEM)) {
			return KNOT_EOK;
		}
		break;
	default:
		if (flags != CMD_CONF_FNONE) {
			return KNOT_EOK;
		}
		break;
	}

	log_error("invalid number of arguments");

	return KNOT_EINVAL;
}

static int get_conf_key(char *key, knot_ctl_data_t *data)
{
	// Get key0.
	char *key0 = key;

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

static void format_data(ctl_cmd_t cmd, knot_ctl_type_t type, knot_ctl_data_t *data,
                        bool *empty)
{
	const char *error = (*data)[KNOT_CTL_IDX_ERROR];
	const char *key0  = (*data)[KNOT_CTL_IDX_SECTION];
	const char *key1  = (*data)[KNOT_CTL_IDX_ITEM];
	const char *id    = (*data)[KNOT_CTL_IDX_ID];
	const char *zone  = (*data)[KNOT_CTL_IDX_ZONE];
	const char *param = (*data)[KNOT_CTL_IDX_TYPE];
	const char *value = (*data)[KNOT_CTL_IDX_DATA];

	switch (cmd) {
	case CTL_STATUS:
	case CTL_STOP:
	case CTL_RELOAD:
	case CTL_CONF_BEGIN:
	case CTL_CONF_ABORT:
	case CTL_CONF_COMMIT:
		// Only error message is expected here.
		if (error != NULL) {
			printf("error: (%s)", error);
		}
		break;
	case CTL_ZONE_STATUS:
	case CTL_ZONE_RELOAD:
	case CTL_ZONE_REFRESH:
	case CTL_ZONE_RETRANSFER:
	case CTL_ZONE_FLUSH:
	case CTL_ZONE_SIGN:
		if (type == KNOT_CTL_TYPE_DATA) {
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
		if (param != NULL) {
			printf("%s %s: %s",
			       (type != KNOT_CTL_TYPE_DATA ? " |" : ""),
			       param, value);
		}
		break;
	case CTL_CONF_LIST:
	case CTL_CONF_READ:
	case CTL_CONF_DIFF:
	case CTL_CONF_GET:
	case CTL_CONF_SET:
	case CTL_CONF_UNSET:
		if (type == KNOT_CTL_TYPE_DATA) {
			printf("%s%s%s%s%s%s%s%s%s%s%s%s",
			       (!(*empty)     ? "\n"       : ""),
			       (error != NULL ? "error: (" : ""),
			       (error != NULL ? error      : ""),
			       (error != NULL ? ") "       : ""),
			       (param != NULL ? param      : ""),
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
	default:
		assert(0);
	}
}

static void format_block(ctl_cmd_t cmd, bool failed, bool empty)
{
	switch (cmd) {
	case CTL_STATUS:
		printf("%s\n", failed ? "" : "Running");
		break;
	case CTL_STOP:
		printf("%s\n", failed ? "" : "Stopped");
		break;
	case CTL_RELOAD:
		printf("%s\n", failed ? "" : "Reloaded");
		break;
	case CTL_CONF_BEGIN:
	case CTL_CONF_ABORT:
	case CTL_CONF_COMMIT:
	case CTL_CONF_SET:
	case CTL_CONF_UNSET:
	case CTL_ZONE_RELOAD:
	case CTL_ZONE_REFRESH:
	case CTL_ZONE_RETRANSFER:
	case CTL_ZONE_FLUSH:
	case CTL_ZONE_SIGN:
		printf("%s\n", failed ? "" : "OK");
		break;
	case CTL_ZONE_STATUS:
	case CTL_CONF_LIST:
	case CTL_CONF_READ:
	case CTL_CONF_DIFF:
	case CTL_CONF_GET:
		printf("%s", empty ? "" : "\n");
		break;
	default:
		break;
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
			log_error("failed to control (%s)", knot_strerror(ret));
			return ret;
		}

		switch (type) {
		case KNOT_CTL_TYPE_END:
			log_error("failed to control (%s)", knot_strerror(KNOT_EMALF));
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
		}

		if (data[KNOT_CTL_IDX_ERROR] != NULL) {
			failed = true;
		}
	}

	return KNOT_EOK;
}

static int cmd_ctl(cmd_args_t *args)
{
	int ret = check_args(args, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd)
	};

	// Send the command.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
	if (ret != KNOT_EOK) {
		log_error("failed to control (%s)", knot_strerror(ret));
		return ret;
	}

	// Finish the input block.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_BLOCK, NULL);
	if (ret != KNOT_EOK) {
		log_error("failed to control (%s)", knot_strerror(ret));
		return ret;
	}

	return ctl_receive(args);
}

static int zone_exec(cmd_args_t *args, int (*fcn)(const knot_dname_t *, void *),
                     void *data)
{
	bool failed = false;

	// Process specified zones.
	if (args->argc > 0) {
		uint8_t id[KNOT_DNAME_MAXLEN];

		for (int i = 0; i < args->argc; i++) {
			if (knot_dname_from_str(id, args->argv[i], sizeof(id)) == NULL ||
			    knot_dname_to_lower(id) != KNOT_EOK) {
				log_zone_str_error(args->argv[i], "invalid name");
				failed = true;
				continue;
			}

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
	UNUSED(data);

	zone_contents_t *contents;
	int ret = zone_load_contents(conf(), dname, &contents);
	if (ret == KNOT_EOK) {
		zone_contents_deep_free(&contents);
	}
	return ret;
}

static int cmd_zone_check(cmd_args_t *args)
{
	return zone_exec(args, zone_check, NULL);
}

static int zone_memstats(const knot_dname_t *dname, void *data)
{
	// Init malloc wrapper for trie size estimation.
	size_t malloc_size = 0;
	knot_mm_t mem_ctx = {
		.ctx = &malloc_size,
		.alloc = estimator_malloc,
		.free = estimator_free
	};

	// Init memory estimation context.
	zone_estim_t est = {
		.node_table = hattrie_create_n(TRIE_BUCKET_SIZE, &mem_ctx),
	};

	char *zone_name = knot_dname_to_str_alloc(dname);
	char *zone_file = conf_zonefile(conf(), dname);
	zs_scanner_t *zs = malloc(sizeof(zs_scanner_t));

	if (est.node_table == NULL || zone_name == NULL || zone_file == NULL ||
	    zs == NULL) {
		log_zone_error(dname, "%s", strerror(KNOT_ENOMEM));
		hattrie_free(est.node_table);
		free(zone_file);
		free(zone_name);
		free(zs);
		return KNOT_ENOMEM;
	}

	// Do a parser run, but do not actually create the zone.
	if (zs_init(zs, zone_name, KNOT_CLASS_IN, 3600) != 0 ||
	    zs_set_processing(zs, estimator_rrset_memsize_wrap, NULL, &est) != 0 ||
	    zs_set_input_file(zs, zone_file) != 0 ||
	    zs_parse_all(zs) != 0) {
		log_zone_error(dname, "failed to parse zone file '%s' (%s)",
		               zone_file, zs_errorname(zs->error.code));
		hattrie_apply_rev(est.node_table, estimator_free_trie_node, NULL);
		hattrie_free(est.node_table);
		free(zone_file);
		free(zone_name);
		zs_deinit(zs);
		free(zs);
		return KNOT_EPARSEFAIL;
	}
	free(zone_file);
	free(zone_name);
	zs_deinit(zs);
	free(zs);

	// Only size of ahtables inside trie's nodes is missing.
	assert(est.htable_size == 0);
	est.htable_size = estimator_trie_htable_memsize(est.node_table);

	// Cleanup.
	hattrie_apply_rev(est.node_table, estimator_free_trie_node, NULL);
	hattrie_free(est.node_table);

	double zone_size = (est.rdata_size + est.node_size + est.dname_size +
	                    est.htable_size + malloc_size) / (1024.0 * 1024.0);

	log_zone_info(dname, "%zu records, %.1f MiB memory",
	              est.record_count, zone_size);

	double *total_size = (double *)data;
	*total_size += zone_size;

	return KNOT_EOK;
}

static int cmd_zone_memstats(cmd_args_t *args)
{
	double total_size = 0;

	int ret = zone_exec(args, zone_memstats, &total_size);

	if (args->argc != 1) {
		log_info("Total %.1f MiB memory", total_size);
	}

	return ret;
}

static int cmd_zone_ctl(cmd_args_t *args)
{
	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd)
	};

	if (args->argc == 0) {
		int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error("failed to control (%s)", knot_strerror(ret));
			return ret;
		}
	}
	for (int i = 0; i < args->argc; i++) {
		data[KNOT_CTL_IDX_ZONE] = args->argv[i];

		int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error("failed to control (%s)", knot_strerror(ret));
			return ret;
		}
	}

	// Finish the input block.
	int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_BLOCK, NULL);
	if (ret != KNOT_EOK) {
		log_error("failed to control (%s)", knot_strerror(ret));
		return ret;
	}

	return ctl_receive(args);
}

static int cmd_conf_init(cmd_args_t *args)
{
	int ret = check_args(args, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = conf_db_check(conf(), &conf()->read_txn);
	if ((ret >= KNOT_EOK || ret == KNOT_CONF_EVERSION)) {
		if (ret != KNOT_EOK && !(args->flags & CMD_FFORCE)) {
			log_error("use force option to overwrite the existing "
			          "destination and ensure the server is not running!");
			return KNOT_EDENIED;
		}

		ret = conf_import(conf(), "", false);
	}

	if (ret == KNOT_EOK) {
		log_info("OK");
	} else {
		log_error("init (%s)", knot_strerror(ret));
	}

	return ret;
}

static int cmd_conf_check(cmd_args_t *args)
{
	int ret = check_args(args, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	log_info("Configuration is valid");

	return 0;
}

static int cmd_conf_import(cmd_args_t *args)
{
	int ret = check_args(args, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = conf_db_check(conf(), &conf()->read_txn);
	if ((ret >= KNOT_EOK || ret == KNOT_CONF_EVERSION)) {
		if (ret != KNOT_EOK && !(args->flags & CMD_FFORCE)) {
			log_error("use force option to overwrite the existing "
			          "destination and ensure the server is not running!");
			return KNOT_EDENIED;
		}

		log_debug("importing confdb from file '%s'", args->argv[0]);

		ret = conf_import(conf(), args->argv[0], true);
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
	int ret = check_args(args, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	log_debug("exporting confdb into file '%s'", args->argv[0]);

	ret = conf_export(conf(), args->argv[0], YP_SNONE);

	if (ret == KNOT_EOK) {
		log_info("OK");
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

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd)
	};

	// Send the command without parameters.
	if (args->argc == 0) {
		ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error("failed to control (%s)", knot_strerror(ret));
			return ret;
		}
	// Set the first item argument.
	} else {
		ret = get_conf_key(args->argv[0], &data);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Send if only one argument or item without values.
		if (args->argc == 1 || !(args->desc->flags & CMD_CONF_FOPT_DATA)) {
			ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
			if (ret != KNOT_EOK) {
				log_error("failed to control (%s)", knot_strerror(ret));
				return ret;
			}
		}
	}

	// Send the item values or the other items.
	for (int i = 1; i < args->argc; i++) {
		if (args->desc->flags & CMD_CONF_FOPT_DATA) {
			data[KNOT_CTL_IDX_DATA] = args->argv[i];
		} else {
			ret = get_conf_key(args->argv[i], &data);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error("failed to control (%s)", knot_strerror(ret));
			return ret;
		}
	}

	// Finish the input block.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_BLOCK, NULL);
	if (ret != KNOT_EOK) {
		log_error("failed to control (%s)", knot_strerror(ret));
		return ret;
	}

	return ctl_receive(args);
}

const cmd_desc_t cmd_table[] = {
	{ CMD_STATUS,          cmd_ctl,           CTL_STATUS },
	{ CMD_STOP,            cmd_ctl,           CTL_STOP },
	{ CMD_RELOAD,          cmd_ctl,           CTL_RELOAD },

	{ CMD_ZONE_CHECK,      cmd_zone_check,    CTL_NONE,       CMD_CONF_FREAD },
	{ CMD_ZONE_MEMSTATS,   cmd_zone_memstats, CTL_NONE,       CMD_CONF_FREAD },
	{ CMD_ZONE_STATUS,     cmd_zone_ctl,      CTL_ZONE_STATUS },
	{ CMD_ZONE_RELOAD,     cmd_zone_ctl,      CTL_ZONE_RELOAD },
	{ CMD_ZONE_REFRESH,    cmd_zone_ctl,      CTL_ZONE_REFRESH },
	{ CMD_ZONE_RETRANSFER, cmd_zone_ctl,      CTL_ZONE_RETRANSFER },
	{ CMD_ZONE_FLUSH,      cmd_zone_ctl,      CTL_ZONE_FLUSH },
	{ CMD_ZONE_SIGN,       cmd_zone_ctl,      CTL_ZONE_SIGN },

	{ CMD_CONF_INIT,       cmd_conf_init,     CTL_NONE,       CMD_CONF_FWRITE },
	{ CMD_CONF_CHECK,      cmd_conf_check,    CTL_NONE,       CMD_CONF_FREAD },
	{ CMD_CONF_IMPORT,     cmd_conf_import,   CTL_NONE,       CMD_CONF_FWRITE },
	{ CMD_CONF_EXPORT,     cmd_conf_export,   CTL_NONE,       CMD_CONF_FREAD },
	{ CMD_CONF_LIST,       cmd_conf_ctl,      CTL_CONF_LIST,  CMD_CONF_FOPT_ITEM },
	{ CMD_CONF_READ,       cmd_conf_ctl,      CTL_CONF_READ,  CMD_CONF_FOPT_ITEM },
	{ CMD_CONF_BEGIN,      cmd_conf_ctl,      CTL_CONF_BEGIN },
	{ CMD_CONF_COMMIT,     cmd_conf_ctl,      CTL_CONF_COMMIT },
	{ CMD_CONF_ABORT,      cmd_conf_ctl,      CTL_CONF_ABORT },
	{ CMD_CONF_DIFF,       cmd_conf_ctl,      CTL_CONF_DIFF,  CMD_CONF_FOPT_ITEM },
	{ CMD_CONF_GET,        cmd_conf_ctl,      CTL_CONF_GET,   CMD_CONF_FOPT_ITEM },
	{ CMD_CONF_SET,        cmd_conf_ctl,      CTL_CONF_SET,   CMD_CONF_FREQ_ITEM | CMD_CONF_FOPT_DATA },
	{ CMD_CONF_UNSET,      cmd_conf_ctl,      CTL_CONF_UNSET, CMD_CONF_FOPT_ITEM | CMD_CONF_FOPT_DATA },
	{ NULL }
};

const cmd_desc_old_t cmd_table_old[] = {
	{ "checkzone",  CMD_ZONE_CHECK },
	{ "memstats",   CMD_ZONE_MEMSTATS },
	{ "zonestatus", CMD_ZONE_STATUS },
	{ "refresh",    CMD_ZONE_REFRESH },
	{ "flush",      CMD_ZONE_FLUSH },
	{ "signzone",   CMD_ZONE_SIGN },
	{ "checkconf",  CMD_CONF_CHECK },
	{ "conf-desc",  CMD_CONF_LIST },
	{ NULL }
};

const cmd_help_t cmd_help_table[] = {
	{ CMD_STATUS,          "",                     "Check if the server is running." },
	{ CMD_STOP,            "",                     "Stop the server if running." },
	{ CMD_RELOAD,          "",                     "Reload the server configuration and modified zones." },
	{ "",                  "",                     "" },
	{ CMD_ZONE_CHECK,      "[<zone>...]",          "Check if the zone can be loaded. (*)" },
	{ CMD_ZONE_MEMSTATS,   "[<zone>...]",          "Estimate memory use for the zone. (*)" },
	{ CMD_ZONE_STATUS,     "[<zone>...]",          "Show the zone status." },
	{ CMD_ZONE_RELOAD,     "[<zone>...]",          "Reload a zone from a disk." },
	{ CMD_ZONE_REFRESH,    "[<zone>...]",          "Force slave zone refresh." },
	{ CMD_ZONE_RETRANSFER, "[<zone>...]",          "Force slave zone retransfer (no serial check)." },
	{ CMD_ZONE_FLUSH,      "[<zone>...]",          "Flush zone journal into the zone file." },
	{ CMD_ZONE_SIGN,       "[<zone>...]",          "Re-sign the automatically signed zone." },
	{ "",                  "",                     "" },
	{ CMD_CONF_INIT,       "",                     "Initialize the confdb. (*)" },
	{ CMD_CONF_CHECK,      "",                     "Check the server configuration. (*)" },
	{ CMD_CONF_IMPORT,     "<filename>",           "Import a config file into the confdb. (*)" },
	{ CMD_CONF_EXPORT,     "<filename>",           "Export the confdb into a config file. (*)" },
	{ CMD_CONF_LIST,       "[<item>...]",          "List the confdb sections or section items." },
	{ CMD_CONF_READ,       "[<item>...]",          "Read the item from the active confdb." },
	{ CMD_CONF_BEGIN,      "",                     "Begin a writing confdb transaction." },
	{ CMD_CONF_COMMIT,     "",                     "Commit the confdb transaction." },
	{ CMD_CONF_ABORT,      "",                     "Rollback the confdb transaction." },
	{ CMD_CONF_DIFF,       "[<item>...]",          "Get the item difference in the transaction." },
	{ CMD_CONF_GET,        "[<item>...]",          "Get the item data from the transaction." },
	{ CMD_CONF_SET,        " <item>  [<data>...]", "Set the item data in the transaction." },
	{ CMD_CONF_UNSET,      "[<item>] [<data>...]", "Unset the item data in the transaction." },
	{ NULL }
};
