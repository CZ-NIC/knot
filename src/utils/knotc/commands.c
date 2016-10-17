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
#include "contrib/openbsd/strlcat.h"
#include "utils/knotc/commands.h"
#include "utils/knotc/estimator.h"

#define CMD_EXIT		"exit"

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

#define CMD_ZONE_READ		"zone-read"
#define CMD_ZONE_BEGIN		"zone-begin"
#define CMD_ZONE_COMMIT		"zone-commit"
#define CMD_ZONE_ABORT		"zone-abort"
#define CMD_ZONE_DIFF		"zone-diff"
#define CMD_ZONE_GET		"zone-get"
#define CMD_ZONE_SET		"zone-set"
#define CMD_ZONE_UNSET		"zone-unset"
#define CMD_ZONE_PURGE		"zone-purge"

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
	case CTL_ZONE_FLUSH:
	case CTL_ZONE_SIGN:
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
		if (data_type == KNOT_CTL_TYPE_DATA) {
			printf("%s%s%s%s%s%s%s%s%s%s%s%s%s",
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
			       (type  != NULL ? type       : ""));
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
	case CTL_CONF_COMMIT:
	case CTL_CONF_ABORT:
	case CTL_CONF_SET:
	case CTL_CONF_UNSET:
	case CTL_ZONE_RELOAD:
	case CTL_ZONE_REFRESH:
	case CTL_ZONE_RETRANSFER:
	case CTL_ZONE_FLUSH:
	case CTL_ZONE_SIGN:
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
	int ret = check_args(args, 0, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_ctl_data_t data = {
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->force ? CTL_FLAG_FORCE : NULL
	};

	// Send the command.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
	if (ret != KNOT_EOK) {
		log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
		return ret;
	}

	// Finish the input block.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_BLOCK, NULL);
	if (ret != KNOT_EOK) {
		log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
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
		.node_table = hattrie_create(&mem_ctx),
	};

	char buff[KNOT_DNAME_TXT_MAXLEN + 1];
	char *zone_name = knot_dname_to_str(buff, dname, sizeof(buff));
	char *zone_file = conf_zonefile(conf(), dname);
	zs_scanner_t *zs = malloc(sizeof(zs_scanner_t));

	if (est.node_table == NULL || zone_name == NULL || zone_file == NULL ||
	    zs == NULL) {
		log_zone_error(dname, "%s", knot_strerror(KNOT_ENOMEM));
		hattrie_free(est.node_table);
		free(zone_file);
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
		zs_deinit(zs);
		free(zs);
		return KNOT_EPARSEFAIL;
	}
	free(zone_file);
	zs_deinit(zs);
	free(zs);

	// Cleanup.
	hattrie_apply_rev(est.node_table, estimator_free_trie_node, NULL);
	hattrie_free(est.node_table);

	double zone_size = (est.rdata_size + est.node_size + est.dname_size +
	                    malloc_size) / (1024.0 * 1024.0);

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
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->force ? CTL_FLAG_FORCE : NULL
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
		int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
			return ret;
		}
	}
	for (int i = 0; i < args->argc; i++) {
		data[KNOT_CTL_IDX_ZONE] = args->argv[i];

		int ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
			return ret;
		}
	}

	// Finish the input block.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_BLOCK, NULL);
	if (ret != KNOT_EOK) {
		log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
		return ret;
	}

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
		uint16_t type;
		if (knot_rrtype_from_string(args->argv[idx], &type) != 0) {
			switch (args->desc->cmd) {
			case CTL_ZONE_SET:
			case CTL_ZONE_UNSET:
				(*data)[KNOT_CTL_IDX_TTL] = args->argv[idx];
				idx++;
				break;
			default:
				return KNOT_EINVAL;
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
		[KNOT_CTL_IDX_FLAGS] = args->force ? CTL_FLAG_FORCE : NULL
	};

	char rdata[65536]; // Maximum item size in libknot control interface.

	int ret = set_node_items(args, &data, rdata, sizeof(rdata));
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
	if (ret != KNOT_EOK) {
		log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
		return ret;
	}

	// Finish the input block.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_BLOCK, NULL);
	if (ret != KNOT_EOK) {
		log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
		return ret;
	}

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
	int ret = check_args(args, 0, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	log_info("Configuration is valid");

	return 0;
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
	int ret = check_args(args, 1, 1);
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
		[KNOT_CTL_IDX_CMD] = ctl_cmd_to_str(args->desc->cmd),
		[KNOT_CTL_IDX_FLAGS] = args->force ? CTL_FLAG_FORCE : NULL
	};

	// Send the command without parameters.
	if (args->argc == 0) {
		ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
			return ret;
		}
	// Set the first item argument.
	} else {
		ret = get_conf_key(args->argv[0], &data);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Send if only one argument or item without values.
		if (args->argc == 1 || !(args->desc->flags & CMD_FOPT_DATA)) {
			ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
			if (ret != KNOT_EOK) {
				log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
				return ret;
			}
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

		ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_DATA, &data);
		if (ret != KNOT_EOK) {
			log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
			return ret;
		}
	}

	// Finish the input block.
	ret = knot_ctl_send(args->ctl, KNOT_CTL_TYPE_BLOCK, NULL);
	if (ret != KNOT_EOK) {
		log_error(CTL_LOG_STR" (%s)", knot_strerror(ret));
		return ret;
	}

	return ctl_receive(args);
}

const cmd_desc_t cmd_table[] = {
	{ CMD_EXIT,            NULL,              CTL_NONE },

	{ CMD_STATUS,          cmd_ctl,           CTL_STATUS },
	{ CMD_STOP,            cmd_ctl,           CTL_STOP },
	{ CMD_RELOAD,          cmd_ctl,           CTL_RELOAD },

	{ CMD_ZONE_CHECK,      cmd_zone_check,    CTL_NONE,            CMD_FOPT_ZONE | CMD_FREAD },
	{ CMD_ZONE_MEMSTATS,   cmd_zone_memstats, CTL_NONE,            CMD_FOPT_ZONE | CMD_FREAD },
	{ CMD_ZONE_STATUS,     cmd_zone_ctl,      CTL_ZONE_STATUS,     CMD_FOPT_ZONE },
	{ CMD_ZONE_RELOAD,     cmd_zone_ctl,      CTL_ZONE_RELOAD,     CMD_FOPT_ZONE },
	{ CMD_ZONE_REFRESH,    cmd_zone_ctl,      CTL_ZONE_REFRESH,    CMD_FOPT_ZONE },
	{ CMD_ZONE_RETRANSFER, cmd_zone_ctl,      CTL_ZONE_RETRANSFER, CMD_FOPT_ZONE },
	{ CMD_ZONE_FLUSH,      cmd_zone_ctl,      CTL_ZONE_FLUSH,      CMD_FOPT_ZONE },
	{ CMD_ZONE_SIGN,       cmd_zone_ctl,      CTL_ZONE_SIGN,       CMD_FOPT_ZONE },

	{ CMD_ZONE_READ,       cmd_zone_node_ctl, CTL_ZONE_READ,       CMD_FREQ_ZONE },
	{ CMD_ZONE_BEGIN,      cmd_zone_ctl,      CTL_ZONE_BEGIN,      CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_COMMIT,     cmd_zone_ctl,      CTL_ZONE_COMMIT,     CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_ABORT,      cmd_zone_ctl,      CTL_ZONE_ABORT,      CMD_FREQ_ZONE | CMD_FOPT_ZONE },
	{ CMD_ZONE_DIFF,       cmd_zone_node_ctl, CTL_ZONE_DIFF,       CMD_FREQ_ZONE },
	{ CMD_ZONE_GET,        cmd_zone_node_ctl, CTL_ZONE_GET,        CMD_FREQ_ZONE },
	{ CMD_ZONE_SET,        cmd_zone_node_ctl, CTL_ZONE_SET,        CMD_FREQ_ZONE },
	{ CMD_ZONE_UNSET,      cmd_zone_node_ctl, CTL_ZONE_UNSET,      CMD_FREQ_ZONE },
	{ CMD_ZONE_PURGE,      cmd_zone_ctl,      CTL_ZONE_PURGE,      CMD_FREQ_ZONE },

	{ CMD_CONF_INIT,       cmd_conf_init,     CTL_NONE,            CMD_FWRITE },
	{ CMD_CONF_CHECK,      cmd_conf_check,    CTL_NONE,            CMD_FREAD },
	{ CMD_CONF_IMPORT,     cmd_conf_import,   CTL_NONE,            CMD_FWRITE },
	{ CMD_CONF_EXPORT,     cmd_conf_export,   CTL_NONE,            CMD_FREAD },
	{ CMD_CONF_LIST,       cmd_conf_ctl,      CTL_CONF_LIST,       CMD_FOPT_ITEM },
	{ CMD_CONF_READ,       cmd_conf_ctl,      CTL_CONF_READ,       CMD_FOPT_ITEM },
	{ CMD_CONF_BEGIN,      cmd_conf_ctl,      CTL_CONF_BEGIN },
	{ CMD_CONF_COMMIT,     cmd_conf_ctl,      CTL_CONF_COMMIT },
	{ CMD_CONF_ABORT,      cmd_conf_ctl,      CTL_CONF_ABORT },
	{ CMD_CONF_DIFF,       cmd_conf_ctl,      CTL_CONF_DIFF,       CMD_FOPT_ITEM | CMD_FREQ_TXN },
	{ CMD_CONF_GET,        cmd_conf_ctl,      CTL_CONF_GET,        CMD_FOPT_ITEM | CMD_FREQ_TXN },
	{ CMD_CONF_SET,        cmd_conf_ctl,      CTL_CONF_SET,        CMD_FREQ_ITEM | CMD_FOPT_DATA | CMD_FREQ_TXN },
	{ CMD_CONF_UNSET,      cmd_conf_ctl,      CTL_CONF_UNSET,      CMD_FOPT_ITEM | CMD_FOPT_DATA | CMD_FREQ_TXN },
	{ NULL }
};

static const cmd_help_t cmd_help_table[] = {
	{ CMD_EXIT,            "",                                       "Exit interactive mode." },
	{ "",                  "",                                       "" },
	{ CMD_STATUS,          "",                                       "Check if the server is running." },
	{ CMD_STOP,            "",                                       "Stop the server if running." },
	{ CMD_RELOAD,          "",                                       "Reload the server configuration and modified zones." },
	{ "",                  "",                                       "" },
	{ CMD_ZONE_CHECK,      "[<zone>...]",                            "Check if the zone can be loaded. (*)" },
	{ CMD_ZONE_MEMSTATS,   "[<zone>...]",                            "Estimate memory use for the zone. (*)" },
	{ CMD_ZONE_STATUS,     "[<zone>...]",                            "Show the zone status." },
	{ CMD_ZONE_RELOAD,     "[<zone>...]",                            "Reload a zone from a disk." },
	{ CMD_ZONE_REFRESH,    "[<zone>...]",                            "Force slave zone refresh." },
	{ CMD_ZONE_RETRANSFER, "[<zone>...]",                            "Force slave zone retransfer (no serial check)." },
	{ CMD_ZONE_FLUSH,      "[<zone>...]",                            "Flush zone journal into the zone file." },
	{ CMD_ZONE_SIGN,       "[<zone>...]",                            "Re-sign the automatically signed zone." },
	{ "",                  "",                                       "" },
	{ CMD_ZONE_READ,       "<zone> [<owner> [<type>]]",              "Get zone data that are currently being presented." },
	{ CMD_ZONE_BEGIN,      "<zone>...",                              "Begin a zone transaction." },
	{ CMD_ZONE_COMMIT,     "<zone>...",                              "Commit the zone transaction." },
	{ CMD_ZONE_ABORT,      "<zone>...",                              "Abort the zone transaction." },
	{ CMD_ZONE_DIFF,       "<zone>",                                 "Get zone changes within the transaction." },
	{ CMD_ZONE_GET,        "<zone> [<owner> [<type>]]",              "Get zone data within the transaction." },
	{ CMD_ZONE_SET,        "<zone>  <owner> [<ttl>] <type> <rdata>", "Add zone record within the transaction." },
	{ CMD_ZONE_UNSET,      "<zone>  <owner> [<type> [<rdata>]]",     "Remove zone data within the transaction." },
	{ CMD_ZONE_PURGE,      "<zone>...",                              "Purge zone data, zone file, and zone journal." },
	{ "",                  "",                                       "" },
	{ CMD_CONF_INIT,       "",                                       "Initialize the confdb. (*)" },
	{ CMD_CONF_CHECK,      "",                                       "Check the server configuration. (*)" },
	{ CMD_CONF_IMPORT,     "<filename>",                             "Import a config file into the confdb. (*)" },
	{ CMD_CONF_EXPORT,     "<filename>",                             "Export the confdb into a config file. (*)" },
	{ CMD_CONF_LIST,       "[<item>...]",                            "List the confdb sections or section items." },
	{ CMD_CONF_READ,       "[<item>...]",                            "Get the item from the active confdb." },
	{ CMD_CONF_BEGIN,      "",                                       "Begin a writing confdb transaction." },
	{ CMD_CONF_COMMIT,     "",                                       "Commit the confdb transaction." },
	{ CMD_CONF_ABORT,      "",                                       "Rollback the confdb transaction." },
	{ CMD_CONF_DIFF,       "[<item>...]",                            "Get the item difference within the transaction." },
	{ CMD_CONF_GET,        "[<item>...]",                            "Get the item data within the transaction." },
	{ CMD_CONF_SET,        " <item>  [<data>...]",                   "Set the item data within the transaction." },
	{ CMD_CONF_UNSET,      "[<item>] [<data>...]",                   "Unset the item data within the transaction." },
	{ NULL }
};

void print_commands(void)
{
	printf("\nActions:\n");

	for (const cmd_help_t *cmd = cmd_help_table; cmd->name != NULL; cmd++) {
		printf(" %-15s %-38s %s\n", cmd->name, cmd->params, cmd->desc);
	}

	printf("\n"
	       "Note:\n"
	       " Use @ owner to denote the zone name.\n"
	       " Empty or '--' <zone> parameter means all zones or all zones with a transaction.\n"
	       " Type <item> parameter in the form of <section>[<identifier>].<name>.\n"
	       " (*) indicates a local operation which requires a configuration.\n");
}
