/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/ctl/remote.h"
#include "knot/conf/conf.h"
#include "knot/conf/confdb.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-load.h"
#include "contrib/string.h"
#include "utils/knotc/estimator.h"
#include "utils/knotc/commands.h"
#include "utils/knotc/remote.h"

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

static int cmd_status(cmd_args_t *args)
{
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_STATUS, KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_stop(cmd_args_t *args)
{
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_STOP, KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_reload(cmd_args_t *args)
{
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_RELOAD, KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_zone_status(cmd_args_t *args)
{
	return cmd_remote(args->socket, KNOT_CTL_ZONE_STATUS, KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_zone_reload(cmd_args_t *args)
{
	return cmd_remote(args->socket, KNOT_CTL_ZONE_RELOAD, KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_zone_refresh(cmd_args_t *args)
{
	return cmd_remote(args->socket, KNOT_CTL_ZONE_REFRESH, KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_zone_retransfer(cmd_args_t *args)
{
	return cmd_remote(args->socket, KNOT_CTL_ZONE_RETRANSFER, KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_zone_flush(cmd_args_t *args)
{
	return cmd_remote(args->socket, KNOT_CTL_ZONE_FLUSH, KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_zone_sign(cmd_args_t *args)
{
	return cmd_remote(args->socket, KNOT_CTL_ZONE_SIGN, KNOT_RRTYPE_NS,
	                  args->argc, args->argv);
}

static int cmd_conf_init(cmd_args_t *args)
{
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	int ret = conf_db_check(conf(), &conf()->read_txn);
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
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	log_info("Configuration is valid");

	return 0;
}

static int cmd_conf_import(cmd_args_t *args)
{
	if (args->argc != 1) {
		log_error("command takes one argument");
		return KNOT_EINVAL;
	}

	int ret = conf_db_check(conf(), &conf()->read_txn);
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
	if (args->argc != 1) {
		log_error("command takes one argument");
		return KNOT_EINVAL;
	}

	log_debug("exporting confdb into file '%s'", args->argv[0]);

	int ret = conf_export(conf(), args->argv[0], YP_SNONE);

	if (ret == KNOT_EOK) {
		log_info("OK");
	} else {
		log_error("export (%s)", knot_strerror(ret));
	}

	return ret;
}

static int cmd_conf_list(cmd_args_t *args)
{
	if (args->argc > 1) {
		log_error("command takes no or one argument");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_LIST, KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_read(cmd_args_t *args)
{
	if (args->argc > 1) {
		log_error("command takes no or one argument");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_READ, KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_begin(cmd_args_t *args)
{
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_BEGIN, KNOT_RRTYPE_TXT,
	                  0, NULL);
}

static int cmd_conf_commit(cmd_args_t *args)
{
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_COMMIT, KNOT_RRTYPE_TXT, 0, NULL);
}

static int cmd_conf_abort(cmd_args_t *args)
{
	if (args->argc > 0) {
		log_error("command does not take arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_ABORT, KNOT_RRTYPE_TXT,
	                  0, NULL);
}

static int cmd_conf_diff(cmd_args_t *args)
{
	if (args->argc > 1) {
		log_error("command takes no or one argument");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_DIFF, KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_get(cmd_args_t *args)
{
	if (args->argc > 1) {
		log_error("command takes no or one argument");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_GET, KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_set(cmd_args_t *args)
{
	if (args->argc < 1 || args->argc > 255) {
		log_error("command takes one or up to 255 arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_SET, KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static int cmd_conf_unset(cmd_args_t *args)
{
	if (args->argc > 255) {
		log_error("command doesn't take more than 255 arguments");
		return KNOT_EINVAL;
	}

	return cmd_remote(args->socket, KNOT_CTL_CONF_UNSET, KNOT_RRTYPE_TXT,
	                  args->argc, args->argv);
}

static bool fetch_zone(int argc, char *argv[], const knot_dname_t *name)
{
	bool found = false;

	int i = 0;
	while (!found && i < argc) {
		/* Convert the argument to dname */
		knot_dname_t *arg_name = knot_dname_from_str_alloc(argv[i]);

		if (arg_name != NULL) {
			(void)knot_dname_to_lower(arg_name);
			found = knot_dname_is_equal(name, arg_name);
		}

		i++;
		knot_dname_free(&arg_name, NULL);
	}

	return found;
}

static int cmd_zone_check(cmd_args_t *args)
{
	/* Zone checking */
	int rc = 0;

	/* Generate databases for all zones */
	for (conf_iter_t iter = conf_iter(conf(), C_ZONE); iter.code == KNOT_EOK;
	     conf_iter_next(conf(), &iter)) {
		conf_val_t id = conf_iter_id(conf(), &iter);

		/* Fetch zone */
		bool match = fetch_zone(args->argc, args->argv, conf_dname(&id));
		if (!match && args->argc > 0) {
			continue;
		}

		/* Create zone loader context. */
		zone_contents_t *contents;
		int ret = zone_load_contents(conf(), conf_dname(&id), &contents);
		if (ret != KNOT_EOK) {
			rc = 1;
			continue;
		}
		zone_contents_deep_free(&contents);
	}

	return rc;
}

static int cmd_zone_memstats(cmd_args_t *args)
{
	zs_scanner_t *zs = malloc(sizeof(zs_scanner_t));
	if (zs == NULL) {
		log_error("not enough memory");
		return 1;
	}

	/* Zone checking */
	double total_size = 0;

	/* Generate databases for all zones */
	for (conf_iter_t iter = conf_iter(conf(), C_ZONE); iter.code == KNOT_EOK;
	     conf_iter_next(conf(), &iter)) {
		conf_val_t id = conf_iter_id(conf(), &iter);

		/* Fetch zone */
		bool match = fetch_zone(args->argc, args->argv, conf_dname(&id));
		if (!match && args->argc > 0) {
			continue;
		}

		/* Init malloc wrapper for trie size estimation. */
		size_t malloc_size = 0;
		knot_mm_t mem_ctx = { .ctx = &malloc_size,
		                      .alloc = estimator_malloc,
		                      .free = estimator_free };

		/* Init memory estimation context. */
		zone_estim_t est = {.node_table = hattrie_create_n(TRIE_BUCKET_SIZE, &mem_ctx),
		                    .dname_size = 0, .node_size = 0,
		                    .htable_size = 0, .rdata_size = 0,
		                    .record_count = 0 };
		if (est.node_table == NULL) {
			log_error("not enough memory");
			conf_iter_finish(conf(), &iter);
			break;
		}

		/* Create zone scanner. */
		char *zone_name = knot_dname_to_str_alloc(conf_dname(&id));
		if (zone_name == NULL) {
			log_error("not enough memory");
			hattrie_free(est.node_table);
			conf_iter_finish(conf(), &iter);
			break;
		}
		if (zs_init(zs, zone_name, KNOT_CLASS_IN, 3600) != 0 ||
		    zs_set_processing(zs, estimator_rrset_memsize_wrap, NULL, &est) != 0) {
			log_zone_error(conf_dname(&id), "failed to load zone");
			zs_deinit(zs);
			free(zone_name);
			hattrie_free(est.node_table);
			continue;
		}
		free(zone_name);

		/* Do a parser run, but do not actually create the zone. */
		char *zonefile = conf_zonefile(conf(), conf_dname(&id));
		if (zs_set_input_file(zs, zonefile) != 0 ||
		    zs_parse_all(zs) != 0) {
			log_zone_error(conf_dname(&id), "failed to parse zone");
			hattrie_apply_rev(est.node_table, estimator_free_trie_node, NULL);
			hattrie_free(est.node_table);
			free(zonefile);
			zs_deinit(zs);
			continue;
		}
		free(zonefile);
		zs_deinit(zs);

		/* Only size of ahtables inside trie's nodes is missing. */
		assert(est.htable_size == 0);
		est.htable_size = estimator_trie_htable_memsize(est.node_table);

		/* Cleanup */
		hattrie_apply_rev(est.node_table, estimator_free_trie_node, NULL);
		hattrie_free(est.node_table);

		double zone_size = ((double)(est.rdata_size +
		                   est.node_size +
		                   est.dname_size +
		                   est.htable_size +
		                   malloc_size) * ESTIMATE_MAGIC) / (1024.0 * 1024.0);

		log_zone_info(conf_dname(&id), "%zu RRs, used memory estimation is %zu MiB",
		              est.record_count, (size_t)zone_size);
		total_size += zone_size;
	}

	free(zs);

	if (args->argc == 0) { // for all zones
		log_info("Estimated memory consumption for all zones is %zu MiB",
		         (size_t)total_size);
	}

	return 0;
}

const cmd_desc_t cmd_table[] = {
	{ CMD_STATUS,          cmd_status },
	{ CMD_STOP,            cmd_stop },
	{ CMD_RELOAD,          cmd_reload },

	{ CMD_ZONE_CHECK,      cmd_zone_check,    CMD_CONF_FREAD },
	{ CMD_ZONE_MEMSTATS,   cmd_zone_memstats, CMD_CONF_FREAD },
	{ CMD_ZONE_STATUS,     cmd_zone_status },
	{ CMD_ZONE_RELOAD,     cmd_zone_reload },
	{ CMD_ZONE_REFRESH,    cmd_zone_refresh },
	{ CMD_ZONE_RETRANSFER, cmd_zone_retransfer },
	{ CMD_ZONE_FLUSH,      cmd_zone_flush },
	{ CMD_ZONE_SIGN,       cmd_zone_sign },

	{ CMD_CONF_INIT,       cmd_conf_init,     CMD_CONF_FWRITE },
	{ CMD_CONF_CHECK,      cmd_conf_check,    CMD_CONF_FREAD },
	{ CMD_CONF_IMPORT,     cmd_conf_import,   CMD_CONF_FWRITE },
	{ CMD_CONF_EXPORT,     cmd_conf_export,   CMD_CONF_FREAD },
	{ CMD_CONF_LIST,       cmd_conf_list },
	{ CMD_CONF_READ,       cmd_conf_read },
	{ CMD_CONF_BEGIN,      cmd_conf_begin },
	{ CMD_CONF_COMMIT,     cmd_conf_commit },
	{ CMD_CONF_ABORT,      cmd_conf_abort },
	{ CMD_CONF_DIFF,       cmd_conf_diff },
	{ CMD_CONF_GET,        cmd_conf_get },
	{ CMD_CONF_SET,        cmd_conf_set },
	{ CMD_CONF_UNSET,      cmd_conf_unset },
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
	{ CMD_CONF_LIST,       "[<item>]",             "List the confdb sections or section items." },
	{ CMD_CONF_READ,       "[<item>]",             "Read the item from the active confdb." },
	{ CMD_CONF_BEGIN,      "",                     "Begin a writing confdb transaction." },
	{ CMD_CONF_COMMIT,     "",                     "Commit the confdb transaction." },
	{ CMD_CONF_ABORT,      "",                     "Rollback the confdb transaction." },
	{ CMD_CONF_DIFF,       "[<item>]",             "Get the item difference in the transaction." },
	{ CMD_CONF_GET,        "[<item>]",             "Get the item data from the transaction." },
	{ CMD_CONF_SET,        " <item>  [<data>...]", "Set the item data in the transaction." },
	{ CMD_CONF_UNSET,      "[<item>] [<data>...]", "Unset the item data in the transaction." },
	{ NULL }
};
