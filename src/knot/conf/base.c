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

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <urcu.h>

#include "knot/conf/base.h"
#include "knot/conf/confdb.h"
#include "knot/conf/tools.h"
#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/internet.h"
#include "libknot/internal/mem.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/internal/sockaddr.h"
#include "libknot/yparser/ypformat.h"

#define MAX_INCLUDE_DEPTH	5

// The active configuration.
conf_t *s_conf;

conf_t* conf(void) {
	return s_conf;
}

static void rm_dir(const char *path)
{
	DIR *dir = opendir(path);
	if (dir == NULL) {
		log_warning("failed to remove directory '%s'", path);
		return;
	}

	// Prepare own dirent structure (see NOTES in man readdir_r).
	size_t len = offsetof(struct dirent, d_name) +
		     fpathconf(dirfd(dir), _PC_NAME_MAX) + 1;

	struct dirent *entry = malloc(len);
	if (entry == NULL) {
		log_warning("failed to remove directory '%s'", path);
		closedir(dir);
		return;
	}
	memset(entry, 0, len);

	// Firstly, delete all files in the directory.
	int ret;
	struct dirent *result = NULL;
	while ((ret = readdir_r(dir, entry, &result)) == 0 &&
	       result != NULL) {
		if (entry->d_name[0] == '.') {
			continue;
		}

		char *file = sprintf_alloc("%s/%s", path, entry->d_name);
		if (file == NULL) {
			ret = KNOT_ENOMEM;
			break;
		}
		remove(file);
		free(file);
	}

	free(entry);
	closedir(dir);

	// Secondly, delete the directory if it is empty.
	if (ret != 0 || remove(path) != 0) {
		log_warning("failed to remove whole directory '%s'", path);
	}
}

int conf_new(
	conf_t **conf,
	const yp_item_t *scheme,
	const char *db_dir)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	conf_t *out = malloc(sizeof(conf_t));
	if (out == NULL) {
		return KNOT_ENOMEM;
	}
	memset(out, 0, sizeof(conf_t));

	// Initialize config scheme.
	int ret = yp_scheme_copy(&out->scheme, scheme);
	if (ret != KNOT_EOK) {
		free(out);
		return ret;
	}

	// Prepare namedb api.
	out->mm = malloc(sizeof(mm_ctx_t));
	mm_ctx_mempool(out->mm, MM_DEFAULT_BLKSIZE);
	struct namedb_lmdb_opts lmdb_opts = NAMEDB_LMDB_OPTS_INITIALIZER;
	lmdb_opts.mapsize = 500 * 1024 * 1024;
	lmdb_opts.flags.env = NAMEDB_LMDB_NOTLS;

	// Open database.
	if (db_dir == NULL) {
		// A temporary solution until proper trie support is available.
		char tpl[] = "/tmp/knot-confdb.XXXXXX";
		lmdb_opts.path = mkdtemp(tpl);
		if (lmdb_opts.path == NULL) {
			log_error("failed to create temporary directory");
			ret = KNOT_ENOMEM;
			goto new_error;
		}
		out->api = namedb_lmdb_api();
		ret = out->api->init(&out->db, out->mm, &lmdb_opts);

		// Remove opened database to ensure it is temporary.
		rm_dir(tpl);
	} else {
		lmdb_opts.path = db_dir;
		out->api = namedb_lmdb_api();
		ret = out->api->init(&out->db, out->mm, &lmdb_opts);
	}

	// Check database opening.
	if (ret != KNOT_EOK) {
		goto new_error;
	}

	// Initialize/check database.
	namedb_txn_t txn;
	ret = out->api->txn_begin(out->db, &txn, 0);
	if (ret != KNOT_EOK) {
		out->api->deinit(out->db);
		goto new_error;
	}

	ret = conf_db_init(out, &txn);
	if (ret != KNOT_EOK) {
		out->api->txn_abort(&txn);
		out->api->deinit(out->db);
		goto new_error;
	}

	ret = out->api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		out->api->deinit(out->db);
		goto new_error;
	}

	// Open common read-only transaction.
	ret = out->api->txn_begin(out->db, &out->read_txn, NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		out->api->deinit(out->db);
		goto new_error;
	}

	*conf = out;

	return KNOT_EOK;
new_error:
	yp_scheme_free(out->scheme);
	free(out->mm);
	free(out);

	return ret;
}

int conf_clone(
	conf_t **conf)
{
	if (conf == NULL || s_conf == NULL) {
		return KNOT_EINVAL;
	}

	conf_t *out = malloc(sizeof(conf_t));
	if (out == NULL) {
		return KNOT_ENOMEM;
	}
	memset(out, 0, sizeof(conf_t));

	// Initialize config scheme.
	int ret = yp_scheme_copy(&out->scheme, s_conf->scheme);
	if (ret != KNOT_EOK) {
		free(out);
		return ret;
	}

	// Set shared items.
	out->api = s_conf->api;
	out->mm = s_conf->mm;
	out->db = s_conf->db;
	out->filename = s_conf->filename;

	// Open common read-only transaction.
	ret = out->api->txn_begin(out->db, &out->read_txn, NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		yp_scheme_free(out->scheme);
		free(out);
		return ret;
	}

	*conf = out;

	return KNOT_EOK;
}

int conf_post_open(
	conf_t *conf)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	conf->hostname = sockaddr_hostname();

	int ret = conf_activate_modules(conf, NULL, &conf->query_modules,
	                                &conf->query_plan);
	if (ret != KNOT_EOK) {
		free(conf->hostname);
		return ret;
	}

	return KNOT_EOK;
}

void conf_update(
	conf_t *conf)
{
	if (conf == NULL) {
		return;
	}

	conf_t **current_conf = &s_conf;
	conf_t *old_conf = rcu_xchg_pointer(current_conf, conf);

	synchronize_rcu();

	if (old_conf) {
		conf_free(old_conf, true);
	}
}

void conf_free(
	conf_t *conf,
	bool is_clone)
{
	if (conf == NULL) {
		return;
	}

	yp_scheme_free(conf->scheme);
	conf->api->txn_abort(&conf->read_txn);
	free(conf->hostname);

	if (conf->query_plan != NULL) {
		conf_deactivate_modules(conf, &conf->query_modules,
		                        conf->query_plan);
	}

	if (!is_clone) {
		conf->api->deinit(conf->db);
		free(conf->mm);
		free(conf->filename);
	}

	free(conf);
}

int conf_activate_modules(
	conf_t *conf,
	knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan)
{
	if (conf == NULL || query_modules == NULL || query_plan == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val;

	// Get list of associated modules.
	if (zone_name != NULL) {
		val = conf_zone_get(conf, C_MODULE, zone_name);
	} else {
		val = conf_default_get(conf, C_MODULE);
	}

	if (val.code == KNOT_ENOENT) {
		return KNOT_EOK;
	} else if (val.code != KNOT_EOK) {
		return val.code;
	}

	// Create query plan.
	*query_plan = query_plan_create(conf->mm);
	if (*query_plan == NULL) {
		return KNOT_ENOMEM;
	}

	if (zone_name != NULL) {
		// Only supported zone class is now IN.
		internet_query_plan(*query_plan);
	}

	// Initialize query modules list.
	init_list(query_modules);

	// Open the modules.
	while (val.code == KNOT_EOK) {
		conf_mod_id_t *mod_id = conf_mod_id(&val);
		if (mod_id == NULL) {
			return KNOT_ENOMEM;
		}

		// Open the module.
		struct query_module *mod = query_module_open(conf, mod_id, conf->mm);
		if (mod == NULL) {
			conf_free_mod_id(mod_id);
			return KNOT_ENOMEM;
		}

		// Load the module.
		int ret = mod->load(*query_plan, mod);
		if (ret != KNOT_EOK) {
			query_module_close(mod);
			return ret;
		}

		add_tail(query_modules, &mod->node);

		conf_val_next(&val);
	}

	return KNOT_EOK;
}

void conf_deactivate_modules(
	conf_t *conf,
	list_t *query_modules,
	struct query_plan *query_plan)
{
	if (conf == NULL || query_modules == NULL || query_plan == NULL) {
		return;
	}

	// Free query modules list.
	struct query_module *mod = NULL, *next = NULL;
	WALK_LIST_DELSAFE(mod, next, *query_modules) {
		mod->unload(mod);
		query_module_close(mod);
	}

	// Free query plan.
	query_plan_free(query_plan);
}

static int parser_process(
	conf_t *conf,
	namedb_txn_t *txn,
	yp_parser_t *parser,
	yp_check_ctx_t *ctx,
	size_t *incl_depth)
{
	int ret = yp_scheme_check_parser(ctx, parser);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = conf_db_set(conf, txn, ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const yp_item_t *item = (ctx->event == YP_EKEY0) ? ctx->key0 : ctx->key1;
	conf_call_f *sem_check = (conf_call_f *)item->misc[0];
	conf_call_f *callback = (conf_call_f *)item->misc[1];
	conf_args_t args = {
		conf, txn, parser->file.name, incl_depth, ctx->key0, ctx->key1,
		ctx->id, ctx->id_len, ctx->data, ctx->data_len
	};

	// Call semantic check if any.
	if (sem_check != NULL && (ret = sem_check(&args)) != KNOT_EOK) {
		return ret;
	}

	// Call callback function if any.
	if (callback != NULL && (ret = callback(&args)) != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

int conf_parse(
	conf_t *conf,
	namedb_txn_t *txn,
	const char *input,
	bool is_file,
	size_t *incl_depth)
{
	if (conf == NULL || txn == NULL || input == NULL ||
	    incl_depth == NULL) {
		return KNOT_EINVAL;
	}

	// Check for include loop.
	if ((*incl_depth)++ > MAX_INCLUDE_DEPTH) {
		return KNOT_EPARSEFAIL;
	}

	yp_parser_t *parser = malloc(sizeof(yp_parser_t));
	if (parser == NULL) {
		return KNOT_ENOMEM;
	}
	yp_init(parser);

	int ret;
	if (is_file) {
		ret = yp_set_input_file(parser, input);
	} else {
		ret = yp_set_input_string(parser, input, strlen(input));
	}
	if (ret != KNOT_EOK) {
		goto init_error;
	}

	yp_check_ctx_t *ctx = yp_scheme_check_init(conf->scheme);
	if (ctx == NULL) {
		ret = KNOT_ENOMEM;
		goto init_error;
	}

	while ((ret = yp_parse(parser)) == KNOT_EOK) {
		ret = parser_process(conf, txn, parser, ctx, incl_depth);
		if (ret != KNOT_EOK) {
			break;
		}
	}

	yp_scheme_check_deinit(ctx);

	if (ret != KNOT_EOF) {
		log_error("invalid configuration%s%s%s, line %zu (%s)",
		          (is_file ? " file '" : ""),
		          (is_file ? input : ""),
		          (is_file ? "'" : ""),
		          parser->line_count, knot_strerror(ret));
		goto init_error;
	}

	(*incl_depth)--;

	ret = KNOT_EOK;
init_error:
	yp_deinit(parser);
	free(parser);

	return ret;
}

int conf_import(
	conf_t *conf,
	const char *input,
	bool is_file)
{
	if (conf == NULL || input == NULL) {
		return KNOT_EINVAL;
	}

	namedb_txn_t txn;
	int ret = conf->api->txn_begin(conf->db, &txn, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Drop the current DB content.
	ret = conf->api->clear(&txn);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		return ret;
	}

	// Initialize new DB.
	ret = conf_db_init(conf, &txn);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		return ret;
	}

	size_t depth = 0;

	// Parse and import given file.
	ret = conf_parse(conf, &txn, input, is_file, &depth);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		return ret;
	}

	// Commit new configuration.
	ret = conf->api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update read-only transaction.
	conf->api->txn_abort(&conf->read_txn);
	ret = conf->api->txn_begin(conf->db, &conf->read_txn, NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

static int export_group(
	conf_t *conf,
	FILE *fp,
	yp_item_t *group,
	uint8_t *id,
	size_t id_len,
	char *out,
	size_t out_len,
	yp_style_t style)
{
	yp_item_t *item;
	for (item = group->sub_items; item->name != NULL; item++) {
		conf_val_t bin;
		bin.code = conf_db_get(conf, &conf->read_txn, group->name,
		                       item->name, id, id_len, &bin);
		if (bin.code == KNOT_ENOENT) {
			continue;
		} else if (bin.code != KNOT_EOK) {
			return bin.code;
		}

		// Format single/multiple-valued item.
		size_t values = conf_val_count(&bin);
		for (size_t i = 1; i <= values; i++) {
			conf_db_val(&bin);
			int ret = yp_format_key1(item, bin.data, bin.len, out,
			                         out_len, style, i == 1,
			                         i == values);
			if (ret != KNOT_EOK) {
				return ret;
			}
			fprintf(fp, "%s", out);

			if (values > 1) {
				conf_val_next(&bin);
			}
		}
	}

	fprintf(fp, "\n");

	return KNOT_EOK;
}

int conf_export(
	conf_t *conf,
	const char *file_name,
	yp_style_t style)
{
	if (conf == NULL || file_name == NULL) {
		return KNOT_EINVAL;
	}

	// Prepare common buffer;
	const size_t buff_len = 2 * CONF_MAX_DATA_LEN; // Rough limit.
	char *buff = malloc(buff_len);
	if (buff == NULL) {
		return KNOT_ENOMEM;
	}

	FILE *fp = fopen(file_name, "w");
	if (fp == NULL) {
		free(buff);
		return KNOT_EFILE;
	}

	int ret;

	// Iterate over the current scheme.
	yp_item_t *item;
	for (item = conf->scheme; item->name != NULL; item++) {
		// Skip non-group items (include).
		if (item->type != YP_TGRP) {
			continue;
		}

		// Check if the item is ever stored in DB.
		uint8_t item_code;
		ret = conf_db_code(conf, &conf->read_txn, CONF_CODE_KEY0_ROOT,
		                   item->name, true, &item_code);
		if (ret == KNOT_ENOENT) {
			continue;
		} else if (ret != KNOT_EOK) {
			goto export_error;
		}

		// Export group name.
		ret = yp_format_key0(item, NULL, 0, buff, buff_len, style,
		                     true, true);
		if (ret != KNOT_EOK) {
			goto export_error;
		}
		fprintf(fp, "%s", buff);

		// Export simple group without identifiers.
		if (item->var.g.id == NULL) {
			ret = export_group(conf, fp, item, NULL, 0, buff,
			                   buff_len, style);
			if (ret != KNOT_EOK) {
				goto export_error;
			}

			continue;
		}

		// Iterate over all identifiers.
		conf_iter_t iter;
		ret = conf_db_iter_begin(conf, &conf->read_txn, item->name,
		                         &iter);
		if (ret != KNOT_EOK) {
			goto export_error;
		}

		while (ret == KNOT_EOK) {
			uint8_t *id;
			size_t id_len;
			ret = conf_db_iter_id(conf, &iter, &id, &id_len);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf, &iter);
				goto export_error;
			}

			// Export identifier.
			ret = yp_format_id(item->var.g.id, id, id_len, buff,
			                   buff_len, style);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf, &iter);
				goto export_error;
			}
			fprintf(fp, "%s", buff);

			// Export other items.
			ret = export_group(conf, fp, item, id, id_len, buff,
			                   buff_len, style);
			if (ret != KNOT_EOK) {
				conf_db_iter_finish(conf, &iter);
				goto export_error;
			}

			ret = conf_db_iter_next(conf, &iter);
		}

		conf_db_iter_finish(conf, &iter);
	}

	ret = KNOT_EOK;
export_error:
	fclose(fp);
	free(buff);

	return ret;
}
