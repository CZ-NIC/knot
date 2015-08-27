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
#include "libknot/yparser/yptrafo.h"
#include "libknot/internal/mempool.h"

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
		CONF_LOG(LOG_WARNING, "failed to remove directory '%s'", path);
		return;
	}

	// Prepare own dirent structure (see NOTES in man readdir_r).
	size_t len = offsetof(struct dirent, d_name) +
		     fpathconf(dirfd(dir), _PC_NAME_MAX) + 1;

	struct dirent *entry = malloc(len);
	if (entry == NULL) {
		CONF_LOG(LOG_WARNING, "failed to remove directory '%s'", path);
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
		CONF_LOG(LOG_WARNING, "failed to remove whole directory '%s'", path);
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
			CONF_LOG(LOG_ERR, "failed to create temporary directory");
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

	// Initialize query modules list.
	init_list(&out->query_modules);

	*conf = out;

	return KNOT_EOK;
new_error:
	yp_scheme_free(out->scheme);
	mp_delete(out->mm->ctx);
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

	// Initialize query modules list.
	init_list(&out->query_modules);

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

	conf_activate_modules(conf, NULL, &conf->query_modules, &conf->query_plan);

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

	conf_deactivate_modules(conf, &conf->query_modules, &conf->query_plan);

	if (!is_clone) {
		conf->api->deinit(conf->db);
		mp_delete(conf->mm->ctx);
		free(conf->mm);
		free(conf->filename);
	}

	free(conf);
}

void conf_activate_modules(
	conf_t *conf,
	const knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan)
{
	int ret = KNOT_EOK;

	if (conf == NULL || query_modules == NULL || query_plan == NULL) {
		ret = KNOT_EINVAL;
		goto activate_error;
	}

	conf_val_t val;

	// Get list of associated modules.
	if (zone_name != NULL) {
		val = conf_zone_get(conf, C_MODULE, zone_name);
	} else {
		val = conf_default_get(conf, C_GLOBAL_MODULE);
	}

	// Check if a module is configured at all.
	if (val.code == KNOT_ENOENT) {
		return;
	} else if (val.code != KNOT_EOK) {
		ret = val.code;
		goto activate_error;
	}

	// Create query plan.
	*query_plan = query_plan_create(conf->mm);
	if (*query_plan == NULL) {
		ret = KNOT_ENOMEM;
		goto activate_error;
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
			ret = KNOT_ENOMEM;
			goto activate_error;
		}

		// Open the module.
		struct query_module *mod = query_module_open(conf, mod_id, conf->mm);
		if (mod == NULL) {
			ret = KNOT_ENOMEM;
			goto activate_error;
		}

		// Check the module scope.
		if ((zone_name == NULL && (mod->scope & MOD_SCOPE_GLOBAL) == 0) ||
		    (zone_name != NULL && (mod->scope & MOD_SCOPE_ZONE) == 0)) {
			if (zone_name != NULL) {
				log_zone_warning(zone_name,
				                 "out of scope module '%s/%.*s'",
				                 mod_id->name + 1, (int)mod_id->len,
				                 mod_id->data);
			} else {
				log_warning("out of scope module '%s/%.*s'",
				            mod_id->name + 1, (int)mod_id->len,
				            mod_id->data);
			}
			query_module_close(mod);
			conf_val_next(&val);
			continue;
		}

		// Load the module.
		ret = mod->load(*query_plan, mod);
		if (ret != KNOT_EOK) {
			if (zone_name != NULL) {
				log_zone_error(zone_name,
				               "failed to load module '%s/%.*s' (%s)",
				               mod_id->name + 1, (int)mod_id->len,
				               mod_id->data, knot_strerror(ret));
			} else {
				log_error("failed to load global module '%s/%.*s' (%s)",
				          mod_id->name + 1, (int)mod_id->len,
				          mod_id->data, knot_strerror(ret));
			}
			query_module_close(mod);
			conf_val_next(&val);
			continue;
		}

		add_tail(query_modules, &mod->node);

		conf_val_next(&val);
	}

	return;
activate_error:
	CONF_LOG(LOG_ERR, "failed to activate modules (%s)", knot_strerror(ret));
}

void conf_deactivate_modules(
	conf_t *conf,
	list_t *query_modules,
	struct query_plan **query_plan)
{
	if (conf == NULL || query_modules == NULL || query_plan == NULL) {
		return;
	}

	// Free query plan.
	query_plan_free(*query_plan);
	*query_plan = NULL;

	// Free query modules list.
	struct query_module *mod = NULL, *next = NULL;
	WALK_LIST_DELSAFE(mod, next, *query_modules) {
		mod->unload(mod);
		query_module_close(mod);
	}
	init_list(query_modules);
}

static int exec_callbacks(
	const yp_item_t *item,
	conf_check_t *args)
{
	for (size_t i = 0; i < YP_MAX_MISC_COUNT; i++) {
		conf_check_f *fcn = (conf_check_f *)item->misc[i];
		if (fcn == NULL) {
			break;
		}
		int ret;
		if ((ret = fcn(args)) != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int previous_block_calls(
	conf_t *conf,
	namedb_txn_t *txn,
	conf_previous_t *prev,
	const char **err_str)
{
	if (prev->id_len > 0) {
		assert(prev->key0 != NULL);

		conf_check_t args = {
			.conf = conf,
			.txn = txn,
			.previous = prev,
			.err_str = err_str
		};

		// Execute previous block callbacks.
		int ret = exec_callbacks(prev->key0, &args);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int item_calls(
	conf_t *conf,
	namedb_txn_t *txn,
	yp_parser_t *parser,
	yp_check_ctx_t *ctx,
	conf_previous_t *prev,
	size_t *incl_depth,
	const char **err_str)
{
	conf_check_t args = {
		.conf = conf,
		.txn = txn,
		.parser = parser,
		.check = ctx,
		.include_depth = incl_depth,
		.previous = prev,
		.err_str = err_str
	};

	const yp_item_t *item;

	// Prepare previous context.
	switch (ctx->event) {
	case YP_EKEY0:
		// Reset previous context id.
		prev->id_len = 0;
		// Set previous context key0 if group item.
		if (ctx->key0->type == YP_TGRP) {
			prev->key0 = ctx->key0;
			return KNOT_EOK;
		}
		item = ctx->key0;
		break;
	case YP_EID:
		memcpy(prev->id, ctx->id, ctx->id_len);
		prev->id_len = ctx->id_len;
		prev->file = parser->file.name;
		prev->line = parser->line_count;
		item = ctx->key1;
		break;
	default:
		assert(ctx->event == YP_EKEY1);
		item = ctx->key1;
		break;
	}

	// Execute item callbacks.
	return exec_callbacks(item, &args);
}

#define CONF_LOG_LINE(input, is_file, line, msg, ...) do { \
	CONF_LOG(LOG_ERR, "%s%s%sline %zu, " msg, \
	         (is_file ? "file '" : ""), (is_file ? input : ""), \
	         (is_file ? "', " : ""), line, ##__VA_ARGS__); \
	} while (0)

static void log_current_err(
	const char *input,
	bool is_file,
	yp_parser_t *parser,
	int ret,
	const char *err_str)
{
	CONF_LOG_LINE(input, is_file, parser->line_count,
	             "item '%.*s', value '%.*s' (%s)",
	             (int)parser->key_len, parser->key,
	             (int)parser->data_len, parser->data,
	             (err_str != NULL ? err_str : knot_strerror(ret)));
}

static void log_prev_err(
	const char *input,
	bool is_file,
	struct conf_previous *prev,
	int ret,
	const char *err_str)
{
	char buff[512];
	size_t len = sizeof(buff);

	// Get textual previous identifier.
	if (yp_item_to_txt(prev->key0->var.g.id, prev->id, prev->id_len,
	                   buff, &len, YP_SNOQUOTE) != KNOT_EOK) {
		buff[0] = '\0';
	}

	CONF_LOG_LINE(input, is_file, prev->line, "%s '%s' (%s)",
	              prev->key0->name + 1, buff,
	              (err_str != NULL ? err_str : knot_strerror(ret)));
}

int conf_parse(
	conf_t *conf,
	namedb_txn_t *txn,
	const char *input,
	bool is_file,
	size_t *incl_depth,
	struct conf_previous *prev)
{
	if (conf == NULL || txn == NULL || input == NULL ||
	    incl_depth == NULL || prev == NULL) {
		return KNOT_EINVAL;
	}

	// Check for include loop.
	if ((*incl_depth)++ > MAX_INCLUDE_DEPTH) {
		CONF_LOG(LOG_ERR, "include loop detected");
		return KNOT_EPARSEFAIL;
	}

	yp_parser_t *parser = malloc(sizeof(yp_parser_t));
	if (parser == NULL) {
		return KNOT_ENOMEM;
	}
	yp_init(parser);

	int ret;

	// Set parser source.
	if (is_file) {
		ret = yp_set_input_file(parser, input);
	} else {
		ret = yp_set_input_string(parser, input, strlen(input));
	}
	if (ret != KNOT_EOK) {
		CONF_LOG(LOG_ERR, "failed to load file '%s' (%s)",
		         input, knot_strerror(ret));
		goto parse_error;
	}

	// Initialize parser check context.
	yp_check_ctx_t *ctx = yp_scheme_check_init(conf->scheme);
	if (ctx == NULL) {
		ret = KNOT_ENOMEM;
		goto parse_error;
	}

	int check_ret = KNOT_EOK;
	const char *err_str = NULL;

	// Parse the configuration.
	while ((ret = yp_parse(parser)) == KNOT_EOK) {
		check_ret = yp_scheme_check_parser(ctx, parser);
		if (check_ret != KNOT_EOK) {
			log_current_err(input, is_file, parser, check_ret, NULL);
			break;
		}
		check_ret = conf_db_set(conf, txn, ctx);
		if (check_ret != KNOT_EOK) {
			log_current_err(input, is_file, parser, check_ret, NULL);
			break;
		}
		if (ctx->event != YP_EKEY1) {
			check_ret = previous_block_calls(conf, txn, prev, &err_str);
			if (check_ret != KNOT_EOK) {
				log_prev_err(input, is_file, prev, check_ret, err_str);
				break;
			}
		}
		check_ret = item_calls(conf, txn, parser, ctx, prev, incl_depth,
		                       &err_str);
		if (check_ret != KNOT_EOK) {
			log_current_err(input, is_file, parser, check_ret, err_str);
			break;
		}
	}

	if (ret == KNOT_EOF) {
		// Call the last block callbacks.
		ret = previous_block_calls(conf, txn, prev, &err_str);
		if (ret != KNOT_EOK) {
			log_prev_err(input, is_file, prev, ret, err_str);
		}
	} else if (ret != KNOT_EOK) {
		log_current_err(input, is_file, parser, ret, NULL);
	} else {
		ret = check_ret;
	}

	yp_scheme_check_deinit(ctx);
parse_error:
	(*incl_depth)--;
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

	int ret;

	namedb_txn_t txn;
	ret = conf->api->txn_begin(conf->db, &txn, 0);
	if (ret != KNOT_EOK) {
		goto import_error;
	}

	// Drop the current DB content.
	ret = conf->api->clear(&txn);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		goto import_error;
	}

	// Initialize new DB.
	ret = conf_db_init(conf, &txn);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		goto import_error;
	}

	size_t depth = 0;
	conf_previous_t prev = { NULL };

	// Parse and import given file.
	ret = conf_parse(conf, &txn, input, is_file, &depth, &prev);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		goto import_error;
	}

	// Commit new configuration.
	ret = conf->api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		goto import_error;
	}

	// Update read-only transaction.
	conf->api->txn_abort(&conf->read_txn);
	ret = conf->api->txn_begin(conf->db, &conf->read_txn, NAMEDB_RDONLY);
	if (ret != KNOT_EOK) {
		goto import_error;
	}

	ret = KNOT_EOK;
import_error:

	return ret;
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
