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

#include <assert.h>
#include <dirent.h>
#include <grp.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <urcu.h>

#include "knot/conf/conf.h"
#include "knot/conf/confdb.h"
#include "knot/conf/tools.h"
#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"
#include "knot/nameserver/internet.h"
#include "knot/server/dthreads.h"
#include "libknot/errcode.h"
#include "libknot/internal/macros.h"
#include "libknot/internal/mem.h"
#include "libknot/internal/mempattern.h"
#include "libknot/internal/mempool.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/internal/sockaddr.h"
#include "libknot/yparser/ypformat.h"
#include "libknot/yparser/yptrafo.h"

#define MAX_INCLUDE_DEPTH	5

conf_t *s_conf;

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
	lmdb_opts.flags.env = NAMEDB_LMDB_NOTLS;

	// A temporary solution until proper trie support in namedb is available.
	if (db_dir == NULL) {
		char tpl[] = "/tmp/knot-confdb.XXXXXX";
		db_dir = mkdtemp(tpl);
		if (db_dir == NULL) {
			log_error("failed to create temporary directory");
			return EXIT_FAILURE;
		}
		out->tmp_dir = strdup(db_dir);
	}
	lmdb_opts.path = db_dir;
	out->api = namedb_lmdb_api();

	// Open database.
	ret = out->api->init(&out->db, out->mm, &lmdb_opts);
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
	out->tmp_dir = s_conf->tmp_dir;

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

	// Remove temporary database.
	DIR *dir;
	if (!is_clone && conf->tmp_dir != NULL &&
	    (dir = opendir(conf->tmp_dir)) != NULL) {
		// Prepare own dirent structure (see NOTES in man readdir_r).
		size_t len = offsetof(struct dirent, d_name) +
		             fpathconf(dirfd(dir), _PC_NAME_MAX) + 1;

		struct dirent *entry = malloc(len);
		if (entry != NULL) {
			memset(entry, 0, len);
			struct dirent *result = NULL;
			int ret;

			while ((ret = readdir_r(dir, entry, &result)) == 0 &&
			       result != NULL) {
				if (entry->d_name[0] == '.') {
					continue;
				}
				char *file = sprintf_alloc("%s/%s",
							   conf->tmp_dir,
							   entry->d_name);
				remove(file);
				free(file);
			}

			free(entry);
			closedir(dir);
			remove(conf->tmp_dir);
			free(conf->tmp_dir);
		}
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

static conf_val_t raw_id_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	const uint8_t *id,
	size_t id_len)
{
	conf_val_t val = { NULL };

	val.code = conf_db_get(conf, &conf->read_txn, key0_name, key1_name,
	                       id, id_len, &val);
	switch (val.code) {
	default:
		log_error("failed to read configuration '%s/%s' (%s)",
		          key0_name + 1, key1_name + 1, knot_strerror(val.code));
	case KNOT_EOK:
	case KNOT_ENOENT:
		return val;
	}
}

conf_val_t conf_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name)
{
	// Check for empty key1.
	if (key1_name == NULL) {
		conf_val_t val = { NULL };
		val.code = KNOT_EINVAL;
		return val;
	}

	return raw_id_get(conf, key0_name, key1_name, NULL, 0);
}

conf_val_t conf_id_get(
	conf_t *conf,
	const yp_name_t *key0_name,
	const yp_name_t *key1_name,
	conf_val_t *id)
{
	// Check for invalid id.
	if (id != NULL) {
		if (id->code != KNOT_EOK) {
			conf_val_t val = { NULL };
			val.code = id->code;
			return val;
		}
		conf_db_val(id);
	} else {
		conf_val_t val = { NULL };
		val.code = KNOT_EINVAL;
		return val;
	}

	return raw_id_get(conf, key0_name, key1_name,
	                  (id == NULL) ? NULL : id->data,
	                  (id == NULL) ? 0 : id->len);
}

conf_val_t conf_mod_get(
	conf_t *conf,
	const yp_name_t *key1_name,
	const conf_mod_id_t *mod_id)
{
	// Check for empty input.
	if (key1_name == NULL || mod_id == NULL) {
		conf_val_t val = { NULL };
		val.code = KNOT_EINVAL;
		return val;
	}

	return raw_id_get(conf, mod_id->name, key1_name, mod_id->data, mod_id->len);
}

conf_val_t conf_zone_get(
	conf_t *conf,
	const yp_name_t *key1_name,
	const knot_dname_t *dname)
{
	conf_val_t val = { NULL };

	if (dname == NULL) {
		val.code = KNOT_EINVAL;
		return val;
	}

	int dname_size = knot_dname_size(dname);

	// Try to get explicit value.
	val.code = conf_db_get(conf, &conf->read_txn, C_ZONE, key1_name,
	                       dname, dname_size, &val);
	switch (val.code) {
	case KNOT_EOK:
		return val;
	default:
		log_zone_error(dname, "failed to read configuration '%s/%s' (%s)",
		               C_ZONE + 1, key1_name + 1, knot_strerror(val.code));
	case KNOT_ENOENT:
		break;
	}

	// Check if a template is available.
	val.code = conf_db_get(conf, &conf->read_txn, C_ZONE, C_TPL, dname,
	                       dname_size, &val);
	switch (val.code) {
	case KNOT_EOK:
		// Use the specified template.
		conf_db_val(&val);
		val.code = conf_db_get(conf, &conf->read_txn, C_TPL, key1_name,
		                       val.data, val.len, &val);
		break;
	default:
		log_zone_error(dname, "failed to read configuration '%s/%s' (%s)",
		               C_ZONE + 1, C_TPL + 1, knot_strerror(val.code));
	case KNOT_ENOENT:
		// Use the default template.
		val.code = conf_db_get(conf, &conf->read_txn, C_TPL, key1_name,
		                       CONF_DEFAULT_ID + 1, CONF_DEFAULT_ID[0],
		                       &val);
	}

	switch (val.code) {
	default:
		log_zone_error(dname, "failed to read configuration '%s/%s' (%s)",
		               C_TPL + 1, key1_name + 1, knot_strerror(val.code));
	case KNOT_EOK:
	case KNOT_ENOENT:
		break;
	}

	return val;
}

conf_val_t conf_default_get(
	conf_t *conf,
	const yp_name_t *key1_name)
{
	conf_val_t val = { NULL };

	val.code = conf_db_get(conf, &conf->read_txn, C_TPL, key1_name,
	                       CONF_DEFAULT_ID + 1, CONF_DEFAULT_ID[0], &val);
	switch (val.code) {
	default:
		log_error("failed to read configuration '%s/%s' (%s)",
		          C_TPL + 1, key1_name + 1, knot_strerror(val.code));
	case KNOT_EOK:
	case KNOT_ENOENT:
		break;
	}

	return val;
}

size_t conf_id_count(
	conf_t *conf,
	const yp_name_t *key0_name)
{
	size_t count = 0;
	conf_iter_t iter = { NULL };

	int ret = conf_db_iter_begin(conf, &conf->read_txn, key0_name, &iter);
	switch (ret) {
	case KNOT_EOK:
		break;
	default:
		log_error("failed to iterate through configuration '%s' (%s)",
		          key0_name + 1, knot_strerror(ret));
	case KNOT_ENOENT:
		return count;
	}

	while (ret == KNOT_EOK) {
		count++;
		ret = conf_db_iter_next(conf, &iter);
	}
	conf_db_iter_finish(conf, &iter);

	return count;
}

conf_iter_t conf_iter(
	conf_t *conf,
	const yp_name_t *key0_name)
{
	conf_iter_t iter = { NULL };

	iter.code = conf_db_iter_begin(conf, &conf->read_txn, key0_name, &iter);
	switch (iter.code) {
	default:
		log_error("failed to iterate thgrough configuration '%s' (%s)",
		          key0_name + 1, knot_strerror(iter.code));
	case KNOT_EOK:
	case KNOT_ENOENT:
		return iter;
	}
}

void conf_iter_next(
	conf_t *conf,
	conf_iter_t *iter)
{
	iter->code = conf_db_iter_next(conf, iter);
	switch (iter->code) {
	default:
		log_error("failed to read next configuration item (%s)",
		          knot_strerror(iter->code));
	case KNOT_EOK:
	case KNOT_EOF:
		return;
	}
}

conf_val_t conf_iter_id(
	conf_t *conf,
	conf_iter_t *iter)
{
	conf_val_t val = { NULL };

	val.code = conf_db_iter_id(conf, iter, (uint8_t **)&val.blob,
	                           &val.blob_len);
	switch (val.code) {
	default:
		log_error("failed to read configuration identifier (%s)",
		          knot_strerror(val.code));
	case KNOT_EOK:
		val.item = iter->item;
		return val;
	}
}

void conf_iter_finish(
	conf_t *conf,
	conf_iter_t *iter)
{
	conf_db_iter_finish(conf, iter);
}

size_t conf_val_count(
	conf_val_t *val)
{
	if (val == NULL || val->code != KNOT_EOK) {
		return 0;
	}

	if (!(val->item->flags & YP_FMULTI)) {
		return 1;
	}

	size_t count = 0;
	conf_db_val(val);
	while (val->code == KNOT_EOK) {
		count++;
		conf_db_val_next(val);
	}
	if (val->code != KNOT_EOF) {
		return 0;
	}

	// Reset to the initial state.
	conf_db_val(val);

	return count;
}

void conf_val_next(
	conf_val_t *val)
{
	conf_db_val_next(val);
}

int64_t conf_int(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->item->type == YP_TINT ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TINT));

	if (val->code == KNOT_EOK) {
		conf_db_val(val);
		return yp_int(val->data, val->len);
	} else {
		return val->item->var.i.dflt;
	}
}

bool conf_bool(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->item->type == YP_TBOOL ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TBOOL));

	if (val->code == KNOT_EOK) {
		conf_db_val(val);
		return yp_bool(val->len);
	} else {
		return val->item->var.b.dflt;
	}
}

unsigned conf_opt(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->item->type == YP_TOPT ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TOPT));

	if (val->code == KNOT_EOK) {
		conf_db_val(val);
		return yp_opt(val->data);
	} else {
		return val->item->var.o.dflt;
	}
}

const char* conf_str(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->item->type == YP_TSTR ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TSTR));

	if (val->code == KNOT_EOK) {
		conf_db_val(val);
		return yp_str(val->data);
	} else {
		return val->item->var.s.dflt;
	}
}

char* conf_abs_path(
	conf_val_t *val,
	const char *base_dir)
{
	assert(val != NULL);

	const char *path = conf_str(val);

	if (path[0] == '/') {
		return strdup(path);
	} else {
		char *abs_path;
		if (base_dir == NULL) {
			char *cwd = realpath("./", NULL);
			abs_path = sprintf_alloc("%s/%s", cwd, path);
			free(cwd);
		} else {
			abs_path = sprintf_alloc("%s/%s", base_dir, path);
		}
		return abs_path;
	}
}

const knot_dname_t* conf_dname(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->item->type == YP_TDNAME ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TDNAME));

	if (val->code == KNOT_EOK) {
		conf_db_val(val);
		return yp_dname(val->data);
	} else {
		return (const knot_dname_t *)val->item->var.d.dflt;
	}
}

conf_mod_id_t* conf_mod_id(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->item->type == YP_TDATA);

	conf_mod_id_t *mod_id = NULL;

	if (val->code == KNOT_EOK) {
		conf_db_val(val);

		// Make copy of mod_id because pointers are not persisent in db.
		mod_id = malloc(sizeof(conf_mod_id_t));
		if (mod_id == NULL) {
			return NULL;
		}

		// Copy module name.
		size_t name_len = 1 + val->data[0];
		mod_id->name = malloc(name_len + 1);
		if (mod_id->name == NULL) {
			free(mod_id);
			return NULL;
		}
		memcpy(mod_id->name, val->data, name_len);

		// Copy module identifier.
		mod_id->len = val->len - name_len;
		mod_id->data = malloc(mod_id->len);
		if (mod_id->data == NULL) {
			free(mod_id->name);
			free(mod_id);
			return NULL;
		}
		memcpy(mod_id->data, val->data + name_len, mod_id->len);
	}

	return mod_id;
}

void conf_free_mod_id(
	conf_mod_id_t *mod_id)
{
	free(mod_id->name);
	free(mod_id->data);
	free(mod_id);
}

struct sockaddr_storage conf_addr(
	conf_val_t *val,
	const char *sock_base_dir)
{
	assert(val != NULL);
	assert(val->item->type == YP_TADDR ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TADDR));

	struct sockaddr_storage out = { AF_UNSPEC };

	if (val->code == KNOT_EOK) {
		int port;
		conf_db_val(val);
		out = yp_addr(val->data, val->len, &port);

		// val->data[0] is socket type identifier.
		if (out.ss_family == AF_UNIX && val->data[1] != '/' &&
		    sock_base_dir != NULL) {
			char *tmp = sprintf_alloc("%s/%.*s", sock_base_dir,
			                          (int)val->len - 1,
			                          val->data + 1);
			val->code = sockaddr_set(&out, AF_UNIX, tmp, 0);
			free(tmp);
		} else if (port != -1) {
			sockaddr_port_set(&out, port);
		} else {
			sockaddr_port_set(&out, val->item->var.a.dflt_port);
		}
	} else {
		const char *dflt_socket = val->item->var.a.dflt_socket;
		if (dflt_socket != NULL) {
			if (dflt_socket[0] != '/' && sock_base_dir != NULL) {
				char *tmp = sprintf_alloc("%s/%s", sock_base_dir,
				                          dflt_socket);
				val->code = sockaddr_set(&out, AF_UNIX, tmp, 0);
				free(tmp);
			} else {
				val->code = sockaddr_set(&out, AF_UNIX,
				                         dflt_socket, 0);
			}
		}
	}

	return out;
}

struct sockaddr_storage conf_net(
	conf_val_t *val,
	unsigned *prefix_length)
{
	assert(val != NULL && prefix_length != NULL);
	assert(val->item->type == YP_TNET ||
	       (val->item->type == YP_TREF &&
	        val->item->var.r.ref->var.g.id->type == YP_TNET));

	struct sockaddr_storage out = { AF_UNSPEC };

	if (val->code == KNOT_EOK) {
		int prefix;
		conf_db_val(val);
		out = yp_addr(val->data, val->len, &prefix);
		if (prefix < 0) {
			if (out.ss_family == AF_INET) {
				*prefix_length = IPV4_PREFIXLEN;
			} else if (out.ss_family == AF_INET6) {
				*prefix_length = IPV6_PREFIXLEN;
			}
		} else {
			*prefix_length = prefix;
		}
	} else {
		*prefix_length = 0;
	}

	return out;
}

void conf_data(
	conf_val_t *val)
{
	assert(val != NULL);
	assert(val->item->type == YP_TB64 || val->item->type == YP_TDATA ||
	       (val->item->type == YP_TREF &&
	        (val->item->var.r.ref->var.g.id->type == YP_TB64 ||
	         val->item->var.r.ref->var.g.id->type == YP_TDATA)));

	if (val->code == KNOT_EOK) {
		conf_db_val(val);
	} else {
		val->data = (const uint8_t *)val->item->var.d.dflt;
		val->len = val->item->var.d.dflt_len;
	}
}

static char* dname_to_filename(
	const knot_dname_t *name,
	const char *suffix)
{
	char *str = knot_dname_to_str_alloc(name);
	if (str == NULL) {
		return NULL;
	}

	// Replace possible slashes with underscores.
	for (char *ch = str; *ch != '\0'; ch++) {
		if (*ch == '/') {
			*ch = '_';
		}
	}

	char *out = sprintf_alloc("%s%s", str, suffix);
	free(str);

	return out;
}

char* conf_zonefile(
	conf_t *conf,
	const knot_dname_t *zone)
{
	assert(conf != NULL && zone != NULL);

	// Item 'file' is not template item (cannot use conf_zone_get)! */
	const char *file = NULL;
	conf_val_t file_val = { NULL };
	file_val.code = conf_db_get(conf, &conf->read_txn, C_ZONE, C_FILE,
	                            zone, knot_dname_size(zone), &file_val);
	if (file_val.code == KNOT_EOK) {
		file = conf_str(&file_val);
		if (file != NULL && file[0] == '/') {
			return strdup(file);
		}
	}

	char *abs_storage = NULL;
	conf_val_t storage_val = conf_zone_get(conf, C_STORAGE, zone);
	if (storage_val.code == KNOT_EOK) {
		abs_storage = conf_abs_path(&storage_val, NULL);
		if (abs_storage == NULL) {
			return NULL;
		}
	}

	char *out = NULL;

	if (file == NULL) {
		char *file = dname_to_filename(zone, "zone");
		out = sprintf_alloc("%s/%s", abs_storage, file);
		free(file);
	} else {
		out = sprintf_alloc("%s/%s", abs_storage, file);
	}

	free(abs_storage);

	return out;
}

char* conf_journalfile(
	conf_t *conf,
	const knot_dname_t *zone)
{
	assert(conf != NULL && zone != NULL);

	char *abs_storage = NULL;
	conf_val_t storage_val = conf_zone_get(conf, C_STORAGE, zone);
	if (storage_val.code == KNOT_EOK) {
		abs_storage = conf_abs_path(&storage_val, NULL);
		if (abs_storage == NULL) {
			return NULL;
		}
	}

	char *name = dname_to_filename(zone, "diff.db");
	char *out = sprintf_alloc("%s/%s", abs_storage, name);
	free(name);
	free(abs_storage);

	return out;
}

size_t conf_udp_threads(
	conf_t *conf)
{
	conf_val_t val = conf_get(conf, C_SRV, C_WORKERS);
	int64_t workers = conf_int(&val);
	if (workers < 1) {
		return dt_optimal_size();
	}

	return workers;
}

size_t conf_tcp_threads(
	conf_t *conf)
{
	size_t thrcount = conf_udp_threads(conf);
	return MAX(thrcount * 2, CONF_XFERS);
}

int conf_bg_threads(
	conf_t *conf)
{
	conf_val_t val = conf_get(conf, C_SRV, C_BG_WORKERS);
	int64_t bg_workers = conf_int(&val);
	if (bg_workers < 1) {
		return MIN(dt_optimal_size(), CONF_XFERS);
	}

	return bg_workers;
}

void conf_user(
	conf_t *conf,
	int *uid,
	int *gid)
{
	assert(uid);
	assert(gid);

	int new_uid = getuid();
	int new_gid = getgid();

	conf_val_t val = conf_get(conf, C_SRV, C_USER);
	if (val.code == KNOT_EOK) {
		const char *user = conf_str(&val);

		// Search for user:group separator.
		char *sep_pos = strchr(user, ':');
		if (sep_pos != NULL) {
			// Process group name.
			struct group *grp = getgrnam(sep_pos + 1);
			if (grp != NULL) {
				new_gid = grp->gr_gid;
			} else {
				log_error("invalid group name '%s'", sep_pos + 1);
			}

			// Cut off group part.
			*sep_pos = '\0';
		}

		// Process user name.
		struct passwd *pwd = getpwnam(user);
		if (pwd != NULL) {
			new_uid = pwd->pw_uid;
		} else {
			log_error("invalid user name '%s'", user);
		}
	}

	*uid = new_uid;
	*gid = new_gid;
}

conf_remote_t conf_remote(
	conf_t *conf,
	conf_val_t *id)
{
	conf_remote_t out = { { AF_UNSPEC } };

	conf_val_t rundir_val = conf_get(conf, C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&rundir_val, NULL);

	// Get remote address.
	conf_val_t val = conf_id_get(conf, C_RMT, C_ADDR, id);
	if (val.code != KNOT_EOK) {
		log_error("invalid remote in configuration");
		return out;
	}
	out.addr = conf_addr(&val, rundir);

	// Get outgoing address (optional).
	val = conf_id_get(conf, C_RMT, C_VIA, id);
	out.via = conf_addr(&val, rundir);

	// Get TSIG key (optional).
	conf_val_t key_id = conf_id_get(conf, C_RMT, C_KEY, id);
	if (key_id.code == KNOT_EOK) {
		out.key.name = (knot_dname_t *)conf_dname(&key_id);

		val = conf_id_get(conf, C_KEY, C_ALG, &key_id);
		out.key.algorithm = conf_opt(&val);

		val = conf_id_get(conf, C_KEY, C_SECRET, &key_id);
		conf_data(&val);
		out.key.secret.data = (uint8_t *)val.data;
		out.key.secret.size = val.len;
	}

	free(rundir);

	return out;
}
