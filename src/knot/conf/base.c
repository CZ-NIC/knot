/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>
#include <urcu.h>

#include "knot/conf/base.h"
#include "knot/conf/confdb.h"
#include "knot/conf/module.h"
#include "knot/conf/tools.h"
#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"
#include "libknot/libknot.h"
#include "libknot/yparser/ypformat.h"
#include "libknot/yparser/yptrafo.h"
#include "contrib/files.h"
#include "contrib/mempattern.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"
#include "contrib/ucw/mempool.h"

// The active configuration.
conf_t *s_conf;

conf_t* conf(void) {
	return s_conf;
}

static int init_and_check(
	conf_t *conf,
	conf_flag_t flags)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	knot_db_txn_t txn;
	unsigned txn_flags = (flags & CONF_FREADONLY) ? KNOT_DB_RDONLY : 0;
	int ret = conf->api->txn_begin(conf->db, &txn, txn_flags);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Initialize the database.
	if (!(flags & CONF_FREADONLY)) {
		ret = conf_db_init(conf, &txn, false);
		if (ret != KNOT_EOK) {
			conf->api->txn_abort(&txn);
			return ret;
		}
	}

	// Check the database.
	if (!(flags & CONF_FNOCHECK)) {
		ret = conf_db_check(conf, &txn);
		if (ret < KNOT_EOK) {
			conf->api->txn_abort(&txn);
			return ret;
		}
	}

	if (flags & CONF_FREADONLY) {
		conf->api->txn_abort(&txn);
		return KNOT_EOK;
	} else {
		return conf->api->txn_commit(&txn);
	}
}

int conf_refresh_txn(
	conf_t *conf)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	// Close previously opened transaction.
	conf->api->txn_abort(&conf->read_txn);

	return conf->api->txn_begin(conf->db, &conf->read_txn, KNOT_DB_RDONLY);
}

void conf_refresh_hostname(
	conf_t *conf)
{
	if (conf == NULL) {
		return;
	}

	free(conf->hostname);
	conf->hostname = sockaddr_hostname();
	if (conf->hostname == NULL) {
		// Empty hostname fallback, NULL cannot be passed to strlen!
		conf->hostname = strdup("");
	}
}

static void init_cache(
	conf_t *conf)
{
	conf_val_t val = conf_get(conf, C_SRV, C_MAX_IPV4_UDP_PAYLOAD);
	if (val.code != KNOT_EOK) {
		val = conf_get(conf, C_SRV, C_MAX_UDP_PAYLOAD);
	}
	conf->cache.srv_max_ipv4_udp_payload = conf_int(&val);

	val = conf_get(conf, C_SRV, C_MAX_IPV6_UDP_PAYLOAD);
	if (val.code != KNOT_EOK) {
		val = conf_get(conf, C_SRV, C_MAX_UDP_PAYLOAD);
	}
	conf->cache.srv_max_ipv6_udp_payload = conf_int(&val);

	val = conf_get(conf, C_SRV, C_TCP_HSHAKE_TIMEOUT);
	conf->cache.srv_tcp_hshake_timeout = conf_int(&val);

	val = conf_get(conf, C_SRV, C_TCP_IDLE_TIMEOUT);
	conf->cache.srv_tcp_idle_timeout = conf_int(&val);

	val = conf_get(conf, C_SRV, C_TCP_REPLY_TIMEOUT);
	conf->cache.srv_tcp_reply_timeout = conf_int(&val);

	val = conf_get(conf, C_SRV, C_MAX_TCP_CLIENTS);
	conf->cache.srv_max_tcp_clients = conf_int(&val);

	val = conf_get(conf, C_CTL, C_TIMEOUT);
	conf->cache.ctl_timeout = conf_int(&val) * 1000;

	conf->cache.srv_nsid = conf_get(conf, C_SRV, C_NSID);
}

int conf_new(
	conf_t **conf,
	const yp_item_t *schema,
	const char *db_dir,
	conf_flag_t flags)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	conf_t *out = malloc(sizeof(conf_t));
	if (out == NULL) {
		return KNOT_ENOMEM;
	}
	memset(out, 0, sizeof(conf_t));

	// Initialize query modules list.
	init_list(&out->query_modules);

	// Initialize config schema.
	int ret = yp_schema_copy(&out->schema, schema);
	if (ret != KNOT_EOK) {
		goto new_error;
	}

	// Initialize a config mempool.
	out->mm = malloc(sizeof(knot_mm_t));
	if (out->mm == NULL) {
		ret = KNOT_ENOMEM;
		goto new_error;
	}
	mm_ctx_mempool(out->mm, MM_DEFAULT_BLKSIZE);

	// Set the DB api.
	out->api = knot_db_lmdb_api();
	struct knot_db_lmdb_opts lmdb_opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	lmdb_opts.mapsize = (size_t)CONF_MAPSIZE * 1024 * 1024;
	lmdb_opts.maxreaders = CONF_MAX_DB_READERS;
	lmdb_opts.flags.env = KNOT_DB_LMDB_NOTLS;

	// Open the database.
	if (db_dir == NULL) {
		// Prepare a temporary database.
		char tpl[] = "/tmp/knot-confdb.XXXXXX";
		lmdb_opts.path = mkdtemp(tpl);
		if (lmdb_opts.path == NULL) {
			CONF_LOG(LOG_ERR, "failed to create temporary directory (%s)",
			         knot_strerror(knot_map_errno()));
			ret = KNOT_ENOMEM;
			goto new_error;
		}

		ret = out->api->init(&out->db, out->mm, &lmdb_opts);

		// Remove the database to ensure it is temporary.
		if (!remove_path(lmdb_opts.path)) {
			CONF_LOG(LOG_WARNING, "failed to purge temporary directory '%s'",
			         lmdb_opts.path);
		}
	} else {
		// Set the specified database.
		lmdb_opts.path = db_dir;

		// Set the read-only mode.
		if (flags & CONF_FREADONLY) {
			lmdb_opts.flags.env |= KNOT_DB_LMDB_RDONLY;
		}

		ret = out->api->init(&out->db, out->mm, &lmdb_opts);
	}
	if (ret != KNOT_EOK) {
		goto new_error;
	}

	// Initialize and check the database.
	ret = init_and_check(out, flags);
	if (ret != KNOT_EOK) {
		goto new_error;
	}

	// Open common read-only transaction.
	ret = conf_refresh_txn(out);
	if (ret != KNOT_EOK) {
		goto new_error;
	}

	// Cache the current hostname.
	if (!(flags & CONF_FNOHOSTNAME)) {
		conf_refresh_hostname(out);
	}

	// Initialize cached values.
	init_cache(out);

	// Load module schemas.
	if (flags & (CONF_FREQMODULES | CONF_FOPTMODULES)) {
		ret = conf_mod_load_common(out);
		if (ret != KNOT_EOK && (flags & CONF_FREQMODULES)) {
			goto new_error;
		}

		for (conf_iter_t iter = conf_iter(out, C_MODULE);
		     iter.code == KNOT_EOK; conf_iter_next(out, &iter)) {
			conf_val_t id = conf_iter_id(out, &iter);
			conf_val_t file = conf_id_get(out, C_MODULE, C_FILE, &id);
			ret = conf_mod_load_extra(out, conf_str(&id), conf_str(&file), false);
			if (ret != KNOT_EOK && (flags & CONF_FREQMODULES)) {
				conf_iter_finish(out, &iter);
				goto new_error;
			}
		}

		conf_mod_load_purge(out, false);
	}

	*conf = out;

	return KNOT_EOK;
new_error:
	conf_free(out);

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

	// Initialize config schema.
	int ret = yp_schema_copy(&out->schema, s_conf->schema);
	if (ret != KNOT_EOK) {
		free(out);
		return ret;
	}

	// Set shared items.
	out->api = s_conf->api;
	out->mm = s_conf->mm;
	out->db = s_conf->db;

	// Open common read-only transaction.
	ret = conf_refresh_txn(out);
	if (ret != KNOT_EOK) {
		yp_schema_free(out->schema);
		free(out);
		return ret;
	}

	// Copy the filename.
	if (s_conf->filename != NULL) {
		out->filename = strdup(s_conf->filename);
	}

	// Copy the hostname.
	if (s_conf->hostname != NULL) {
		out->hostname = strdup(s_conf->hostname);
	}

	// Initialize query modules list.
	init_list(&out->query_modules);

	// Initialize cached values.
	init_cache(out);

	out->is_clone = true;

	*conf = out;

	return KNOT_EOK;
}

conf_t *conf_update(
	conf_t *conf,
	conf_update_flag_t flags)
{
	// Remove the clone flag for new master configuration.
	if (conf != NULL) {
		conf->is_clone = false;

		if ((flags & CONF_UPD_FCONFIO) && s_conf != NULL) {
			conf->io.flags = s_conf->io.flags;
			conf->io.zones = s_conf->io.zones;
		}
		if ((flags & CONF_UPD_FMODULES) && s_conf != NULL) {
			list_dup(&conf->query_modules, &s_conf->query_modules,
			         sizeof(knotd_mod_t));
			conf->query_plan = s_conf->query_plan;
		}
	}

	conf_t **current_conf = &s_conf;
	conf_t *old_conf = rcu_xchg_pointer(current_conf, conf);

	synchronize_rcu();

	if (old_conf != NULL) {
		// Remove the clone flag if a single configuration.
		old_conf->is_clone = (conf != NULL) ? true : false;

		if (flags & CONF_UPD_FCONFIO) {
			old_conf->io.zones = NULL;
		}
		if (flags & CONF_UPD_FMODULES) {
			WALK_LIST_FREE(old_conf->query_modules);
			old_conf->query_plan = NULL;
		}
		if (!(flags & CONF_UPD_FNOFREE)) {
			conf_free(old_conf);
			old_conf = NULL;
		}
	}

	return old_conf;
}

void conf_free(
	conf_t *conf)
{
	if (conf == NULL) {
		return;
	}

	yp_schema_free(conf->schema);
	free(conf->filename);
	free(conf->hostname);
	if (conf->api != NULL) {
		conf->api->txn_abort(&conf->read_txn);
	}

	if (conf->io.txn != NULL && conf->api != NULL) {
		conf->api->txn_abort(conf->io.txn_stack);
	}
	if (conf->io.zones != NULL) {
		trie_free(conf->io.zones);
		mm_free(conf->mm, conf->io.zones);
	}

	conf_mod_load_purge(conf, false);
	conf_deactivate_modules(&conf->query_modules, &conf->query_plan);
	conf_mod_unload_shared(conf);

	if (!conf->is_clone) {
		if (conf->api != NULL) {
			conf->api->deinit(conf->db);
		}
		if (conf->mm != NULL) {
			mp_delete(conf->mm->ctx);
			free(conf->mm);
		}
	}

	free(conf);
}

#define CONF_LOG_LINE(file, line, msg, ...) do { \
	CONF_LOG(LOG_ERR, "%s%s%sline %zu, " msg, \
	         (file != NULL ? "file '" : ""), (file != NULL ? file : ""), \
	         (file != NULL ? "', " : ""), line, ##__VA_ARGS__); \
	} while (0)

static void log_parser_err(
	yp_parser_t *parser,
	int ret)
{
	CONF_LOG_LINE(parser->file.name, parser->line_count,
	              "item '%.*s', value '%.*s' (%s)",
	              (int)parser->key_len, parser->key,
	              (int)parser->data_len, parser->data,
	              knot_strerror(ret));
}

static void log_call_err(
	yp_parser_t *parser,
	knotd_conf_check_args_t *args,
	int ret)
{
	CONF_LOG_LINE(args->extra->file_name, args->extra->line,
	              "item '%s', value '%.*s' (%s)", args->item->name + 1,
	              (int)parser->data_len, parser->data,
	              args->err_str != NULL ? args->err_str : knot_strerror(ret));
}

static void log_prev_err(
	knotd_conf_check_args_t *args,
	int ret)
{
	char buff[512] = { 0 };
	size_t len = sizeof(buff);

	// Get the previous textual identifier.
	if ((args->item->flags & YP_FMULTI) != 0) {
		if (yp_item_to_txt(args->item->var.g.id, args->id, args->id_len,
		                   buff, &len, YP_SNOQUOTE) != KNOT_EOK) {
			buff[0] = '\0';
		}
	}

	CONF_LOG_LINE(args->extra->file_name, args->extra->line,
	              "%s '%s' (%s)", args->item->name + 1, buff,
	              args->err_str != NULL ? args->err_str : knot_strerror(ret));
}

static int finalize_previous_section(
	conf_t *conf,
	knot_db_txn_t *txn,
	yp_parser_t *parser,
	yp_check_ctx_t *ctx)
{
	yp_node_t *node = &ctx->nodes[0];

	// Return if no previous section or include or empty multi-section.
	if (node->item == NULL || node->item->type != YP_TGRP ||
	    (node->id_len == 0 && (node->item->flags & YP_FMULTI) != 0)) {
		return KNOT_EOK;
	}

	knotd_conf_check_extra_t extra = {
		.conf = conf,
		.txn = txn,
		.file_name = parser->file.name,
		.line = parser->line_count
	};
	knotd_conf_check_args_t args = {
		.item = node->item,
		.id = node->id,
		.id_len = node->id_len,
		.data = node->data,
		.data_len = node->data_len,
		.extra = &extra
	};

	int ret = conf_exec_callbacks(&args);
	if (ret != KNOT_EOK) {
		log_prev_err(&args, ret);
	}

	return ret;
}

static int finalize_item(
	conf_t *conf,
	knot_db_txn_t *txn,
	yp_parser_t *parser,
	yp_check_ctx_t *ctx)
{
	yp_node_t *node = &ctx->nodes[ctx->current];

	// Section callbacks are executed before another section.
	if (node->item->type == YP_TGRP && node->id_len == 0) {
		return KNOT_EOK;
	}

	knotd_conf_check_extra_t extra = {
		.conf = conf,
		.txn = txn,
		.file_name = parser->file.name,
		.line = parser->line_count
	};
	knotd_conf_check_args_t args = {
		.item = (parser->event == YP_EID) ? node->item->var.g.id : node->item,
		.id = node->id,
		.id_len = node->id_len,
		.data = node->data,
		.data_len = node->data_len,
		.extra = &extra
	};

	int ret = conf_exec_callbacks(&args);
	if (ret != KNOT_EOK) {
		log_call_err(parser, &args, ret);
	}

	return ret;
}

int conf_parse(
	conf_t *conf,
	knot_db_txn_t *txn,
	const char *input,
	bool is_file)
{
	if (conf == NULL || txn == NULL || input == NULL) {
		return KNOT_EINVAL;
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
	yp_check_ctx_t *ctx = yp_schema_check_init(&conf->schema);
	if (ctx == NULL) {
		ret = KNOT_ENOMEM;
		goto parse_error;
	}

	int check_ret = KNOT_EOK;

	// Parse the configuration.
	while ((ret = yp_parse(parser)) == KNOT_EOK) {
		if (parser->event == YP_EKEY0 || parser->event == YP_EID) {
			check_ret = finalize_previous_section(conf, txn, parser, ctx);
			if (check_ret != KNOT_EOK) {
				break;
			}
		}

		check_ret = yp_schema_check_parser(ctx, parser);
		if (check_ret != KNOT_EOK) {
			log_parser_err(parser, check_ret);
			break;
		}

		yp_node_t *node = &ctx->nodes[ctx->current];
		yp_node_t *parent = node->parent;

		if (parent == NULL) {
			check_ret = conf_db_set(conf, txn, node->item->name,
			                        NULL, node->id, node->id_len,
			                        node->data, node->data_len);
		} else {
			check_ret = conf_db_set(conf, txn, parent->item->name,
			                        node->item->name, parent->id,
			                        parent->id_len, node->data,
			                        node->data_len);
		}
		if (check_ret != KNOT_EOK) {
			log_parser_err(parser, check_ret);
			break;
		}

		check_ret = finalize_item(conf, txn, parser, ctx);
		if (check_ret != KNOT_EOK) {
			break;
		}
	}

	if (ret == KNOT_EOF) {
		ret = finalize_previous_section(conf, txn, parser, ctx);
	} else if (ret != KNOT_EOK) {
		log_parser_err(parser, ret);
	} else {
		ret = check_ret;
	}

	yp_schema_check_deinit(ctx);
parse_error:
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

	knot_db_txn_t txn;
	ret = conf->api->txn_begin(conf->db, &txn, 0);
	if (ret != KNOT_EOK) {
		goto import_error;
	}

	// Initialize the DB.
	ret = conf_db_init(conf, &txn, true);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		goto import_error;
	}

	// Parse and import given file.
	ret = conf_parse(conf, &txn, input, is_file);
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		goto import_error;
	}
	// Load purge must be here as conf_parse may be called recursively!
	conf_mod_load_purge(conf, false);

	// Commit new configuration.
	ret = conf->api->txn_commit(&txn);
	if (ret != KNOT_EOK) {
		goto import_error;
	}

	// Update read-only transaction.
	ret = conf_refresh_txn(conf);
	if (ret != KNOT_EOK) {
		goto import_error;
	}

	// Update cached values.
	init_cache(conf);

	// Reset the filename.
	free(conf->filename);
	conf->filename = NULL;
	if (is_file) {
		conf->filename = strdup(input);
	}

	ret = KNOT_EOK;
import_error:

	return ret;
}

static int export_group_name(
	FILE *fp,
	const yp_item_t *group,
	char *out,
	size_t out_len,
	yp_style_t style)
{
	int ret = yp_format_key0(group, NULL, 0, out, out_len, style, true, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	fprintf(fp, "%s", out);

	return KNOT_EOK;
}

static int export_group(
	conf_t *conf,
	FILE *fp,
	const yp_item_t *group,
	const uint8_t *id,
	size_t id_len,
	char *out,
	size_t out_len,
	yp_style_t style,
	bool *exported)
{
	// Export the multi-group name.
	if ((group->flags & YP_FMULTI) != 0 && !(*exported)) {
		int ret = export_group_name(fp, group, out, out_len, style);
		if (ret != KNOT_EOK) {
			return ret;
		}
		*exported = true;
	}

	// Iterate through all possible group items.
	for (yp_item_t *item = group->sub_items; item->name != NULL; item++) {
		// Export the identifier.
		if (group->var.g.id == item && (group->flags & YP_FMULTI) != 0) {
			int ret = yp_format_id(group->var.g.id, id, id_len, out,
			                       out_len, style);
			if (ret != KNOT_EOK) {
				return ret;
			}
			fprintf(fp, "%s", out);
			continue;
		}

		conf_val_t bin;
		conf_db_get(conf, &conf->read_txn, group->name, item->name,
		            id, id_len, &bin);
		if (bin.code == KNOT_ENOENT) {
			continue;
		} else if (bin.code != KNOT_EOK) {
			return bin.code;
		}

		// Export the single-group name if an item is set.
		if ((group->flags & YP_FMULTI) == 0 && !(*exported)) {
			int ret = export_group_name(fp, group, out, out_len, style);
			if (ret != KNOT_EOK) {
				return ret;
			}
			*exported = true;
		}

		// Format single/multiple-valued item.
		size_t values = conf_val_count(&bin);
		for (size_t i = 1; i <= values; i++) {
			conf_val(&bin);
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

	if (*exported) {
		fprintf(fp, "\n");
	}

	return KNOT_EOK;
}

static int export_item(
	conf_t *conf,
	FILE *fp,
	const yp_item_t *item,
	char *buff,
	size_t buff_len,
	yp_style_t style)
{
	bool exported = false;

	// Skip non-group items (include).
	if (item->type != YP_TGRP) {
		return KNOT_EOK;
	}

	// Export simple group without identifiers.
	if (!(item->flags & YP_FMULTI)) {
		return export_group(conf, fp, item, NULL, 0, buff, buff_len,
		                    style, &exported);
	}

	// Iterate over all identifiers.
	conf_iter_t iter;
	int ret = conf_db_iter_begin(conf, &conf->read_txn, item->name, &iter);
	switch (ret) {
	case KNOT_EOK:
		break;
	case KNOT_ENOENT:
		return KNOT_EOK;
	default:
		return ret;
	}

	while (ret == KNOT_EOK) {
		const uint8_t *id;
		size_t id_len;
		ret = conf_db_iter_id(conf, &iter, &id, &id_len);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf, &iter);
			return ret;
		}

		// Export group with identifiers.
		ret = export_group(conf, fp, item, id, id_len, buff, buff_len,
		                   style, &exported);
		if (ret != KNOT_EOK) {
			conf_db_iter_finish(conf, &iter);
			return ret;
		}

		ret = conf_db_iter_next(conf, &iter);
	}
	if (ret != KNOT_EOF) {
		return ret;
	}

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
		return knot_map_errno();
	}

	fprintf(fp, "# Configuration export (Knot DNS %s)\n\n", PACKAGE_VERSION);

	const char *mod_prefix = KNOTD_MOD_NAME_PREFIX;
	const size_t mod_prefix_len = strlen(mod_prefix);

	int ret;

	// Iterate over the schema.
	for (yp_item_t *item = conf->schema; item->name != NULL; item++) {
		// Don't export module sections again.
		if (strncmp(item->name + 1, mod_prefix, mod_prefix_len) == 0) {
			break;
		}

		// Export module sections before the template section.
		if (strcmp(item->name + 1, C_TPL + 1) == 0) {
			for (yp_item_t *mod = item + 1; mod->name != NULL; mod++) {
				// Skip non-module sections.
				if (strncmp(mod->name + 1, mod_prefix, mod_prefix_len) != 0) {
					continue;
				}

				// Export module section.
				ret = export_item(conf, fp, mod, buff, buff_len, style);
				if (ret != KNOT_EOK) {
					goto export_error;
				}
			}
		}

		// Export non-module section.
		ret = export_item(conf, fp, item, buff, buff_len, style);
		if (ret != KNOT_EOK) {
			goto export_error;
		}
	}

	ret = KNOT_EOK;
export_error:
	fclose(fp);
	free(buff);

	return ret;
}
