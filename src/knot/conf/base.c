/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
#include "contrib/json.h"
#include "contrib/sockaddr.h"
#include "contrib/string.h"

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

static void refresh_hostname(
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

static int infinite_adjust(
	int timeout)
{
	return (timeout > 0) ? timeout : -1;
}

static void init_cache(
	conf_t *conf,
	bool reinit_cache)
{
	/*
	 * For UDP, TCP, XDP, and background workers, cache the number of running
	 * workers. Cache the setting of TCP reuseport too. These values
	 * can't change in runtime, while config data can.
	 */

	static bool   first_init = true;
	static bool   running_tcp_reuseport;
	static bool   running_socket_affinity;
	static bool   running_xdp_udp;
	static bool   running_xdp_tcp;
	static uint16_t running_xdp_quic;
	static bool   running_route_check;
	static uint16_t running_ring_size;
	static uint16_t running_busypoll_budget;
	static uint16_t running_busypoll_timeout;
	static size_t running_udp_threads;
	static size_t running_tcp_threads;
	static size_t running_xdp_threads;
	static size_t running_bg_threads;
	static size_t running_quic_clients;
	static size_t running_quic_outbufs;
	static size_t running_quic_idle;

	if (first_init || reinit_cache) {
		running_tcp_reuseport = conf_get_bool(conf, C_SRV, C_TCP_REUSEPORT);
		running_socket_affinity = conf_get_bool(conf, C_SRV, C_SOCKET_AFFINITY);
		running_xdp_udp = conf_get_bool(conf, C_XDP, C_UDP);
		running_xdp_tcp = conf_get_bool(conf, C_XDP, C_TCP);
		running_xdp_quic = 0;
		if (conf_get_bool(conf, C_XDP, C_QUIC)) {
			running_xdp_quic = conf_get_int(conf, C_XDP, C_QUIC_PORT);
		}
		running_route_check = conf_get_bool(conf, C_XDP, C_ROUTE_CHECK);
		running_ring_size = conf_get_int(conf, C_XDP, C_RING_SIZE);
		running_busypoll_budget = conf_get_int(conf, C_XDP, C_BUSYPOLL_BUDGET);
		running_busypoll_timeout = conf_get_int(conf, C_XDP, C_BUSYPOLL_TIMEOUT);
		running_udp_threads = conf_udp_threads(conf);
		running_tcp_threads = conf_tcp_threads(conf);
		running_xdp_threads = conf_xdp_threads(conf);
		running_bg_threads = conf_bg_threads(conf);
		running_quic_clients = conf_get_int(conf, C_SRV, C_QUIC_MAX_CLIENTS);
		running_quic_outbufs = conf_get_int(conf, C_SRV, C_QUIC_OUTBUF_MAX_SIZE);
		running_quic_idle = conf_get_int(conf, C_SRV, C_QUIC_IDLE_CLOSE);

		first_init = false;
	}

	conf_val_t val = conf_get(conf, C_SRV, C_UDP_MAX_PAYLOAD_IPV4);
	if (val.code != KNOT_EOK) {
		val = conf_get(conf, C_SRV, C_UDP_MAX_PAYLOAD);
	}
	conf->cache.srv_udp_max_payload_ipv4 = conf_int(&val);

	val = conf_get(conf, C_SRV, C_UDP_MAX_PAYLOAD_IPV6);
	if (val.code != KNOT_EOK) {
		val = conf_get(conf, C_SRV, C_UDP_MAX_PAYLOAD);
	}
	conf->cache.srv_udp_max_payload_ipv6 = conf_int(&val);

	val = conf_get(conf, C_SRV, C_TCP_IDLE_TIMEOUT);
	conf->cache.srv_tcp_idle_timeout = conf_int(&val);

	val = conf_get(conf, C_SRV, C_TCP_IO_TIMEOUT);
	conf->cache.srv_tcp_io_timeout = infinite_adjust(conf_int(&val));

	val = conf_get(conf, C_SRV, C_TCP_RMT_IO_TIMEOUT);
	conf->cache.srv_tcp_remote_io_timeout = infinite_adjust(conf_int(&val));

	val = conf_get(conf, C_SRV, C_TCP_FASTOPEN);
	conf->cache.srv_tcp_fastopen = conf_bool(&val);

	conf->cache.srv_quic_max_clients = running_quic_clients;

	conf->cache.srv_quic_idle_close = running_quic_idle;

	conf->cache.srv_quic_obuf_max_size = running_quic_outbufs;

	conf->cache.srv_tcp_reuseport = running_tcp_reuseport;

	conf->cache.srv_socket_affinity = running_socket_affinity;

	val = conf_get(conf, C_SRV, C_DBUS_EVENT);
	while (val.code == KNOT_EOK) {
		conf->cache.srv_dbus_event |= conf_opt(&val);
		conf_val_next(&val);
	}

	conf->cache.srv_udp_threads = running_udp_threads;

	conf->cache.srv_tcp_threads = running_tcp_threads;

	conf->cache.srv_xdp_threads = running_xdp_threads;

	conf->cache.srv_bg_threads = running_bg_threads;

	conf->cache.srv_tcp_max_clients = conf_tcp_max_clients(conf);

	val = conf_get(conf, C_XDP, C_TCP_MAX_CLIENTS);
	conf->cache.xdp_tcp_max_clients = conf_int(&val);

	val = conf_get(conf, C_XDP, C_TCP_INBUF_MAX_SIZE);
	conf->cache.xdp_tcp_inbuf_max_size = conf_int(&val);

	val = conf_get(conf, C_XDP, C_TCP_OUTBUF_MAX_SIZE);
	conf->cache.xdp_tcp_outbuf_max_size = conf_int(&val);

	val = conf_get(conf, C_XDP, C_TCP_IDLE_CLOSE);
	conf->cache.xdp_tcp_idle_close = conf_int(&val);

	val = conf_get(conf, C_XDP, C_TCP_IDLE_RESET);
	conf->cache.xdp_tcp_idle_reset = conf_int(&val);

	val = conf_get(conf, C_XDP, C_TCP_RESEND);
	conf->cache.xdp_tcp_idle_resend = conf_int(&val);

	conf->cache.xdp_udp = running_xdp_udp;

	conf->cache.xdp_tcp = running_xdp_tcp;

	conf->cache.xdp_quic = running_xdp_quic;

	conf->cache.xdp_route_check = running_route_check;

	conf->cache.xdp_ring_size = running_ring_size;

	conf->cache.xdp_busypoll_budget = running_busypoll_budget;

	conf->cache.xdp_busypoll_timeout = running_busypoll_timeout;

	val = conf_get(conf, C_CTL, C_TIMEOUT);
	conf->cache.ctl_timeout = conf_int(&val) * 1000;
	/* infinite_adjust() call isn't needed, 0 is adjusted later anyway. */

	val = conf_get(conf, C_SRV, C_NSID);
	if (val.code != KNOT_EOK) {
		if (conf->hostname == NULL) {
			conf->cache.srv_nsid_data = (const uint8_t *)"";
			conf->cache.srv_nsid_len = 0;
		} else {
			conf->cache.srv_nsid_data = (const uint8_t *)conf->hostname;
			conf->cache.srv_nsid_len = strlen(conf->hostname);
		}
	} else {
		conf->cache.srv_nsid_data = conf_bin(&val, &conf->cache.srv_nsid_len);
	}

	val = conf_get(conf, C_SRV, C_ECS);
	conf->cache.srv_ecs = conf_bool(&val);

	val = conf_get(conf, C_SRV, C_ANS_ROTATION);
	conf->cache.srv_ans_rotate = conf_bool(&val);

	val = conf_get(conf, C_SRV, C_AUTO_ACL);
	conf->cache.srv_auto_acl = conf_bool(&val);

	val = conf_get(conf, C_SRV, C_PROXY_ALLOWLIST);
	conf->cache.srv_proxy_enabled = (conf_val_count(&val) > 0);

	val = conf_get(conf, C_SRV, C_IDENT);
	if (val.code == KNOT_EOK) {
		conf->cache.srv_ident = conf_str(&val); // Can be NULL!
	} else {
		conf->cache.srv_ident = conf->hostname;
	}

	val = conf_get(conf, C_SRV, C_VERSION);
	if (val.code == KNOT_EOK) {
		conf->cache.srv_has_version = true;
		conf->cache.srv_version = conf_str(&val); // Can be NULL!
	} else {
		conf->cache.srv_has_version = false;
		conf->cache.srv_version = "Knot DNS " PACKAGE_VERSION;
	}
}

int conf_new(
	conf_t **conf,
	const yp_item_t *schema,
	const char *db_dir,
	size_t max_conf_size,
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

	// Initialize config schema.
	int ret = yp_schema_copy(&out->schema, schema);
	if (ret != KNOT_EOK) {
		goto new_error;
	}

	// Initialize query modules list.
	out->query_modules = malloc(sizeof(list_t));
	if (out->query_modules == NULL) {
		ret = KNOT_ENOMEM;
		goto new_error;
	}
	init_list(out->query_modules);

	// Set the DB api.
	out->mapsize = max_conf_size;
	out->api = knot_db_lmdb_api();
	struct knot_db_lmdb_opts lmdb_opts = KNOT_DB_LMDB_OPTS_INITIALIZER;
	lmdb_opts.mapsize = out->mapsize;
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

		ret = out->api->init(&out->db, NULL, &lmdb_opts);

		// Remove the database to ensure it is temporary.
		int ret2 = remove_path(lmdb_opts.path, false);
		if (ret2 != KNOT_EOK) {
			CONF_LOG(LOG_WARNING, "failed to purge temporary directory '%s' (%s)",
			         lmdb_opts.path, knot_strerror(ret2));
		}
	} else {
		// Set the specified database.
		lmdb_opts.path = db_dir;

		// Set the read-only mode.
		if (flags & CONF_FREADONLY) {
			lmdb_opts.flags.env |= KNOT_DB_LMDB_RDONLY;
		}

		ret = out->api->init(&out->db, NULL, &lmdb_opts);
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
		refresh_hostname(out);
	}

	// Initialize cached values.
	init_cache(out, false);

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
			ret = conf_mod_load_extra(out, conf_str(&id), conf_str(&file),
			                          MOD_EXPLICIT);
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
	out->db = s_conf->db;

	// Initialize query modules list.
	out->query_modules = malloc(sizeof(list_t));
	if (out->query_modules == NULL) {
		yp_schema_free(out->schema);
		free(out);
		return KNOT_ENOMEM;
	}
	init_list(out->query_modules);

	// Open common read-only transaction.
	ret = conf_refresh_txn(out);
	if (ret != KNOT_EOK) {
		free(out->query_modules);
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

	out->catalog = s_conf->catalog;

	// Initialize cached values.
	init_cache(out, false);

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
			free(conf->query_modules);
			conf->query_modules = s_conf->query_modules;
			conf->query_plan = s_conf->query_plan;
			knot_dynarray_foreach(mod, module_t *, module, s_conf->modules) {
				mod_dynarray_add(&conf->modules, module);
			}
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
			old_conf->query_modules = NULL;
			old_conf->query_plan = NULL;
			old_conf->modules.size = 0; // Preserve shared modules.
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
	}

	conf_mod_load_purge(conf, false);
	conf_deactivate_modules(conf->query_modules, &conf->query_plan);
	free(conf->query_modules);
	conf_mod_unload_shared(conf);

	if (!conf->is_clone) {
		if (conf->api != NULL) {
			conf->api->deinit(conf->db);
		}
	}

	free(conf);
}

#define CONF_LOG_LINE(file, line, msg, ...) do { \
	CONF_LOG(LOG_ERR, "%s%s%sline %zu" msg, \
	         (file != NULL ? "file '" : ""), (file != NULL ? file : ""), \
	         (file != NULL ? "', " : ""), line, ##__VA_ARGS__); \
	} while (0)

static void log_parser_err(
	yp_parser_t *parser,
	int ret)
{
	if (parser->event == YP_ENULL) {
		CONF_LOG_LINE(parser->file.name, parser->line_count,
		              " (%s)", knot_strerror(ret));
	} else {
		CONF_LOG_LINE(parser->file.name, parser->line_count,
		              ", item '%s'%s%.*s%s (%s)", parser->key,
		              (parser->data_len > 0) ? ", value '"  : "",
		              (int)parser->data_len,
		              (parser->data_len > 0) ? parser->data : "",
		              (parser->data_len > 0) ? "'"          : "",
		              knot_strerror(ret));
	}
}

static void log_parser_schema_err(
	yp_parser_t *parser,
	int ret)
{
	// Emit better message for 'unknown module' error.
	if (ret == KNOT_YP_EINVAL_ITEM && parser->event == YP_EKEY0 &&
	    strncmp(parser->key, KNOTD_MOD_NAME_PREFIX, strlen(KNOTD_MOD_NAME_PREFIX)) == 0) {
		CONF_LOG_LINE(parser->file.name, parser->line_count,
		              ", unknown module '%s'", parser->key);
	} else {
		log_parser_err(parser, ret);
	}
}

static void log_call_err(
	yp_parser_t *parser,
	knotd_conf_check_args_t *args,
	int ret)
{
	CONF_LOG_LINE(args->extra->file_name, args->extra->line,
	              ", item '%s'%s%s%s (%s)", args->item->name + 1,
	              (parser->data_len > 0) ? ", value '"  : "",
	              (parser->data_len > 0) ? parser->data : "",
	              (parser->data_len > 0) ? "'"          : "",
	              (args->err_str != NULL) ? args->err_str : knot_strerror(ret));
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

	CONF_LOG_LINE(args->extra->file_name, args->extra->line - 1,
	              ", section '%s%s%s%s' (%s)", args->item->name + 1,
	              (buff[0] != '\0') ? "[" : "",
	              buff,
	              (buff[0] != '\0') ? "]" : "",
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
			log_parser_schema_err(parser, check_ret);
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
	import_flag_t flags)
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
	ret = conf_db_init(conf, &txn, !(flags & IMPORT_NO_PURGE));
	if (ret != KNOT_EOK) {
		conf->api->txn_abort(&txn);
		goto import_error;
	}

	// Parse and import given file.
	ret = conf_parse(conf, &txn, input, flags & IMPORT_FILE);
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
	init_cache(conf, flags & IMPORT_REINIT_CACHE);

	// Reset the filename.
	free(conf->filename);
	conf->filename = NULL;
	if (flags & IMPORT_FILE) {
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
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	// Prepare common buffer;
	const size_t buff_len = 2 * CONF_MAX_DATA_LEN; // Rough limit.
	char *buff = malloc(buff_len);
	if (buff == NULL) {
		return KNOT_ENOMEM;
	}

	FILE *fp = (file_name != NULL) ? fopen(file_name, "w") : stdout;
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
		if (strcmp(&item->name[1], &C_TPL[1]) == 0) {
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
	if (file_name != NULL) {
		fclose(fp);
	}
	free(buff);

	return ret;
}

/*
 * Execute the provided block of code twice: first to handle a JSON schema for
 * a single item, and then to define an array of these items.
 */
#define SINGLE_OR_ARRAY(code_block) \
do { \
	if (item->flags & YP_FMULTI) { \
		jsonw_list(w, "oneOf"); \
		jsonw_object(w, NULL); \
		{ code_block } \
		jsonw_end(w); \
		jsonw_object(w, NULL); \
		jsonw_str(w, "type", "array"); \
		jsonw_object(w, "items"); \
	} \
	{ code_block } \
	if (item->flags & YP_FMULTI) { \
		jsonw_end(w); \
		jsonw_end(w); \
		jsonw_end(w); \
	} \
} while (0)

static int export_group_items(jsonw_t *w, const yp_item_t *item, bool array);

static void export_type(jsonw_t *w, const yp_item_t *item)
{
	switch (item->type) {
	case YP_TINT:
		SINGLE_OR_ARRAY(
			switch (item->var.i.unit) {
			case YP_SSIZE:
				jsonw_str(w, "$ref", "#/$defs/int_size");
				break;
			case YP_STIME:
				jsonw_str(w, "$ref", "#/$defs/int_time");
				break;
			default:
				jsonw_str(w, "$ref", "#/$defs/int");
				break;
			}
		);
		break;
	case YP_TBOOL:
		SINGLE_OR_ARRAY(
			jsonw_str(w, "$ref", "#/$defs/switch");
		);
		break;
	case YP_TOPT:
		SINGLE_OR_ARRAY(
			jsonw_str(w, "type", "string");
			jsonw_list(w, "enum");
			for (const knot_lookup_t *o = item->var.o.opts;
			     o->name != NULL; ++o) {
				jsonw_str(w, NULL, o->name);
			}
			jsonw_end(w);
		);
		break;
	case YP_TSTR:
		SINGLE_OR_ARRAY(
			jsonw_str(w, "type", "string");
		);
		break;
	case YP_TDNAME:
		SINGLE_OR_ARRAY(
			jsonw_str(w, "$ref", "#/$defs/dname");
		);
		break;
	case YP_TB64:
		SINGLE_OR_ARRAY(
			jsonw_str(w, "$ref", "#/$defs/base64");
		);
		break;
	case YP_TGRP:
		export_group_items(w, item->sub_items, item->flags & YP_FMULTI);
		break;
	case YP_THEX:
	case YP_TADDR:
	case YP_TNET:
	case YP_TDATA:
	case YP_TREF:
		SINGLE_OR_ARRAY(
			jsonw_str(w, "type", "string");
		);
		break;
	default:
		assert(0);
		break;
	}
}

static int export_group_items(jsonw_t *w, const yp_item_t *item, bool array)
{
	assert(w != NULL && item != NULL);

	if (array) {
		jsonw_list(w, "type");
		jsonw_str(w, NULL, "array");
		jsonw_str(w, NULL, "null");
		jsonw_end(w);
		jsonw_object(w, "items");
	}

	jsonw_list(w, "type");
	jsonw_str(w, NULL, "object");
	jsonw_str(w, NULL, "null");
	jsonw_end(w);
	jsonw_bool(w, "additionalProperties", false);
	jsonw_object(w, "properties");
	for (; item->name != NULL; ++item) {
		jsonw_object(w, item->name + 1);
		export_type(w, item);
		jsonw_end(w);
	}
	jsonw_end(w);

	if (array) {
		jsonw_end(w);
	}

	return KNOT_EOK;
}

int conf_export_schema(
	conf_t *conf,
	const char *file_name)
{
	if (conf == NULL) {
		return KNOT_EINVAL;
	}

	FILE *fp = (file_name != NULL) ? fopen(file_name, "w") : stdout;
	if (fp == NULL) {
		return knot_map_errno();
	}

	jsonw_t *w = jsonw_new(fp, "  ");
	jsonw_object(w, NULL);

	// JSON-Schema header
	jsonw_str(w, "$schema", "https://json-schema.org/draft/2020-12/schema");
	jsonw_str(w, "$id", "https://knot-dns.cz/config.schema.json");
	jsonw_str(w, "title", "Knot DNS configuration schema");
	jsonw_str(w, "description", "Version Knot DNS " PACKAGE_VERSION);

	// Define own types
	jsonw_object(w, "$defs");
	// Switch type
	jsonw_object(w, "switch");
	jsonw_list(w, "oneOf");
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "boolean");
	jsonw_end(w);
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "string");
	jsonw_list(w, "enum");
	jsonw_str(w, NULL, "on");
	jsonw_str(w, NULL, "off");
	jsonw_str(w, NULL, "true");
	jsonw_str(w, NULL, "false");
	jsonw_end(w);
	jsonw_end(w);
	jsonw_end(w);
	jsonw_end(w);
	// Base64 type
	jsonw_object(w, "base64");
	jsonw_str(w, "type", "string");
	jsonw_str(w, "pattern", "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]===)?$");
	jsonw_end(w);
	// DNAME type
	jsonw_object(w, "dname");
	jsonw_str(w, "type", "string");
	jsonw_str(w, "pattern", "^(([a-zA-Z0-9_*/-]|(\\\\[^0-9])|(\\\\(([0-1][0-9][0-9])|(2[0-4][0-9])|(25[0-5]))))\\.?)+$");
	jsonw_end(w);
	// Integer type
	jsonw_object(w, "int");
	jsonw_list(w, "oneOf");
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "integer");
	jsonw_end(w);
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "string");
	jsonw_str(w, "pattern", "^[+-]?[0-9]+$");
	jsonw_end(w);
	jsonw_end(w);
	jsonw_end(w);
	// Size integer type
	jsonw_object(w, "int_size");
	jsonw_list(w, "oneOf");
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "integer");
	jsonw_end(w);
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "string");
	jsonw_str(w, "pattern", "^[+-]?[0-9]+[BKMG]?$");
	jsonw_end(w);
	jsonw_end(w);
	jsonw_end(w);
	// Time integer type
	jsonw_object(w, "int_time");
	jsonw_list(w, "oneOf");
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "integer");
	jsonw_end(w);
	jsonw_object(w, NULL);
	jsonw_str(w, "type", "string");
	jsonw_str(w, "pattern", "^[+-]?[0-9]+[smhd]?$");
	jsonw_end(w);
	jsonw_end(w);
	jsonw_end(w);
	// END
	jsonw_end(w);

	// Export configuration schema
	int ret = export_group_items(w, conf->schema, false);

	jsonw_end(w);
	jsonw_free(&w);

	if (file_name != NULL) {
		fclose(fp);
	}

	return ret;
}
