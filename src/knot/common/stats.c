/*  Copyright (C) 2025 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <inttypes.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <urcu.h>

#include "contrib/files.h"
#include "contrib/openbsd/strlcpy.h"
#include "contrib/threads.h"
#include "knot/common/stats.h"
#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"
#include "libknot/xdp.h"

static uint64_t stats_get_counter(knot_atomic_uint64_t **stats_vals, uint32_t offset,
                                  unsigned threads)
{
	uint64_t res = 0;
	for (unsigned i = 0; i < threads; i++) {
		res += ATOMIC_GET(stats_vals[i][offset]);
	}
	return res;
}

int stats_xdp(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx)
{
#ifdef ENABLE_XDP
#define CTR_FILL(structure, item_name, avg) { \
	assert(ctr_id < CTR_COUNT); \
	xdp_ctr_t *ctr = &if_stats[i][ctr_id++]; \
	ctr->if_name = sock_stats[0].if_name; \
	strlcpy(ctr->ctr_name, #item_name, sizeof(ctr->ctr_name)); \
	ctr->value = 0; \
	for (int j = 0; j < iface->fd_xdp_count; j++) { \
		ctr->value += sock_stats[j].structure.item_name; \
	} \
	if (avg) { \
		ctr->value /= iface->fd_xdp_count; \
	} \
}
	stats_dump_params_t params = { .section = "xdp" };

	if (ctx->section != NULL && strcasecmp(ctx->section, params.section) != 0) {
		return KNOT_EOK;
	}

	typedef struct {
		const char *if_name;
		char ctr_name[16];
		uint64_t value;
	} xdp_ctr_t;

	const unsigned CTR_COUNT = 11;
	xdp_ctr_t if_stats[ctx->server->n_ifaces][CTR_COUNT];

	bool have_xdp = false;
	for (int i = 0; i < ctx->server->n_ifaces; i++) {
		iface_t *iface = &ctx->server->ifaces[i];
		if (iface->fd_xdp_count == 0) {
			continue;
		}
		have_xdp = true;

		knot_xdp_stats_t sock_stats[iface->fd_xdp_count];
		for (int j = 0; j < iface->fd_xdp_count; j++) {
			knot_xdp_socket_stats(iface->xdp_sockets[j], &sock_stats[j]);
		}

		unsigned ctr_id = 0;
		CTR_FILL(socket, rx_dropped, false);
		CTR_FILL(socket, rx_invalid, false);
		CTR_FILL(socket, tx_invalid, false);
		CTR_FILL(socket, rx_full,    false);
		CTR_FILL(socket, fq_empty,   false);
		CTR_FILL(socket, tx_empty,   false);
		CTR_FILL(rings,  tx_busy,    true);
		CTR_FILL(rings,  fq_fill,    true);
		CTR_FILL(rings,  rx_fill,    true);
		CTR_FILL(rings,  tx_fill,    true);
		CTR_FILL(rings,  cq_fill,    true);
	}

	if (have_xdp) {
		for (int j = 0; j < CTR_COUNT; j++) {
			params.item_begin = true;
			for (int i = 0; i < ctx->server->n_ifaces; i++) {
				iface_t *iface = &ctx->server->ifaces[i];
				if (iface->fd_xdp_count == 0) {
					continue;
				}
				xdp_ctr_t *ctr = &if_stats[i][j];
				params.id = ctr->if_name;
				params.item = ctr->ctr_name;
				params.value = ctr->value;
				int ret = fcn(&params, ctx);
				if (ret != KNOT_EOK) {
					return ret;
				}
			}
		}
	}
#undef CTR_FILL
#endif
	return KNOT_EOK;
}

#define DUMP_VAL(params, it, val) { \
	(params).item = (it); \
	(params).value = (val); \
	int ret = fcn(&(params), ctx); \
	if (ret != KNOT_EOK) { \
		return ret; \
	} \
}

int stats_server(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx)
{
	stats_dump_params_t params = { .section = "server" };

	if (ctx->section != NULL && strcasecmp(ctx->section, params.section) != 0) {
		return KNOT_EOK;
	}

	DUMP_VAL(params, "zone-count", knot_zonedb_size(ctx->server->zone_db));
	DUMP_VAL(params, "tcp-io-timeout", ctx->server->stats.tcp_io_timeout);
	DUMP_VAL(params, "tcp-idle-timeout", ctx->server->stats.tcp_idle_timeout);

	return KNOT_EOK;
}

int stats_zone(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx)
{
	knot_dname_txt_storage_t zone;
	stats_dump_params_t params = { .section = "zone", .zone = zone };

	if (ctx->section != NULL && strcasecmp(ctx->section, params.section) != 0) {
		return KNOT_EOK;
	}

	assert(ctx->zone);
	zone_contents_t *contents = ctx->zone->contents;

	if (knot_dname_to_str(zone, ctx->zone->name, sizeof(zone)) == NULL) {
		return KNOT_EINVAL;
	}

	DUMP_VAL(params, "size", contents != NULL ? contents->size : 0);
	DUMP_VAL(params, "max-ttl", contents != NULL ? contents->max_ttl : 0);

	return KNOT_EOK;
}

static int stats_counter(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx,
                         stats_dump_params_t *params, knotd_mod_t *mod, mod_ctr_t *ctr)
{
	params->id = NULL;
	params->value_pos = 0;

	uint64_t val = stats_get_counter(mod->stats_vals, ctr->offset, ctx->threads);

	DUMP_VAL(*params, ctr->name, val);

	return KNOT_EOK;
}

static int stats_counters(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx,
                          stats_dump_params_t *params, knotd_mod_t *mod, mod_ctr_t *ctr)
{
	char id[64];
	params->id = id;
	params->value_pos = 0;
	params->item_begin = true;

	for (uint32_t i = 0; i < ctr->count; i++) {
		uint64_t val = stats_get_counter(mod->stats_vals, ctr->offset + i,
		                                 ctx->threads);

		if (ctr->idx_to_str != NULL) {
			char *str = ctr->idx_to_str(i, ctr->count);
			if (str == NULL) {
				continue;
			}
			(void)snprintf(id, sizeof(id), "%s", str);
			free(str);
		} else {
			(void)snprintf(id, sizeof(id), "%u", i);
		}

		DUMP_VAL(*params, ctr->name, val);
		params->value_pos++;
	}

	params->id = NULL;

	return KNOT_EOK;
}

int stats_modules(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx)
{
	if (ctx->section != NULL && strncasecmp(ctx->section, "mod-", strlen("mod-")) != 0) {
		return KNOT_EOK;
	}

	knot_dname_txt_storage_t zone;
	stats_dump_params_t params = { 0 };

	knotd_mod_t *mod;
	WALK_LIST(mod, *ctx->query_modules) {
		// Skip modules without statistics.
		if (mod->stats_count == 0) {
			continue;
		}

		if (ctx->threads == 0) {
			ctx->threads = knotd_mod_threads(mod);
		}

		params.section = mod->id->name + 1;
		params.module_begin = true;
		if (ctx->zone != NULL && params.zone == NULL) {
			params.zone = knot_dname_to_str(zone, ctx->zone->name,
			                                sizeof(zone));
			if (params.zone == NULL) {
				return KNOT_EINVAL;
			}
		}

		// Dump module counters.
		for (int i = 0; i < mod->stats_count; i++) {
			mod_ctr_t *ctr = mod->stats_info + i;
			if (ctr->name == NULL) {
				// Empty counter.
				continue;
			}
			int ret = (ctr->count == 1) ?
			          stats_counter(fcn, ctx, &params, mod, ctr) :
			          stats_counters(fcn, ctx, &params, mod, ctr);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

struct {
	bool active_dumper;
	pthread_t dumper;
	uint32_t timer;
	server_t *server;
} stats = { 0 };

typedef struct {
	FILE *fd;
	bool section_emitted;
	bool zone_section_emitted;
	bool zone_emitted;
	bool id_emitted;
} dump_ctx_t;

static int dump_ctr(stats_dump_params_t *params, stats_dump_ctx_t *dump_ctx)
{
	dump_ctx_t *ctx = dump_ctx->ctx;

	if (params->value == 0) {
		return KNOT_EOK;
	}

	const char *INDENT = "      ";
	unsigned indent = 0;

	if (params->zone != NULL) {
		if (!ctx->zone_section_emitted) {
			fprintf(ctx->fd, "zone:\n");
			ctx->zone_section_emitted = true;
		}

		if (!ctx->zone_emitted) {
			fprintf(ctx->fd, " \"%s\":\n", params->zone);
			ctx->zone_emitted = true;
		}
		indent += 2;
	}

	if (!ctx->section_emitted || params->module_begin) {
		fprintf(ctx->fd, "%-.*s%s:\n", indent, INDENT, params->section);
		ctx->section_emitted = true;
		params->module_begin = false;
	}
	indent++;

	if (params->id != NULL) {
		if (params->item_begin) {
			fprintf(ctx->fd, "%-.*s%s:\n", indent, INDENT, params->item);
			params->item_begin = false;
		}
		indent++;
		fprintf(ctx->fd, "%-.*s%s: %"PRIu64"\n", indent, INDENT,
		        params->id, params->value);
	} else {
		fprintf(ctx->fd, "%-.*s%s: %"PRIu64"\n", indent, INDENT,
		        params->item, params->value);
	}

	return KNOT_EOK;
}

static void zone_stats_dump(zone_t *zone, stats_dump_ctx_t *dump_ctx)
{
	if (EMPTY_LIST(zone->query_modules)) {
		return;
	}

	// Reset per-zone context.
	dump_ctx_t *ctx = dump_ctx->ctx;
	*ctx = (dump_ctx_t){
		.fd = ctx->fd,
		.zone_section_emitted = ctx->zone_section_emitted,
	};

	dump_ctx->zone = zone;
	dump_ctx->query_modules = &zone->query_modules;

	(void)stats_modules(dump_ctr, dump_ctx);
}

static void dump_to_file(conf_t *conf, FILE *fd, server_t *server)
{
	char date[64] = "";

	// Get formatted current time string.
	struct tm tm;
	time_t now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), KNOT_LOG_TIME_FORMAT, &tm);

	// Get the server identity.
	const char *ident = conf->cache.srv_ident;

	// Dump record header.
	fprintf(fd,
	        "---\n"
	        "time: %s\n"
	        "identity: %s\n",
	        date, ident);

	dump_ctx_t ctx = { .fd = fd };

	stats_dump_ctx_t dump_ctx = {
		.server = server,
		.query_modules = conf->query_modules,
		.ctx = &ctx,
	};

	// Dump server counters.
	(void)stats_server(dump_ctr, &dump_ctx);

	// Dump XDP counters.
	ctx = (dump_ctx_t){ .fd = fd };
	(void)stats_xdp(dump_ctr, &dump_ctx);

	// Dump global module counters.
	ctx = (dump_ctx_t){ .fd = fd };
	(void)stats_modules(dump_ctr, &dump_ctx);

	// Dump per zone module counters (fixed zone counters not included).
	ctx = (dump_ctx_t){ .fd = fd };
	knot_zonedb_foreach(server->zone_db, zone_stats_dump, &dump_ctx);
}

static void dump_stats(server_t *server)
{
	conf_t *pconf = conf();
	conf_val_t val = conf_get(pconf, C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	val = conf_get(pconf, C_STATS, C_FILE);
	char *file_name = conf_abs_path(&val, rundir);
	free(rundir);

	val = conf_get(pconf, C_STATS, C_APPEND);
	bool append = conf_bool(&val);

	// Open or create output file.
	FILE *fd = NULL;
	char *tmp_name = NULL;
	if (append) {
		fd = fopen(file_name, "a");
		if (fd == NULL) {
			log_error("stats, failed to append file '%s' (%s)",
			          file_name, knot_strerror(knot_map_errno()));
			free(file_name);
			return;
		}
	} else {
		int ret = open_tmp_file(file_name, &tmp_name, &fd,
		                        S_IRUSR | S_IWUSR | S_IRGRP);
		if (ret != KNOT_EOK) {
			log_error("stats, failed to open file '%s' (%s)",
			          file_name, knot_strerror(ret));
			free(file_name);
			return;
		}
	}
	assert(fd);

	// Dump stats into the file.
	dump_to_file(pconf, fd, server);

	fflush(fd);
	fclose(fd);

	// Switch the file contents.
	if (!append) {
		int ret = rename(tmp_name, file_name);
		if (ret != 0) {
			log_error("stats, failed to access file '%s' (%s)",
			          file_name, knot_strerror(knot_map_errno()));
			unlink(tmp_name);
		}
		free(tmp_name);
	}

	log_debug("stats, dumped into file '%s'", file_name);
	free(file_name);
}

static void *dumper(void *data)
{
	rcu_register_thread();
	while (true) {
		assert(stats.timer > 0);
		sleep(stats.timer);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		rcu_read_lock();
		dump_stats(stats.server);
		rcu_read_unlock();
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	}
	rcu_unregister_thread();
	return NULL;
}

void stats_reconfigure(conf_t *conf, server_t *server)
{
	if (conf == NULL || server == NULL) {
		return;
	}

	stats.server = server;

	conf_val_t val = conf_get(conf, C_STATS, C_TIMER);
	stats.timer = conf_int(&val);
	if (stats.timer > 0) {
		// Check if dumping is already running.
		if (stats.active_dumper) {
			return;
		}

		int ret = thread_create_nosignal(&stats.dumper, dumper, NULL);
		if (ret != 0) {
			log_error("stats, failed to launch periodic dumping (%s)",
			          knot_strerror(knot_map_errno_code(ret)));
		} else {
			stats.active_dumper = true;
		}
	// Stop current dumping.
	} else if (stats.active_dumper) {
		pthread_cancel(stats.dumper);
		pthread_join(stats.dumper, NULL);
		stats.active_dumper = false;
	}
}

void stats_deinit(void)
{
	if (stats.active_dumper) {
		pthread_cancel(stats.dumper);
		pthread_join(stats.dumper, NULL);
	}

	memset(&stats, 0, sizeof(stats));
}
