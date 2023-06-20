/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/common/stats.h"
#include "knot/common/log.h"
#include "knot/nameserver/query_module.h"

struct {
	bool active_dumper;
	pthread_t dumper;
	uint32_t timer;
	server_t *server;
} stats = { 0 };

typedef struct {
	FILE *fd;
	const list_t *query_modules;
	const knot_dname_t *zone;
	unsigned threads;
	int level;
	bool zone_emitted;
	bool zone_name_emitted;
	bool module_emitted;
} dump_ctx_t;

#define DUMP_STR(fd, level, name, ...) do { \
	fprintf(fd, "%-.*s"name":\n", level, "    ", ##__VA_ARGS__); \
} while (0)

#define DUMP_CTR(fd, level, name, idx, val) do { \
	fprintf(fd, "%-.*s"name": %"PRIu64"\n", level, "    ", idx, val); \
} while (0)

static uint64_t server_zone_count(server_t *server)
{
	return knot_zonedb_size(server->zone_db);
}

const stats_item_t server_stats[] = {
	{ "zone-count", { .server_val = server_zone_count } },
	{ 0 }
};

static uint64_t zone_size(zone_t *zone)
{
	return zone->contents != NULL ? zone->contents->size : 0;
}

static uint64_t zone_max_ttl(zone_t *zone)
{
	return zone->contents != NULL ? zone->contents->max_ttl : 0;
}

const stats_item_t zone_contents_stats[] = {
	{ "size",    { .zone_val = zone_size } },
	{ "max-ttl", { .zone_val = zone_max_ttl } },
	{ 0 }
};

uint64_t stats_get_counter(uint64_t **stats_vals, uint32_t offset, unsigned threads)
{
	uint64_t res = 0;
	for (unsigned i = 0; i < threads; i++) {
		res += ATOMIC_GET(stats_vals[i][offset]);
	}
	return res;
}

static void dump_common(dump_ctx_t *ctx, knotd_mod_t *mod)
{
	// Dump zone name.
	if (ctx->zone != NULL) {
		// Prevent from zone section override.
		if (!ctx->zone_emitted) {
			ctx->level = 0;
			DUMP_STR(ctx->fd, ctx->level++, "zone");
			ctx->zone_emitted = true;
		}

		if (!ctx->zone_name_emitted) {
			ctx->level = 1;
			knot_dname_txt_storage_t name;
			if (knot_dname_to_str(name, ctx->zone, sizeof(name)) == NULL) {
				return;
			}
			DUMP_STR(ctx->fd, ctx->level++, "\"%s\"", name);
			ctx->zone_name_emitted = true;
		}
	}

	if (!ctx->module_emitted) {
		DUMP_STR(ctx->fd, ctx->level++, "%s", mod->id->name + 1);
		ctx->module_emitted = true;
	}
}

static void dump_counter(dump_ctx_t *ctx, knotd_mod_t *mod, mod_ctr_t *ctr)
{
	uint64_t counter = stats_get_counter(mod->stats_vals, ctr->offset, ctx->threads);
	if (counter == 0) {
		// Skip empty counter.
		return;
	}

	dump_common(ctx, mod);

	DUMP_CTR(ctx->fd, ctx->level, "%s", ctr->name, counter);
}

static void dump_counters(dump_ctx_t *ctx, knotd_mod_t *mod, mod_ctr_t *ctr)
{
	bool counter_emitted = false;
	for (uint32_t j = 0; j < ctr->count; j++) {
		uint64_t counter = stats_get_counter(mod->stats_vals, ctr->offset + j, ctx->threads);
		if (counter == 0) {
			// Skip empty counter.
			continue;
		}

		dump_common(ctx, mod);

		if (!counter_emitted) {
			DUMP_STR(ctx->fd, ctx->level, "%s", ctr->name);
			counter_emitted = true;
		}

		if (ctr->idx_to_str != NULL) {
			char *str = ctr->idx_to_str(j, ctr->count);
			if (str != NULL) {
				DUMP_CTR(ctx->fd, ctx->level + 1, "%s", str, counter);
				free(str);
			}
		} else {
			DUMP_CTR(ctx->fd, ctx->level + 1, "%u", j, counter);
		}
	}
}

static void dump_modules(dump_ctx_t *ctx)
{
	knotd_mod_t *mod;
	WALK_LIST(mod, *ctx->query_modules) {
		// Skip modules without statistics.
		if (mod->stats_count == 0) {
			continue;
		}

		if (ctx->threads == 0) {
			ctx->threads = knotd_mod_threads(mod);
		}

		// Dump module counters.
		ctx->module_emitted = false;
		for (int i = 0; i < mod->stats_count; i++) {
			mod_ctr_t *ctr = mod->stats_info + i;
			if (ctr->name == NULL) {
				// Empty counter.
				continue;
			}
			if (ctr->count == 1) {
				// Simple counter.
				dump_counter(ctx, mod, ctr);
			} else {
				// Array of counters.
				dump_counters(ctx, mod, ctr);
			}
		}
	}
}

static void zone_stats_dump(zone_t *zone, dump_ctx_t *ctx)
{
	if (EMPTY_LIST(zone->query_modules)) {
		return;
	}

	ctx->query_modules = &zone->query_modules;
	ctx->zone = zone->name;
	ctx->zone_name_emitted = false;

	dump_modules(ctx);
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

	dump_ctx_t ctx = {
		.fd = fd,
		.query_modules = conf->query_modules,
	};

	// Dump server statistics.
	DUMP_STR(ctx.fd, ctx.level, "server");
	for (const stats_item_t *item = server_stats; item->name != NULL; item++) {
		DUMP_CTR(ctx.fd, ctx.level + 1, "%s", item->name, item->server_val(server));
	}

	// Dump global statistics.
	dump_modules(&ctx);

	// Dump zone statistics.
	knot_zonedb_foreach(server->zone_db, zone_stats_dump, &ctx);
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

	// Update server context.
	stats.server = server;

	conf_val_t val = conf_get(conf, C_STATS, C_TIMER);
	stats.timer = conf_int(&val);
	if (stats.timer > 0) {
		// Check if dumping is already running.
		if (stats.active_dumper) {
			return;
		}

		int ret = pthread_create(&stats.dumper, NULL, dumper, NULL);
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
