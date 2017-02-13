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

#define DUMP_STR(fd, level, name, ...) do { \
	fprintf(fd, "%-.*s"name": %s\n", level, "    ", ##__VA_ARGS__); \
	} while (0)
#define DUMP_CTR(fd, level, name, ...) do { \
	fprintf(fd, "%-.*s"name": %"PRIu64"\n", level, "    ", ##__VA_ARGS__); \
	} while (0)

uint64_t server_zone_count(server_t *server)
{
	return knot_zonedb_size(server->zone_db);
}

const stats_item_t server_stats[] = {
	{ "zone-count", server_zone_count },
	{ 0 }
};

static void dump_counters(FILE *fd, int level, mod_ctr_t *ctr)
{
	for (uint32_t j = 0; j < ctr->count; j++) {
		// Skip empty counters.
		if (ctr->counters[j] == 0) {
			continue;
		}

		if (ctr->idx_to_str != NULL) {
			char *str = ctr->idx_to_str(j, ctr->count);
			if (str != NULL) {
				DUMP_CTR(fd, level, "%s", str, ctr->counters[j]);
				free(str);
			}
		} else {
			DUMP_CTR(fd, level, "%u", j, ctr->counters[j]);
		}
	}
}

static void dump_modules(FILE *fd, list_t *query_modules, const knot_dname_t *zone)
{
	static int level = 0;
	struct query_module *mod = NULL;
	WALK_LIST(mod, *query_modules) {
		// Skip modules without statistics.
		if (mod->stats_count == 0) {
			continue;
		}

		// Dump zone name.
		if (zone != NULL) {
			// Prevent from zone section override.
			if (level == 0) {
				DUMP_STR(fd, level++, "zone", "");
			} else {
				level = 1;
			}

			char name[KNOT_DNAME_TXT_MAXLEN + 1];
			if (knot_dname_to_str(name, zone, sizeof(name)) == NULL) {
				return;
			}
			DUMP_STR(fd, level++, "\"%s\"", name, "");
		} else {
			level = 0;
		}

		// Dump module counters.
		DUMP_STR(fd, level, "%s", mod->id->name + 1, "");
		for (int i = 0; i < mod->stats_count; i++) {
			mod_ctr_t *ctr = mod->stats + i;
			if (ctr->name == NULL) {
				// Empty counter.
				continue;
			}
			if (ctr->count == 1) {
				// Simple counter.
				DUMP_CTR(fd, level + 1, "%s", ctr->name, ctr->counter);
			} else {
				// Array of counters.
				DUMP_STR(fd, level + 1, "%s", ctr->name, "");
				dump_counters(fd, level + 2, ctr);
			}
		}
	}
}

static void zone_stats_dump(zone_t *zone, FILE *fd)
{
	if (EMPTY_LIST(zone->query_modules)) {
		return;
	}

	dump_modules(fd, &zone->query_modules, zone->name);
}

static void dump_to_file(FILE *fd, server_t *server)
{
	char date[64] = "";

	// Get formated current time string.
	struct tm tm;
	time_t now = time(NULL);
	localtime_r(&now, &tm);
	strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S%z", &tm);

	// Get the server identity.
	conf_val_t val = conf_get(conf(), C_SRV, C_IDENT);
	const char *ident = conf_str(&val);
	if (ident == NULL || ident[0] == '\0') {
		ident = conf()->hostname;
	}

	// Dump record header.
	fprintf(fd,
	        "---\n"
	        "time: %s\n"
	        "identity: %s\n",
	        date, ident);

	// Dump server statistics.
	DUMP_STR(fd, 0, "server", "");
	for (const stats_item_t *item = server_stats; item->name != NULL; item++) {
		DUMP_CTR(fd, 1, "%s", item->name, item->val(server));
	}

	// Dump global statistics.
	dump_modules(fd, &conf()->query_modules, NULL);

	// Dump zone statistics.
	knot_zonedb_foreach(server->zone_db, zone_stats_dump, fd);
}

static void dump_stats(server_t *server)
{
	conf_val_t val = conf_get(conf(), C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	val = conf_get(conf(), C_STATS, C_FILE);
	char *file_name = conf_abs_path(&val, rundir);
	free(rundir);

	val = conf_get(conf(), C_STATS, C_APPEND);
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
	dump_to_file(fd, server);

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
	while (true) {
		assert(stats.timer > 0);
		sleep(stats.timer);

		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		rcu_read_lock();
		dump_stats(stats.server);
		rcu_read_unlock();
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	}

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
