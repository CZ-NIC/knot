/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/nameserver/query_module.h"

struct {
	bool active_dumper;
	pthread_t dumper;
	uint32_t timer;
	server_t *server;
} stats = { 0 };

typedef void (*dump_cb)(FILE *, server_t *);

static const dump_cb generators[] = {
    dump_to_yaml,
    dump_to_json
};

static void dump_stats(server_t *server)
{
	conf_t *pconf = conf();
	conf_val_t val = conf_get(pconf, C_SRV, C_RUNDIR);
	char *rundir = conf_abs_path(&val, NULL);
	
	val = conf_get(pconf, C_STATS, C_FILE);
	char *file_name = conf_abs_path(&val, rundir);
	free(rundir);
	
	val = conf_get(pconf, C_STATS, C_FORMAT);
	unsigned format = conf_opt(&val);

	val = conf_get(pconf, C_STATS, C_APPEND);
	bool append = conf_bool(&val);

	// Open or create output file.
	FILE *fd = NULL;
	char *tmp_name = NULL;
	if (append) {
		fd = fopen(file_name, "r+");
		if (fd) {
			fseek(fd, 0, SEEK_END);
		} else { // when file not exists
			fd = fopen(file_name, "w");
			if (fd == NULL) {
				log_error("stats, failed to append file '%s' (%s)",
			        	file_name, knot_strerror(knot_map_errno()));
				free(file_name);
				return;
			}
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
	generators[format](fd, server);

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
