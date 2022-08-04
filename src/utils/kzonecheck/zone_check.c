/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>
#include <assert.h>

#include "utils/kzonecheck/zone_check.h"

#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "utils/common/msg.h"

typedef struct {
	sem_handler_t handler;
	unsigned errors[SEM_ERR_UNKNOWN + 1]; /*!< Counting errors by type. */
	unsigned error_count;                 /*!< Total error count. */
} err_handler_stats_t;

static void err_callback(sem_handler_t *handler, const zone_contents_t *zone,
                         const knot_dname_t *node, sem_error_t error, const char *data)
{
	assert(handler != NULL);
	assert(zone != NULL);
	err_handler_stats_t *stats = (err_handler_stats_t *)handler;

	knot_dname_txt_storage_t buff;
	char *owner = knot_dname_to_str(buff, (node != NULL ? node : zone->apex->owner),
	                                sizeof(buff));
	if (owner == NULL) {
		owner = "";
	}

	printf("[%s] %s%s%s\n", owner, sem_error_msg(error),
	      (data != NULL ? " "  : ""),
	      (data != NULL ? data : ""));

	stats->errors[error]++;
	stats->error_count++;
}

static void print_statistics(err_handler_stats_t *stats)
{
	printf("\nError summary:\n");
	for (sem_error_t i = 0; i <= SEM_ERR_UNKNOWN; ++i) {
		if (stats->errors[i] > 0) {
			printf("%4u\t%s\n", stats->errors[i], sem_error_msg(i));
		}
	}
}

int zone_check(const char *zone_file, const knot_dname_t *zone_name,
               semcheck_optional_t optional, time_t time)
{
	err_handler_stats_t stats = {
		.handler = { .cb = err_callback },
	};

	zloader_t zl;
	int ret = zonefile_open(&zl, zone_file, zone_name, optional, time);
	if (ret != KNOT_EOK) {
		return ret;
	}
	zl.err_handler = (sem_handler_t *)&stats;
	zl.creator->master = true;

	zone_contents_t *contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (contents == NULL && !stats.handler.error) {
		return KNOT_ERROR;
	}
	zone_contents_deep_free(contents);

	if (stats.error_count > 0) {
		print_statistics(&stats);
		return stats.handler.error ? KNOT_EZONEINVAL : KNOT_ESEMCHECK;
	} else {
		return KNOT_EOK;
	}
}
