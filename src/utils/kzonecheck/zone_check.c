/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/zone/digest.h"
#include "knot/zone/zonefile.h"
#include "knot/zone/zone-dump.h"
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

	fprintf(stderr, "[%s] %s%s%s\n", owner, sem_error_msg(error),
	       (data != NULL ? " "  : ""),
	       (data != NULL ? data : ""));

	stats->errors[error]++;
	stats->error_count++;
}

static void print_statistics(err_handler_stats_t *stats)
{
	fprintf(stderr, "\nError summary:\n");
	for (sem_error_t i = 0; i <= SEM_ERR_UNKNOWN; ++i) {
		if (stats->errors[i] > 0) {
			fprintf(stderr, "%4u\t%s\n", stats->errors[i], sem_error_msg(i));
		}
	}
}

int zone_check(const char *zone_file, const knot_dname_t *zone_name, bool zonemd,
               semcheck_optional_t optional, time_t time, bool print)
{
	err_handler_stats_t stats = {
		.handler = { .cb = err_callback },
	};

	zloader_t zl;
	int ret = zonefile_open(&zl, zone_file, zone_name, optional, time);
	switch (ret) {
	case KNOT_EOK:
		break;
	case KNOT_EACCES:
	case KNOT_EFILE:
		ERR2("failed to load the zone file");
		return ret;
	default:
		ERR2("failed to run semantic checks (%s)", knot_strerror(ret));
		return ret;
	}
	zl.err_handler = (sem_handler_t *)&stats;
	zl.creator->master = true;

	zone_contents_t *contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (contents == NULL && !stats.handler.error) {
		ERR2("failed to run semantic checks");
		return KNOT_ERROR;
	}

	if (stats.error_count > 0) {
		print_statistics(&stats);
		if (stats.handler.error) {
			fprintf(stderr, "\n");
			ERR2("serious semantic error detected");
			ret = KNOT_EINVAL;
		} else {
			ret = KNOT_ESEMCHECK;
		}
	}

	if (zonemd) {
		ret = zone_contents_digest_verify(contents);
		if (ret != KNOT_EOK) {
			if (stats.error_count > 0 && !stats.handler.error) {
				fprintf(stderr, "\n");
			}
			ERR2("invalid ZONEMD");
		}
	}

	if (print) {
		if (ret != KNOT_EOK) {
			fprintf(stderr, "\n");
		}
		printf(";; Zone dump (Knot DNS %s)\n", PACKAGE_VERSION);
		zone_dump_text(contents, stdout, false, NULL);
	}

	zone_contents_deep_free(contents);

	return ret;
}
