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

#include <stdio.h>
#include <assert.h>

#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "utils/kzonecheck/zone_check.h"

typedef struct {
	err_handler_t handler;
	FILE *outfile;
	unsigned errors[(-ZC_ERR_UNKNOWN) + 1]; /*!< Counting errors by type */
	unsigned error_count; /*!< Total error count */
} err_handler_stats_t;

static void err_callback(err_handler_t *handler, const zone_contents_t *zone,
                         const zone_node_t *node, zc_error_t error, const char *data)
{
	assert(handler != NULL);
	assert(zone != NULL);
	err_handler_stats_t *stats = (err_handler_stats_t *)handler;

	char buff[KNOT_DNAME_TXT_MAXLEN + 1] = "";
	(void)knot_dname_to_str(buff, (node != NULL ? node->owner : zone->apex->owner),
	                        sizeof(buff));

	fprintf(stats->outfile, "[%s] %s%s%s\n",
	        buff, semantic_check_error_msg(error),
	        (data != NULL ? " "  : ""),
	        (data != NULL ? data : ""));

	stats->errors[-error]++;
	stats->error_count++;
}

static void print_statistics(err_handler_stats_t *stats)
{
	fprintf(stats->outfile, "\nError summary:\n");
	for(int i = ZC_ERR_UNKNOWN; i < ZC_ERR_LAST; ++i) {
		if (stats->errors[-i] > 0) {
			fprintf(stats->outfile, "%4u\t%s\n", stats->errors[-i],
			        semantic_check_error_msg(i));
		}
	}
}

int zone_check(const char *zone_file, const knot_dname_t *zone_name,
               FILE *outfile, time_t time)
{
	err_handler_stats_t stats = {
		.handler = { .cb = err_callback },
		.outfile = outfile
	};

	zloader_t zl;
	int ret = zonefile_open(&zl, zone_file, zone_name, true, time);
	if (ret != KNOT_EOK) {
		return ret;
	}
	zl.err_handler = (err_handler_t *)&stats;
	zl.creator->master = true;

	zone_contents_t *contents = zonefile_load(&zl);
	zonefile_close(&zl);
	if (contents == NULL && !stats.handler.fatal_error) {
		return KNOT_ERROR;
	}
	zone_contents_deep_free(&contents);

	if (stats.error_count > 0) {
		print_statistics(&stats);
		return stats.handler.fatal_error ? KNOT_EZONEINVAL : KNOT_ESEMCHECK;
	} else {
		return KNOT_EOK;
	}
}
