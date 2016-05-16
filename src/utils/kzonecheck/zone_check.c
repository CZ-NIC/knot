/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "contrib/ucw/lists.h"
#include "utils/kzonecheck/zone_check.h"

static void print_errors(err_handler_t *handler, FILE *outfile)
{
	err_node_t *n;
	WALK_LIST(n, handler->error_list) {
		if (n->error > (int)ZC_ERR_GLUE_RECORD) {
			fprintf(outfile, "zone: [%s], semantic check, unknown error\n",
			        n->zone_name ? n->zone_name : "?");
			return;
		}

		const char *errmsg = zonechecks_error_messages[-n->error];

		fprintf(outfile ,"node: '%s' (%s%s%s)\n",
		        n->name ? n->name : "?",
		        errmsg ? errmsg : "unknown error",
		        n->data ? " " : "",
		        n->data ? n->data : "");
	}
}

static void print_statistics(err_handler_t *handler, FILE *outfile)
{
	fprintf(outfile, "\nERRORS SUMMARY:\n\tCount\tError\n");
	for(int i = ZC_ERR_UNKNOWN; i < ZC_ERR_LAST; ++i) {
		if (handler->errors[-i] > 0) {
			fprintf(outfile, "\t%u\t%s\n", handler->errors[-i], zonechecks_error_messages[-i]);
		}
	}
}

int zone_check(const char *zone_file, const knot_dname_t *zone_name,
               FILE *outfile)
{
	zloader_t zl;
	int ret = zonefile_open(&zl, zone_file, zone_name, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zl.creator->master = true;

	zone_contents_t *contents;
	contents = zonefile_load(&zl);

	if (zl.err_handler.error_count > 0) {
		ret = KNOT_ESEMCHECK;
		print_errors(&zl.err_handler, outfile);
		print_statistics(&zl.err_handler, outfile);
	}

	zonefile_close(&zl);
	if (contents == NULL) {
		return KNOT_ERROR;
	}

	zone_contents_deep_free(&contents);

	return ret;
}
