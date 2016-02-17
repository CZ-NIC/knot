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

#include <unistd.h>
#include <getopt.h>
#include <stdio.h>

#include "libknot/libknot.h"
#include "knot/zone/contents.h"
#include "knot/zone/zonefile.h"
#include "contrib/ucw/lists.h"
#include "utils/common/params.h"
#include "knot/common/log.h"


#define PROGRAM_NAME "kzonecheck"

static void print_help(void)
{
	printf("Usage: %s [parameters] <action> [action_args]\n"
	       "\n"
	       "Parameters:\n"
	       " -o, --origin <zone origin>                  blabla\n"
	       "                                       (default blabla)\n"
	       " -v, --verbose                        Enable debug output.\n"
	       " -h, --help                           Print the program help.\n"
	       " -V, --version                        Print the program version.\n"
	       "\n"
	       "Actions:\n",
	       PROGRAM_NAME);
}

void print_errors(err_handler_t *handler)
{
	err_node_t *n;
	WALK_LIST(n, handler->error_list) {
		if (n->error > (int)ZC_ERR_GLUE_RECORD) {
			fprintf(stderr, "zone: [%s], semantic check, unknown error\n",
			        n->zone_name ? n->zone_name : "?");
			return;
		}

		const char *errmsg = zonechecks_error_messages[-n->error];

		fprintf(stderr ,"node: '%s' (%s%s%s)\n",
		        n->name ? n->name : "?",
		        errmsg ? errmsg : "unknown error",
		        n->data ? " " : "",
		        n->data ? n->data : "");
	}
}

void  print_statistics(err_handler_t *handler)
{
	fprintf(stderr, "\nERRORS SUMMARY:\n\tCount\tError\n");
	for(int i = ZC_ERR_UNKNOWN; i < ZC_ERR_LAST; ++i) {
		if (handler->errors[-i] > 0) {
			fprintf(stderr, "\t%u\t%s\n", handler->errors[-i], zonechecks_error_messages[-i]);
		}
	}
}

int zone_check(const char *zone_file, const knot_dname_t *zone_name)
{
	zloader_t zl;
	int ret = zonefile_open(&zl, zone_file, zone_name, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zl.creator->master = true;

	zone_contents_t *contents;
	contents = zonefile_load(&zl);

	print_errors(&zl.err_handler);
	print_statistics(&zl.err_handler);

	zonefile_close(&zl);
	if (contents == NULL) {
		return KNOT_ERROR;
	}

	zone_contents_deep_free(&contents);

	return KNOT_EOK;
}


int main(int argc, char *argv[])
{
	char *filename;
	char *zonename = "";
	bool verbose = false;

	/* Long options. */
	struct option opts[] = {
		{ "origin",  required_argument, NULL, 'o' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	/* Parse command line arguments */
	int opt = 0, li = 0;
	while ((opt = getopt_long(argc, argv, "o:vVh", opts, &li)) != -1) {
		switch (opt) {
		case 'o':
			zonename = optarg;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			print_help();
			return EXIT_SUCCESS;
		case 'V':
			print_version(PROGRAM_NAME);
			return EXIT_SUCCESS;
		default:
			print_help();
			return EXIT_FAILURE;
		}
	}

	/* Check if there's at least one remaining non-option. */
	if (optind >= argc) {
		fprintf(stderr, "Expected argument after options\n");
		print_help();
		return EXIT_FAILURE;
	}
	filename = argv[optind];


	/* Set up simplified logging just to stdout/stderr. */
	log_init();
	log_levels_set(LOGT_STDOUT, LOG_ANY, LOG_MASK(LOG_INFO) | LOG_MASK(LOG_NOTICE));
	log_levels_set(LOGT_STDERR, LOG_ANY, LOG_UPTO(LOG_WARNING));
	log_levels_set(LOGT_SYSLOG, LOG_ANY, 0);
	log_flag_set(LOG_FNO_TIMESTAMP | LOG_FNO_INFO);
	if (verbose) {
		log_levels_add(LOGT_STDOUT, LOG_ANY, LOG_MASK(LOG_DEBUG));
	}

	knot_dname_t *dname = knot_dname_from_str_alloc(zonename);

	int ret = zone_check(filename, dname);

	printf("%d", ret);

	free(dname);

	return ret;
}
