/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <inttypes.h>			// PRIu64
#include <stdio.h>			// printf
#include <stdlib.h>			// atoi
#include <getopt.h>			// getopt

#include "common/errcode.h"		// knot_strerror
#include "zscanner/file_loader.h"	// file_loader
#include "zscanner/test/processing.h"	// processing functions
#include "zscanner/test/tests.h"	// test functions

#define DEFAULT_MODE	1

void help(void)
{
	printf("\nZone scanner testing tool.\n"
	       "Usage: zscanner-tool [parameters] origin zonefile\n"
	       "\n"
	       "Parameters:\n"
	       " -m [0,1,2]   Processing mode.\n"
	       "     0        Empty output.\n"
	       "     1        Debug output (DEFAULT).\n"
	       "     2        Test output.\n"
	       " -t           Launch unit tests.\n"
	       " -h           Print this help.\n");
}

int main(int argc, char *argv[])
{
	// Parsed command line arguments.
	int c = 0, li = 0;
	int ret, mode = DEFAULT_MODE, test = 0;
	file_loader_t *fl;
	const char *origin;
	const char *zone_file;

	// Command line long options.
	struct option opts[] = {
		{"mode",	required_argument, 0, 'm'},
		{"test",	no_argument,	   0, 't'},
		{"help",	no_argument,	   0, 'h'},
		{0, 		0, 		   0, 0}
	};

	// Command line options processing.
	while ((c = getopt_long(argc, argv, "m:th", opts, &li)) != -1) {
		switch (c) {
		case 'm':
			mode = atoi(optarg);
			break;
		case 't':
			test = 1;
			break;
		case 'h': // Fall through.
		default:
			help();
			return EXIT_FAILURE;
		}
	}

	if (test == 1) {
		test__date_to_timestamp();
	} else {
		// Check if there are 2 remaining non-options.
		if (argc - optind != 2) {
			help();
			return EXIT_FAILURE;
		}

		zone_file = argv[optind];
		origin = argv[optind + 1];

		// Create appropriate file loader.
		switch (mode) {
		case 0:
			fl = file_loader_create(origin,
						zone_file,
						DEFAULT_CLASS,
						DEFAULT_TTL,
						&empty_process,
						&empty_process,
						NULL);
			break;
		case 1:
			fl = file_loader_create(origin,
						zone_file,
						DEFAULT_CLASS,
						DEFAULT_TTL,
						&debug_process_record,
						&debug_process_error,
						NULL);
			break;
		case 2:
			fl = file_loader_create(origin,
						zone_file,
						DEFAULT_CLASS,
						DEFAULT_TTL,
						&test_process_record,
						&test_process_error,
						NULL);
			break;
		default:
			printf("Bad mode number!\n");
			help();
			return EXIT_FAILURE;
		}

		// Check file loader.
		if (fl != NULL) {
			ret = file_loader_process(fl);

			switch (ret) {
			case KNOT_EOK:
				if (mode == DEFAULT_MODE) {
					printf("Zone file has been processed "
					       "successfully\n");
				}
				file_loader_free(fl);
				break;

			case FLOADER_ESCANNER:
				if (mode == DEFAULT_MODE) {
					printf("Zone processing has stopped with "
					       "%"PRIu64" warnings/errors!\n",
					       fl->scanner->error_counter);
				}
				file_loader_free(fl);
				return EXIT_FAILURE;

			default:
				if (mode == DEFAULT_MODE) {
					printf("%s\n", knot_strerror(ret));
				}
				file_loader_free(fl);
				return EXIT_FAILURE;
			}
		} else {
			printf("File open error!\n");
			return EXIT_FAILURE;
		}
	}

	return EXIT_SUCCESS;
}
