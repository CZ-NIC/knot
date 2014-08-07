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

#include <inttypes.h>			// PRIu64
#include <stdio.h>			// printf
#include <stdlib.h>			// atoi
#include <getopt.h>			// getopt
#include <pthread.h>			// pthread_t

#include "scanner.h"
#include "tests/processing.h"
#include "tests/tests.h"

#define DEFAULT_MODE	1
#define DEFAULT_CLASS	1
#define DEFAULT_TTL	0

static void *timestamp_worker(void *data)
{
	int *ret = (int *)data;
	*ret = test__date_to_timestamp();
	return NULL;
}

static void help(void)
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

static int time_test()
{
	pthread_t t1, t2, t3;
	int ret1, ret2, ret3;

	pthread_create(&t1, NULL, timestamp_worker, &ret1);
	pthread_create(&t2, NULL, timestamp_worker, &ret2);
	pthread_create(&t3, NULL, timestamp_worker, &ret3);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);
	pthread_join(t3, NULL);

	if (ret1 != 0 || ret2 != 0 || ret3 != 0) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int main(int argc, char *argv[])
{
	// Parsed command line arguments.
	int c = 0, li = 0;
	int mode = DEFAULT_MODE, test = 0;

	// Command line long options.
	struct option opts[] = {
		{ "mode",	required_argument,	0,	'm' },
		{ "test",	no_argument,		0,	't' },
		{ "help",	no_argument,		0,	'h' },
		{ 0, 		0, 			0,	0 }
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
		case 'h':
			help();
			return EXIT_SUCCESS;
		default:
			help();
			return EXIT_FAILURE;
		}
	}

	if (test == 1) {
		return time_test();
	}

	// Check if there are 2 remaining non-options.
	if (argc - optind != 2) {
		help();
		return EXIT_FAILURE;
	}

	const char   *origin = argv[optind];
	const char   *zone_file = argv[optind + 1];
	zs_scanner_t *s;

	// Create appropriate zone scanner.
	switch (mode) {
	case 0:
		s = zs_scanner_create(origin,
		                      DEFAULT_CLASS,
		                      DEFAULT_TTL,
		                      NULL,
		                      NULL,
		                      NULL);
		break;
	case 1:
		s = zs_scanner_create(origin,
		                      DEFAULT_CLASS,
		                      DEFAULT_TTL,
		                      &debug_process_record,
		                      &debug_process_error,
		                      NULL);
		break;
	case 2:
		s = zs_scanner_create(origin,
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

	// Check parser creation.
	if (s == NULL) {
		printf("Scanner create error!\n");
		return EXIT_FAILURE;
	}

	// Parse the file.
	int ret = zs_scanner_parse_file(s, zone_file);
	if (ret == 0) {
		if (mode == DEFAULT_MODE) {
			printf("Zone file has been processed successfully\n");
		}
		zs_scanner_free(s);
		return EXIT_SUCCESS;
	} else {
		if (s->error_counter > 0 && mode == DEFAULT_MODE) {
			printf("Zone processing has stopped with "
			       "%"PRIu64" warnings/errors!\n",
			       s->error_counter);
		} else if (mode == DEFAULT_MODE) {
			printf("%s\n", zs_strerror(s->error_code));
		}
		zs_scanner_free(s);
		return EXIT_FAILURE;
	}
}
