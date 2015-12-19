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

#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "tests/processing.h"
#include "tests/tests.h"
#include "scanner.h"

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
	       " -s           State parsing mode.\n"
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

int state_parsing(
	zs_scanner_t *s)
{
	zs_scanner_t *ss;

	while (zs_parse_record(s) == 0) {
		switch (s->state) {
		case ZS_STATE_DATA:
			if (s->process.record != NULL) {
				s->process.record(s);
			}
			break;
		case ZS_STATE_ERROR:
			if (s->process.error != NULL) {
				s->process.error(s);
			}
			if (s->error.fatal) {
				return -1;
			}
			break;
		case ZS_STATE_INCLUDE:
			ss = malloc(sizeof(zs_scanner_t));
			if (ss == NULL) {
				return -1;
			}
			if (zs_init(ss, (char *)s->buffer, s->default_class, s->default_ttl) != 0 ||
			    zs_set_input_file(ss, (char *)(s->include_filename)) != 0 ||
			    zs_set_processing(ss, s->process.record, s->process.error, s->process.data) != 0 ||
			    state_parsing(ss) != 0 ||
			    ss->error.counter > 0) {
				if (ss->error.counter > 0) {
					s->error.code = ZS_UNPROCESSED_INCLUDE;
				} else {
					s->error.code = ss->error.code;
				}

				s->error.counter++;
				s->error.fatal = true;
				if (s->process.error != NULL) {
					s->process.error(s);
				}

				zs_deinit(ss);
				free(ss);
				return -1;
			}
			zs_deinit(ss);
			free(ss);
			break;
		case ZS_STATE_NONE:
			break;
		case ZS_STATE_EOF:
			// Set the next input string block.
			break;
		case ZS_STATE_STOP:
			return 0;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	// Parsed command line arguments.
	int c = 0, li = 0, ret;
	int mode = DEFAULT_MODE, state = 0, test = 0;

	// Command line long options.
	struct option opts[] = {
		{ "mode",	required_argument,	0,	'm' },
		{ "state",	no_argument,		0,	's' },
		{ "test",	no_argument,		0,	't' },
		{ "help",	no_argument,		0,	'h' },
		{ 0, 		0, 			0,	0 }
	};

	// Command line options processing.
	while ((c = getopt_long(argc, argv, "m:sth", opts, &li)) != -1) {
		switch (c) {
		case 'm':
			mode = atoi(optarg);
			break;
		case 's':
			state = 1;
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

	const char *origin = argv[optind];
	const char *zone_file = argv[optind + 1];

	// Create a zone scanner.
	zs_scanner_t *s = malloc(sizeof(zs_scanner_t));
	if (s == NULL) {
		printf("Scanner create error!\n");
		return EXIT_FAILURE;
	}
	if (zs_init(s, origin, DEFAULT_CLASS, DEFAULT_TTL) != 0) {
		printf("Scanner init error!\n");
		free(s);
		return EXIT_FAILURE;
	}
	if (zs_set_input_file(s, zone_file) != 0) {
		printf("Scanner file error!\n");
		zs_deinit(s);
		free(s);
		return EXIT_FAILURE;
	}

	// Set the processing mode.
	switch (mode) {
	case 0:
		ret = 0;
		break;
	case 1:
		ret = zs_set_processing(s, debug_process_record, debug_process_error, NULL);
		break;
	case 2:
		ret = zs_set_processing(s, test_process_record, test_process_error, NULL);
		break;
	default:
		printf("Bad mode number!\n");
		help();
		return EXIT_FAILURE;
	}
	if (ret != 0) {
		printf("Processing setup error!\n");
		return EXIT_FAILURE;
	}

	// Parse the file.
	ret = state ? state_parsing(s) : zs_parse_all(s);
	if (ret == 0) {
		if (mode == DEFAULT_MODE) {
			printf("Zone file has been processed successfully\n");
		}

		zs_deinit(s);
		free(s);
		return EXIT_SUCCESS;
	} else {
		if (s->error.counter > 0 && mode == DEFAULT_MODE) {
			printf("Zone processing has stopped with "
			       "%"PRIu64" warnings/errors!\n",
			       s->error.counter);
		} else if (mode == DEFAULT_MODE) {
			printf("%s\n", zs_strerror(s->error.code));
		}

		zs_deinit(s);
		free(s);
		return EXIT_FAILURE;
	}
}
