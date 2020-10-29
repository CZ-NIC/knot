/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <getopt.h>
#include <libgen.h>
#include <stdio.h>

#include "contrib/time.h"
#include "contrib/tolower.h"
#include "libknot/libknot.h"
#include "knot/common/log.h"
#include "knot/zone/semantic-check.h"
#include "utils/common/params.h"
#include "utils/kzonecheck/zone_check.h"

#define PROGRAM_NAME "kzonecheck"

static void print_help(void)
{
	printf("Usage: %s [parameters] <filename>\n"
	       "\n"
	       "Parameters:\n"
	       " -o, --origin <zone_origin>  Zone name.\n"
	       "                              (default filename without .zone)\n"
	       " -d, --dnssec <on|off>       Also check DNSSEC-related records.\n"
	       " -t, --time <timestamp>      Current time specification.\n"
	       "                              (default current UNIX time)\n"
	       " -v, --verbose               Enable debug output.\n"
	       " -h, --help                  Print the program help.\n"
	       " -V, --version               Print the program version.\n"
	       "\n",
	       PROGRAM_NAME);
}

static bool str2bool(const char *s)
{
	switch (knot_tolower(s[0])) {
	case '1':
	case 'y':
	case 't':
		return true;
	case 'o':
		return knot_tolower(s[1]) == 'n';
	default:
		return false;
	}
}

int main(int argc, char *argv[])
{
	const char *origin = NULL;
	bool verbose = false;
	semcheck_optional_t optional = SEMCHECK_AUTO_DNSSEC; // default value for --dnssec
	knot_time_t check_time = (knot_time_t)time(NULL);

	/* Long options. */
	struct option opts[] = {
		{ "origin",  required_argument, NULL, 'o' },
		{ "time",    required_argument, NULL, 't' },
		{ "dnssec",  required_argument, NULL, 'd' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	/* Set the time zone. */
	tzset();

	/* Parse command line arguments */
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "o:t:d:vVh", opts, NULL)) != -1) {
		switch (opt) {
		case 'o':
			origin = optarg;
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
		case 'd':
			optional = str2bool(optarg) ? SEMCHECK_DNSSEC : SEMCHECK_NO_DNSSEC;
			break;
		case 't':
			if (knot_time_parse("YMDhms|#|+-#U|+-#",
			                    optarg, &check_time) != KNOT_EOK) {
				fprintf(stderr, "Unknown time format\n");
				return EXIT_FAILURE;
			}
			break;
		default:
			print_help();
			return EXIT_FAILURE;
		}
	}

	/* Check if there's at least one remaining non-option. */
	if (optind >= argc) {
		fprintf(stderr, "Expected zone file name\n");
		print_help();
		return EXIT_FAILURE;
	}

	char *filename = argv[optind];

	char *zonename;
	if (origin == NULL) {
		/* Get zone name from file name. */
		const char *ext = ".zone";
		zonename = basename(filename);
		if (strcmp(zonename + strlen(zonename) - strlen(ext), ext) == 0) {
			zonename = strndup(zonename, strlen(zonename) - strlen(ext));
		} else {
			zonename = strdup(zonename);
		}
	} else {
		zonename = strdup(origin);
	}

	log_init();
	log_levels_set(LOG_TARGET_STDOUT, LOG_SOURCE_ANY, 0);
	log_levels_set(LOG_TARGET_STDERR, LOG_SOURCE_ANY, 0);
	log_levels_set(LOG_TARGET_SYSLOG, LOG_SOURCE_ANY, 0);
	log_flag_set(LOG_FLAG_NOTIMESTAMP | LOG_FLAG_NOINFO);
	if (verbose) {
		log_levels_add(LOG_TARGET_STDOUT, LOG_SOURCE_ANY, LOG_UPTO(LOG_DEBUG));
	}

	knot_dname_t *dname = knot_dname_from_str_alloc(zonename);
	free(zonename);
	int ret = zone_check(filename, dname, stdout, optional, (time_t)check_time);
	knot_dname_free(dname, NULL);

	log_close();

	switch (ret) {
	case KNOT_EOK:
		if (verbose) {
			fprintf(stdout, "No semantic error found\n");
		}
		return EXIT_SUCCESS;
	case KNOT_EZONEINVAL:
		fprintf(stdout, "Serious semantic error detected\n");
		// FALLTHROUGH
	case KNOT_ESEMCHECK:
		return EXIT_FAILURE;
	case KNOT_EACCES:
	case KNOT_EFILE:
		fprintf(stderr, "Failed to load the zone file\n");
		return EXIT_FAILURE;
	default:
		fprintf(stderr, "Failed to run semantic checks (%s)\n", knot_strerror(ret));
		return EXIT_FAILURE;
	}
}
