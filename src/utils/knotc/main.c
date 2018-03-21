/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdio.h>

#include "contrib/strtonum.h"
#include "knot/common/log.h"
#include "utils/common/params.h"
#include "utils/knotc/commands.h"
#include "utils/knotc/interactive.h"
#include "utils/knotc/process.h"

#define PROGRAM_NAME		"knotc"
#define SPACE			"  "
#define DEFAULT_CTL_TIMEOUT	5

static void print_help(void)
{
	printf("Usage: %s [parameters] <action> [action_args]\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>      "SPACE"Use a textual configuration file.\n"
	       "                          "SPACE" (default %s)\n"
	       " -C, --confdb <dir>       "SPACE"Use a binary configuration database directory.\n"
	       "                          "SPACE" (default %s)\n"
	       " -m, --max-conf-size <MiB>"SPACE"Set maximum configuration size (max 10000 MiB).\n"
	       "                          "SPACE" (default %d MiB)\n"
	       " -s, --socket <path>      "SPACE"Use a control UNIX socket path.\n"
	       "                          "SPACE" (default %s)\n"
	       " -t, --timeout <sec>      "SPACE"Use a control socket timeout (max 7200 seconds).\n"
	       "                          "SPACE" (default %u seconds)\n"
	       " -f, --force              "SPACE"Forced operation. Overrides some checks.\n"
	       " -v, --verbose            "SPACE"Enable debug output.\n"
	       " -h, --help               "SPACE"Print the program help.\n"
	       " -V, --version            "SPACE"Print the program version.\n",
	       PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR,
	       CONF_MAPSIZE, RUN_DIR "/knot.sock", DEFAULT_CTL_TIMEOUT);

	print_commands();
}

params_t params = {
	.max_conf_size = (size_t)CONF_MAPSIZE * 1024 * 1024,
	.timeout = DEFAULT_CTL_TIMEOUT * 1000
};

int main(int argc, char **argv)
{
	/* Long options. */
	struct option opts[] = {
		{ "config",        required_argument, NULL, 'c' },
		{ "confdb",        required_argument, NULL, 'C' },
		{ "max-conf-size", required_argument, NULL, 'm' },
		{ "socket",        required_argument, NULL, 's' },
		{ "timeout",       required_argument, NULL, 't' },
		{ "force",         no_argument,       NULL, 'f' },
		{ "verbose",       no_argument,       NULL, 'v' },
		{ "help",          no_argument,       NULL, 'h' },
		{ "version",       no_argument,       NULL, 'V' },
		{ NULL }
	};

	/* Parse command line arguments */
	int opt = 0;
	while ((opt = getopt_long(argc, argv, "+c:C:m:s:t:fvhV", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			params.config = optarg;
			break;
		case 'C':
			params.confdb = optarg;
			break;
		case 'm':
			if (str_to_size(optarg, &params.max_conf_size, 1, 10000) != KNOT_EOK) {
				print_help();
				return EXIT_FAILURE;
			}
			/* Convert to bytes. */
			params.max_conf_size *= 1024 * 1024;
			break;
		case 's':
			params.socket = optarg;
			break;
		case 't':
			if (str_to_int(optarg, &params.timeout, 0, 7200) != KNOT_EOK) {
				print_help();
				return EXIT_FAILURE;
			}
			/* Convert to milliseconds. */
			params.timeout *= 1000;
			break;
		case 'f':
			params.force = true;
			break;
		case 'v':
			params.verbose = true;
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

	/* Set up simplified logging just to stdout/stderr. */
	log_init();
	log_levels_set(LOG_TARGET_STDOUT, LOG_SOURCE_ANY,
	               LOG_MASK(LOG_INFO) | LOG_MASK(LOG_NOTICE));
	log_levels_set(LOG_TARGET_STDERR, LOG_SOURCE_ANY, LOG_UPTO(LOG_WARNING));
	log_levels_set(LOG_TARGET_SYSLOG, LOG_SOURCE_ANY, 0);
	log_flag_set(LOG_FLAG_NOTIMESTAMP | LOG_FLAG_NOINFO);
	if (params.verbose) {
		log_levels_add(LOG_TARGET_STDOUT, LOG_SOURCE_ANY, LOG_MASK(LOG_DEBUG));
	}

	int ret;
	if (argc - optind < 1) {
		ret = interactive_loop(&params);
	} else {
		ret = process_cmd(argc - optind, (const char **)argv + optind, &params);
	}

	log_close();

	return (ret == KNOT_EOK) ? EXIT_SUCCESS : EXIT_FAILURE;
}
