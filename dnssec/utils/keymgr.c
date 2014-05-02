/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>

#include "shared.h"
#include "utils.h"

typedef struct global_params {
	const char *kasp_dir;
} global_params_t;

static void help(void)
{
	printf("%s [OPTIONS...] COMMAND ...\n\n"
	       "Query or manage DNSSEC key and signing policy.\n\n"
	       "  -h --help              Show this help\n"
	       "     --version           Show tool version\n"
	       "  -d --dir               KASP storage directory\n\n"
	       "Commands:\n"
	       "  zone                   Manage zones\n"
	       "  key                    Manage keys\n\n",
	       program_invocation_short_name);
}

static void version(void)
{
	printf("%s (libdnssec), version %s\n",
	       program_invocation_short_name,
	       PACKAGE_VERSION);
}

int main_zone(int argc, char *argv[], global_params_t *global)
{
	printf("%s\n", __func__);
	return 0;
}

int main_key(int argc, char *argv[], global_params_t *global)
{
	printf("%s\n", __func__);
	return 0;
}

/*!
 * Parse global options.
 *
 * \retval -1 Parsing failed.
 * \retval 0  Parsing OK, terminate.
 * \retval 1  Parsing OK, continue.
 *
 */
int parse_options(int argc, char *argv[], global_params_t *global)
{
	enum {
		ARG_VERSION = 0x100,
	};

	static const struct option options[] = {
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, ARG_VERSION },
		{ "dir",     required_argument, NULL, 'd' },
		{ NULL },
	};

	int c;
        while ((c = getopt_long(argc, argv, "+hd:", options, NULL)) >= 0) {
		switch (c) {
		case 'h':
			help();
			return 0;
		case ARG_VERSION:
			version();
			return 0;
		case 'd':
			global->kasp_dir = optarg;
			break;
		default:
			assert(c == '?');
			return -1;
		}
	};

	return 1;
}

int parse_command(int argc, char *argv[], global_params_t *global)
{
	int left = argc - optind;
	if (left == 0) {
		error("No command specified.\n");
		return 1;
	}

	static const struct {
		const char *name;
		int (*callback)(int argc, char *argv[], global_params_t *global);
	} commands[] = {
		{ "zone", main_zone },
		{ "key",  main_key },
	};

	char *command = argv[optind];
	for (int i = 0; i < 2; i++) {
		if (streq(commands[i].name, command)) {
			optind += 1;
			return commands[i].callback(argc, argv, global);
		}
	}

	error("Unknown command.\n");
	return 1;
}

int main(int argc, char *argv[])
{
	global_params_t global = {};

	int r = parse_options(argc, argv, &global);
	if (r < 0) {
		return 1;
	} else if (r == 0) {
		return 0;
	}

	return parse_command(argc, argv, &global);
}
