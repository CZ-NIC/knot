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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "utils.h"

struct options {
	char *kasp_dir;
};

typedef struct options options_t;

struct command {
	const char *name;
	int (*callback)(options_t *options, int argc, char *argv[]);
};

typedef struct command command_t;

/*
 * keymgr init
 */
static int main_init(options_t *options, int argc, char *argv[])
{
	fprintf(stderr, "KASP dir %s\n", options->kasp_dir);

	error("Not implemented.");
	return 1;
}

static int main_zone(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int main_policy(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int main_keystore(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int main_key(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int subcommand(const command_t *subcommands, options_t *options,
			   int argc, char *argv[])
{
	assert(subcommands);
	assert(options);
	assert(argv);

	if (argc < 1) {
		error("No command specified");
		return 1;
	}

	char *command = argv[0];
	for (const command_t *cmd = subcommands; cmd->name != NULL; cmd++) {
		if (strcmp(command, cmd->name) == 0) {
			return cmd->callback(options, argc - 1, argv + 1);
		}
	}

	error("Invalid command");
	return 1;
}

static const command_t main_commands[] = {
	{ "init",     main_init },
	{ "zone",     main_zone },
	{ "policy",   main_policy },
	{ "keystore", main_keystore },
	{ "key",      main_key },
	{ NULL }
};

int main(int argc, char *argv[])
{
	int exit_code = 1;

	// global configuration
	options_t options = { 0 };
	options.kasp_dir = getcwd(NULL, 0);
	assert(options.kasp_dir);

	// global options
	static struct option opts[] = {
		{ "dir", required_argument, NULL, 'd' },
		{ NULL }
	};

	int c = 0;
	int opt_index = 0;
	while (c = getopt_long(argc, argv, "+", opts, &opt_index), c != -1) {
		switch (c) {
		case 'd':
			free(options.kasp_dir);
			options.kasp_dir = strdup(optarg);
			break;
		case '?':
			goto failed;
		default:
			assert(0);
		}
	}

	exit_code = subcommand(main_commands, &options, optind, argv + optind);

failed:
	free(options.kasp_dir);

	return exit_code;
}
