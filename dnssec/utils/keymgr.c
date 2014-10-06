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

#include <dnssec/error.h>
#include <dnssec/kasp.h>

#include "shared.h"
#include "utils.h"

/* -- global options ------------------------------------------------------- */

struct options {
	char *kasp_dir;
};

typedef struct options options_t;

/* -- internal ------------------------------------------------------------- */

static void cleanup_kasp(dnssec_kasp_t **kasp_ptr)
{
	dnssec_kasp_deinit(*kasp_ptr);
}

#define _cleanup_kasp_ _cleanup_(cleanup_kasp)

/* -- subcommands processing ----------------------------------------------- */

struct command {
	const char *name;
	int (*callback)(options_t *options, int argc, char *argv[]);
};

typedef struct command command_t;

static int subcommand(const command_t *subcommands, options_t *options,
			   int argc, char *argv[])
{
	assert(subcommands);
	assert(options);
	assert(argv);

	if (argc < 1) {
		error("No command specified.\n");
		return 1;
	}

	char *command = argv[0];
	for (const command_t *cmd = subcommands; cmd->name != NULL; cmd++) {
		if (strcmp(command, cmd->name) == 0) {
			fprintf(stderr, "[debug] command '%s'\n", cmd->name);
			return cmd->callback(options, argc, argv);
		}
	}

	error("Invalid command.\n");
	return 1;
}

/* -- actions implementation ----------------------------------------------- */

/*
 * keymgr init
 */
static int cmd_init(options_t *options, int argc, char *argv[])
{
	if (argc != 1) {
		error("Extra parameters supplied.\n");
		return 1;
	}

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_init(kasp, options->kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot initialize KASP directory (%s).\n",
		      dnssec_strerror(r));
	}

	return (r == DNSSEC_EOK ? 0 : 1);
}

/*
 * keymgr zone add [--policy <policy>] <name>
 */
static int cmd_zone_add(options_t *options, int argc, char *argv[])
{
	char *policy_name = NULL;

	static const struct option opts[] = {
		{ "policy", required_argument, NULL, 'p' },
		{ NULL }
	};

	int c = 0;
	optind = 0;
	while (c = getopt_long(argc, argv, "+p:", opts, NULL), c != -1) {
		switch (c) {
		case 'p':
			policy_name = optarg;
			break;
		case '?':
			error("Invalid option");
			return 1;
		default:
			assert(0);
		}
	}

	if (argc != optind + 1) {
		error("Invalid number of positional arguments.\n");
		return 1;
	}

	char *zone_name = argv[optind];

	// create zone

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_open(kasp, options->kasp_dir);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_open: %s\n", dnssec_strerror(r));
		return 1;
	}

	dnssec_kasp_zone_t *zone = dnssec_kasp_zone_new(zone_name);
	if (!zone) {
		error("dnssec_kasp_zone_new: %s\n", dnssec_strerror(r));
		return 1;
	}

	r = dnssec_kasp_save_zone(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_save_zone: %s\n", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

/*
 * keymgr zone list [substring-match]
 */
static int cmd_zone_list(options_t *options, int argc, char *argv[])
{
	const char *match;
	if (argc == 1) {
		match = NULL;
	} else if (argc == 2) {
		match = argv[1];
	} else {
		error("Extra parameter specified.\n");
		return 1;
	}

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_open(kasp, options->kasp_dir);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_open: %s\n", dnssec_strerror(r));
		return 1;
	}

	printf("list of zones (match substring '%s')\n", match ? match : "");


	return 0;
}

/*
 * keymgr zone
 */
static int cmd_zone(options_t *options, int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "add",  cmd_zone_add },
		{ "list", cmd_zone_list },
		{ NULL }
	};

	return subcommand(commands, options, argc - 1, argv + 1);
}

static int cmd_policy(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int cmd_keystore(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int cmd_key_generate(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int cmd_key_import(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int cmd_key(options_t *options, int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "generate", cmd_key_generate },
		{ "import",   cmd_key_import },
		{ NULL }
	};

	return subcommand(commands, options, argc - 1, argv + 1);
}

int main(int argc, char *argv[])
{
	int exit_code = 1;

	// global configuration

	options_t options = { 0 };
	options.kasp_dir = getcwd(NULL, 0);
	assert(options.kasp_dir);

	// global options

	static const struct option opts[] = {
		{ "dir", required_argument, NULL, 'd' },
		{ NULL }
	};

	int c = 0;
	while (c = getopt_long(argc, argv, "+", opts, NULL), c != -1) {
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

	// subcommands

	static const command_t commands[] = {
		{ "init",     cmd_init },
		{ "zone",     cmd_zone },
		{ "policy",   cmd_policy },
		{ "keystore", cmd_keystore },
		{ "key",      cmd_key },
		{ NULL }
	};

	exit_code = subcommand(commands, &options, argc - optind, argv + optind);

failed:
	free(options.kasp_dir);

	return exit_code;
}
