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
#include <dnssec/keystore.h>

#include "shared.h"
#include "utils.h"

/* -- global options ------------------------------------------------------- */

struct options {
	char *kasp_dir;
	char *keystore_dir;
};

typedef struct options options_t;

/* -- internal ------------------------------------------------------------- */

static void cleanup_kasp(dnssec_kasp_t **kasp_ptr)
{
	dnssec_kasp_deinit(*kasp_ptr);
}

static void cleanup_keystore(dnssec_keystore_t **keystore_ptr)
{
	dnssec_keystore_deinit(*keystore_ptr);
}

static void cleanup_kasp_zone(dnssec_kasp_zone_t **zone_ptr)
{
	dnssec_kasp_zone_free(*zone_ptr);
}

#define _cleanup_kasp_ _cleanup_(cleanup_kasp)
#define _cleanup_keystore_ _cleanup_(cleanup_keystore)
#define _cleanup_zone_ _cleanup_(cleanup_kasp_zone)

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

	// KASP

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_init(kasp, options->kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot initialize KASP directory (%s).\n",
		      dnssec_strerror(r));
		return 1;
	}

	// keystore

	_cleanup_keystore_ dnssec_keystore_t *store = NULL;
	dnssec_keystore_init_pkcs8_dir(&store);

	r = dnssec_keystore_init(store, options->keystore_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot initialize default keystore (%s).\n",
		      dnssec_strerror(r));
		return 1;
	}

	return 0;
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

	r = dnssec_kasp_zone_save(kasp, zone);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_zone_save: %s\n", dnssec_strerror(r));
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

	dnssec_list_t *zones = NULL;
	r = dnssec_kasp_zone_list(kasp, &zones);
	if (r != DNSSEC_EOK) {
		error("dnssec_kasp_list_zones");
	}

	bool found_match = false;

	dnssec_list_foreach(item, zones) {
		const char *name = dnssec_item_get(item);
		if (match == NULL || strcasestr(name, match) != NULL) {
			found_match = true;
			printf("%s\n", name);
		}
	}

	if (!found_match) {
		fprintf(stderr, "No matching zone found.\n");
	}

	dnssec_list_free_full(zones, NULL, NULL);

	return 0;
}

static bool is_zone_used(dnssec_kasp_zone_t *zone)
{
	time_t now = time(NULL);
	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(item, keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(item);
		if (dnssec_kasp_key_is_used(&key->timing, now)) {
			return true;
		}
	}

	return false;
}

/*
 * keymgr zone remove [--force] <name>
 */
static int cmd_zone_remove(options_t *options, int argc, char *argv[])
{
	static const struct option opts[] = {
		{ "force", no_argument, NULL, 'f' },
		{ NULL }
	};

	bool force = false;

	int c = 0;
	optind = 0;
	while (c = getopt_long(argc, argv, "+", opts, NULL), c != -1) {
		switch (c) {
		case 'f':
			force = true;
			break;
		case '?':
			error("Invalid option.\n");
			return 1;
		default:
			assert(0);
		}
	}

	if (argc != optind + 1) {
		error("Name of one zone has to be specified.\n");
		return 1;
	}

	char *zone_name = argv[optind];

	// delete zone

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_open(kasp, options->kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot open KASP directory (%s).\n", dnssec_strerror(r));
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = NULL;
	r = dnssec_kasp_zone_load(kasp, zone_name, &zone);
	if (r != DNSSEC_EOK) {
		error("Cannot retrieve zone from KASP (%s).\n", dnssec_strerror(r));
		return 1;
	}

	if (!force && is_zone_used(zone)) {
		error("Some keys are being used. Cannot remove the zone "
		      "unless --force is given.\n");
		return 1;
	}

	r = dnssec_kasp_zone_remove(kasp, zone_name);
	if (r != DNSSEC_EOK) {
		error("Cannot remove the zone (%s).\n", dnssec_strerror(r));
		return 1;
	}

	return 0;
}

static int cmd_zone_key_list(options_t *options, int argc, char *argv[])
{
	error("Not implemented.\n");
	return 1;
}

/*
 * keymgr zone key generate <zone> <algorithm> [<bits>] [ksk]
 */
static int cmd_zone_key_generate(options_t *options, int argc, char *argv[])
{
	if (argc != 3) {
		error("Invalid parameters.\n");
		return 1;
	}

	const char *zone_name = argv[1];
	const char *algorithm_name = argv[2];

	_cleanup_kasp_ dnssec_kasp_t *kasp = NULL;
	dnssec_kasp_init_dir(&kasp);

	int r = dnssec_kasp_open(kasp, options->kasp_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot open KASP directory (%s).\n", dnssec_strerror(r));
		return 1;
	}

	_cleanup_zone_ dnssec_kasp_zone_t *zone = NULL;
	r = dnssec_kasp_zone_load(kasp, zone_name, &zone);
	if (r != DNSSEC_EOK) {
		error("Cannot retrieve zone from KASP (%s).\n", dnssec_strerror(r));
		return 1;
	}

	error("Not implemented.\n");
	return 1;
}

static int cmd_zone_key_import(options_t *options, int argc, char *argv[])
{
	error("Not implemented.\n");
	return 1;
}

static int cmd_zone_key(options_t *options, int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list",     cmd_zone_key_list },
		{ "generate", cmd_zone_key_generate },
		{ "import",   cmd_zone_key_import },
		{ NULL }
	};

	return subcommand(commands, options, argc -1, argv + 1);
}

static int cmd_zone(options_t *options, int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "add",    cmd_zone_add },
		{ "list",   cmd_zone_list },
		{ "remove", cmd_zone_remove },
		{ "key",    cmd_zone_key },
		{ NULL }
	};

	return subcommand(commands, options, argc - 1, argv + 1);
}

static int cmd_policy(options_t *options, int argc, char *argv[])
{
	error("Not implemented.");
	return 1;
}

static int cmd_keystore_list(options_t *options, int argc, char *argv[])
{
	_cleanup_keystore_ dnssec_keystore_t *store = NULL;
	dnssec_keystore_init_pkcs8_dir(&store);
	int r = dnssec_keystore_open(store, options->keystore_dir);
	if (r != DNSSEC_EOK) {
		error("Cannot open default key store (%s).\n", dnssec_strerror(r));
		return 1;
	}

	dnssec_list_t *keys = NULL;
	dnssec_keystore_list_keys(store, &keys);
	dnssec_list_foreach(item, keys) {
		const char *key_id = dnssec_item_get(item);
		printf("%s\n", key_id);
	}
	dnssec_list_free_full(keys, NULL, NULL);

	return 0;
}

static int cmd_keystore(options_t *options, int argc, char *argv[])
{
	static const command_t commands[] = {
		{ "list",   cmd_keystore_list },
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

	if (asprintf(&options.keystore_dir, "%s/keys", options.kasp_dir) == -1) {
		error("failed to allocate memory\n");
		goto failed;
	}

	// subcommands

	static const command_t commands[] = {
		{ "init",     cmd_init },
		{ "zone",     cmd_zone },
		{ "policy",   cmd_policy },
		{ "keystore", cmd_keystore },
		{ NULL }
	};

	exit_code = subcommand(commands, &options, argc - optind, argv + optind);

failed:
	free(options.kasp_dir);
	free(options.keystore_dir);

	return exit_code;
}
