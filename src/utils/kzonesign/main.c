/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdlib.h>

#include "knot/conf/conf.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/zone-update.h"
#include "knot/server/server.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "utils/common/params.h"

#define PROGRAM_NAME "kzonesign"

static const char *global_outdir = NULL;

// copy-pasted from keymgr
static bool init_conf(const char *confdb)
{
	size_t max_conf_size = (size_t)CONF_MAPSIZE * 1024 * 1024;

	conf_flag_t flags = CONF_FNOHOSTNAME | CONF_FOPTMODULES;
	if (confdb != NULL) {
		flags |= CONF_FREADONLY;
	}

	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, conf_schema, confdb, max_conf_size, flags);
	if (ret != KNOT_EOK) {
		printf("Failed opening configuration database %s (%s)\n",
		       (confdb == NULL ? "" : confdb), knot_strerror(ret));
		return false;
	}
	conf_update(new_conf, CONF_UPD_FNONE);
	return true;
}

static void print_help(void)
{
	printf("Usage: %s [parameters] -c <conf_file> <zone_name>\n"
	       "\n"
	       "Parameters:\n"
	       " -o, --outdir <dir_name>  Output directory.\n"
	       " -r, --rollover           Allow key rollovers and NSEC3 re-salt.\n"
	       " -t, --time <timestamp>   Current time specification.\n"
	       "                            (default current UNIX time)\n"
	       " -h, --help               Print the program help.\n"
	       " -V, --version            Print the program version.\n"
	       "\n",
	       PROGRAM_NAME);
}

int main(int argc, char *argv[])
{
	const char *confile = NULL, *zone_str = NULL;
	knot_dname_t *zone_name = NULL;
	zone_contents_t *unsigned_conts = NULL;
	zone_t *zone_struct = NULL;
	zone_update_t up = { 0 };
	server_t fake_server = { 0 };
	zone_sign_roll_flags_t rollover = 0;
	int64_t timestamp = 0;
	zone_sign_reschedule_t next_sign = { 0 };

	struct option opts[] = {
		{ "config",    required_argument, NULL, 'c' },
		{ "outdir",    required_argument, NULL, 'o' },
		{ "rollover",  no_argument,       NULL, 'r' },
		{ "time",      required_argument, NULL, 't' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ NULL }
	};

	tzset();

	int opt;
	while ((opt = getopt_long(argc, argv, "c:o:rt:hV", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			confile = optarg;
			break;
		case 'o':
			global_outdir = optarg;
			break;
		case 'r':
			rollover = KEY_ROLL_ALLOW_ALL;
			break;
		case 't':
			timestamp = atol(optarg);
			if (timestamp <= 0) {
				print_help();
				return EXIT_FAILURE;
			}
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
	if (confile == NULL || argc - optind != 1) {
		print_help();
		return EXIT_FAILURE;
	}

	zone_str = argv[optind];
	zone_name = knot_dname_from_str_alloc(zone_str);
	if (zone_name == NULL) {
		printf("Invalid zone name '%s'\n", zone_str);
		return EXIT_FAILURE;
	}
	knot_dname_to_lower(zone_name);

	if (!init_conf(NULL)) {
		free(zone_name);
		return EXIT_FAILURE;
	}

	int ret = conf_import(conf(), confile, true, false);
	if (ret != KNOT_EOK) {
		printf("Failed opening configuration file '%s' (%s)\n",
		       confile, knot_strerror(ret));
		goto fail;
	}

	conf_val_t val = conf_zone_get(conf(), C_DOMAIN, zone_name);
	if (val.code != KNOT_EOK) {
		printf("Zone '%s' not configured\n", zone_str);
		ret = val.code;
		goto fail;
	}
	val = conf_zone_get(conf(), C_DNSSEC_POLICY, zone_name);
	if (val.code != KNOT_EOK) {
		printf("Waring: DNSSEC policy not configured for zone '%s', taking defaults\n", zone_str);
	}

	zone_struct = zone_new(zone_name);
	if (zone_struct == NULL) {
		printf("out of memory\n");
		ret = KNOT_ENOMEM;
		goto fail;
	}

	ret = zone_load_contents(conf(), zone_name, &unsigned_conts, false);
	if (ret != KNOT_EOK) {
		printf("Failed to load zone contents (%s)\n", knot_strerror(ret));
		goto fail;
	}

	ret = zone_update_from_contents(&up, zone_struct, unsigned_conts, UPDATE_FULL);
	if (ret != KNOT_EOK) {
		printf("Failed to initialize zone update (%s)\n", knot_strerror(ret));
		zone_contents_deep_free(unsigned_conts);
		goto fail;
	}

	kasp_db_ensure_init(&fake_server.kaspdb, conf());
	zone_struct->server = &fake_server;

	ret = knot_dnssec_zone_sign(&up, conf(), 0, rollover, timestamp, &next_sign);
	if (ret == KNOT_DNSSEC_ENOKEY) { // exception: allow generating initial keys
		rollover = KEY_ROLL_ALLOW_ALL;
		ret = knot_dnssec_zone_sign(&up, conf(), 0, rollover, timestamp, &next_sign);
	}
	if (ret != KNOT_EOK) {
		printf("Failed to sign the zone (%s)\n", knot_strerror(ret));
		zone_update_clear(&up);
		goto fail;
	}

	if (global_outdir == NULL) {
		char *zonefile = conf_zonefile(conf(), zone_name);
		ret = zonefile_write(zonefile, up.new_cont);
		free(zonefile);
	} else {
		zone_contents_t *temp = zone_struct->contents;
		zone_struct->contents = up.new_cont;
		ret = zone_dump_to_dir(conf(), zone_struct, global_outdir);
		zone_struct->contents = temp;
	}
	zone_update_clear(&up);
	if (ret != KNOT_EOK) {
		printf("Failed to flush signed zone file (%s)\n", knot_strerror(ret));
		goto fail;
	}

	printf("Next signing: %"KNOT_TIME_PRINTF"\n", next_sign.next_sign);
	if (rollover) {
		printf("Next roll-over: %"KNOT_TIME_PRINTF"\n", next_sign.next_rollover);
		if (next_sign.next_nsec3resalt) {
			printf("Next NSEC3 re-salt: %"KNOT_TIME_PRINTF"\n", next_sign.next_nsec3resalt);
		}
		if (next_sign.plan_ds_check) {
			printf("KSK submission to parent zone needed\n");
		}
	}

fail:
	if (fake_server.kaspdb.path != NULL) {
		knot_lmdb_deinit(&fake_server.kaspdb);
	}
	zone_free(&zone_struct);
	conf_free(conf());
	free(zone_name);
	return ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE;
}
