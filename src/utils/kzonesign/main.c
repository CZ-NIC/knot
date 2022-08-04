/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/dnssec/zone-events.h"
#include "knot/updates/zone-update.h"
#include "knot/server/server.h"
#include "knot/zone/adjust.h"
#include "knot/zone/zone-load.h"
#include "knot/zone/zonefile.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "utils/common/util_conf.h"
#include "contrib/strtonum.h"

#define PROGRAM_NAME "kzonesign"

static void print_help(void)
{
	printf("Usage: %s [-c | -C <path>] [parameters] <zone_name>\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>      Path to a textual configuration file.\n"
	       "                           (default %s)\n"
	       " -C, --confdb <dir>       Path to a configuration database directory.\n"
	       "                           (default %s)\n"
	       " -o, --outdir <dir_name>  Output directory.\n"
	       " -r, --rollover           Allow key rollovers and NSEC3 re-salt.\n"
	       " -v, --verify             Only verify if zone is signed correctly.\n"
	       " -t, --time <timestamp>   Current time specification.\n"
	       "                           (default current UNIX time)\n"
	       " -h, --help               Print the program help.\n"
	       " -V, --version            Print the program version.\n"
	       "\n",
	       PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR);
}

typedef struct {
	const char *zone_name_str;
	knot_dname_storage_t zone_name;
	const char *outdir;
	zone_sign_roll_flags_t rollover;
	int64_t timestamp;
	bool verify;
} sign_params_t;

static int zonesign(sign_params_t *params)
{
	char *zonefile = NULL;
	zone_contents_t *unsigned_conts = NULL;
	zone_t *zone_struct = NULL;
	zone_update_t up = { 0 };
	server_t fake_server = { 0 };
	zone_sign_reschedule_t next_sign = { 0 };
	int ret = KNOT_ERROR;

	conf_val_t val = conf_zone_get(conf(), C_DOMAIN, params->zone_name);
	if (val.code != KNOT_EOK) {
		ERR2("zone '%s' not configured", params->zone_name_str);
		ret = KNOT_ENOENT;
		goto fail;
	}
	val = conf_zone_get(conf(), C_DNSSEC_POLICY, params->zone_name);
	if (val.code != KNOT_EOK) {
		WARN2("DNSSEC policy not configured for zone '%s', taking defaults",
		      params->zone_name_str);
	}

	zone_struct = zone_new(params->zone_name);
	if (zone_struct == NULL) {
		ERR2("out of memory");
		ret = KNOT_ENOMEM;
		goto fail;
	}

	ret = zone_load_contents(conf(), params->zone_name, &unsigned_conts,
	                         SEMCHECK_MANDATORY_SOFT, false);
	if (ret != KNOT_EOK) {
		ERR2("failed to load zone contents (%s)", knot_strerror(ret));
		goto fail;
	}

	ret = zone_update_from_contents(&up, zone_struct, unsigned_conts, UPDATE_FULL);
	if (ret != KNOT_EOK) {
		ERR2("failed to initialize zone update (%s)", knot_strerror(ret));
		zone_contents_deep_free(unsigned_conts);
		goto fail;
	}

	if (params->verify) {
		val = conf_zone_get(conf(), C_ADJUST_THR, params->zone_name);
		ret = zone_adjust_full(up.new_cont, conf_int(&val));
		if (ret != KNOT_EOK) {
			ERR2("failed to adjust the zone (%s)", knot_strerror(ret));
			zone_update_clear(&up);
			goto fail;
		}

		ret = knot_dnssec_validate_zone(&up, conf(), params->timestamp, false);
		if (ret != KNOT_EOK) {
			ERR2("DNSSEC validation failed (%s)", knot_strerror(ret));
			char type_str[16];
			knot_dname_txt_storage_t name_str;
			if (knot_dname_to_str(name_str, up.validation_hint.node, sizeof(name_str)) != NULL &&
			    knot_rrtype_to_string(up.validation_hint.rrtype, type_str, sizeof(type_str)) >= 0) {
				ERR2("affected node: '%s' type '%s'", name_str, type_str);
			}
		} else {
			INFO2("DNSSEC validation successful");
		}
		zone_update_clear(&up);
		goto fail;
	}

	kasp_db_ensure_init(&fake_server.kaspdb, conf());
	zone_struct->server = &fake_server;

	ret = knot_dnssec_zone_sign(&up, conf(), 0, params->rollover,
	                            params->timestamp, &next_sign);
	if (ret == KNOT_DNSSEC_ENOKEY) { // exception: allow generating initial keys
		params->rollover = KEY_ROLL_ALLOW_ALL;
		ret = knot_dnssec_zone_sign(&up, conf(), 0, params->rollover,
		                            params->timestamp, &next_sign);
	}
	if (ret != KNOT_EOK) {
		ERR2("failed to sign the zone (%s)", knot_strerror(ret));
		zone_update_clear(&up);
		goto fail;
	}

	if (params->outdir == NULL) {
		zonefile = conf_zonefile(conf(), params->zone_name);
		ret = zonefile_write(zonefile, up.new_cont);
	} else {
		zone_contents_t *temp = zone_struct->contents;
		zone_struct->contents = up.new_cont;
		ret = zone_dump_to_dir(conf(), zone_struct, params->outdir);
		zone_struct->contents = temp;
	}
	zone_update_clear(&up);
	if (ret != KNOT_EOK) {
		if (params->outdir == NULL) {
			ERR2("failed to update zone file '%s' (%s)",
			     zonefile, knot_strerror(ret));
		} else {
			ERR2("failed to flush signed zone to '%s' file (%s)",
			     params->outdir, knot_strerror(ret));

		}
		goto fail;
	}

	INFO2("Next signing: %"KNOT_TIME_PRINTF, next_sign.next_sign);
	if (params->rollover) {
		INFO2("Next roll-over: %"KNOT_TIME_PRINTF, next_sign.next_rollover);
		if (next_sign.next_nsec3resalt) {
			INFO2("Next NSEC3 re-salt: %"KNOT_TIME_PRINTF, next_sign.next_nsec3resalt);
		}
		if (next_sign.plan_ds_check) {
			INFO2("KSK submission to parent zone needed");
		}
	}

fail:
	if (fake_server.kaspdb.path != NULL) {
		knot_lmdb_deinit(&fake_server.kaspdb);
	}
	zone_free(&zone_struct);
	free(zonefile);

	return ret;
}

int main(int argc, char *argv[])
{
	sign_params_t params = { 0 };

	struct option opts[] = {
		{ "config",    required_argument, NULL, 'c' },
		{ "confdb",    required_argument, NULL, 'C' },
		{ "outdir",    required_argument, NULL, 'o' },
		{ "rollover",  no_argument,       NULL, 'r' },
		{ "verify" ,   no_argument,       NULL, 'v' },
		{ "time",      required_argument, NULL, 't' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ NULL }
	};

	tzset();

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "c:C:o:rvt:hV", opts, NULL)) != -1) {
		switch (opt) {
		case 'c':
			if (util_conf_init_file(optarg) != KNOT_EOK) {
				goto failure;
			}
			break;
		case 'C':
			if (util_conf_init_confdb(optarg) != KNOT_EOK) {
				goto failure;
			}
			break;
		case 'o':
			params.outdir = optarg;
			break;
		case 'r':
			params.rollover = KEY_ROLL_ALLOW_ALL;
			break;
		case 'v':
			params.verify = true;
			break;
		case 't':
			; uint32_t num = 0;
			if (str_to_u32(optarg, &num) != KNOT_EOK || num == 0) {
				print_help();
				goto failure;
			}
			params.timestamp = num;
			break;
		case 'h':
			print_help();
			goto success;
		case 'V':
			print_version(PROGRAM_NAME);
			goto success;
		default:
			print_help();
			goto failure;
		}
	}
	if (argc - optind != 1) {
		ERR2("missing zone name");
		print_help();
		goto failure;
	}
	params.zone_name_str = argv[optind];
	if (knot_dname_from_str(params.zone_name, params.zone_name_str,
	                        sizeof(params.zone_name)) == NULL) {
		ERR2("invalid zone name '%s'", params.zone_name_str);
		print_help();
		goto failure;
	}
	knot_dname_to_lower(params.zone_name);

	if (util_conf_init_default(false) != KNOT_EOK) {
		goto failure;
	}

	if (zonesign(&params) != KNOT_EOK) {
		goto failure;
	}

success:
	util_conf_deinit();
	return EXIT_SUCCESS;
failure:
	util_conf_deinit();
	return EXIT_FAILURE;
}
