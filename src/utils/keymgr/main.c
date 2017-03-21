/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>

#include "knot/conf/conf.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/libknot.h"
#include "utils/common/params.h"
#include "utils/keymgr/functions.h"

#define PROGRAM_NAME	"keymgr"

static void print_help(void)
{
	printf("Usage: %s [parameter] options/commands...\n"
	       "\n"
	       "Parameters:\n"
	       " -h     Display this help.\n"
	       " -V     Print program version.\n"
	       " -t     Generate TSIG key.\n"
	       "        (syntax: -t <tsig_name> [<algorithm>] [<bits>]\n"
	       " -d     Use specified KASP db path.\n"
	       "        (syntax: -d <KASP_dir> <zone> <command> options...)\n"
	       " -c     Use specified Knot config file.\n"
	       "        (syntax: -c <config_file> <zone> <command> options...)\n"
	       " -C     Use specified Knot configuration database.\n"
	       "        (syntax: -C <confdb_dir> <zone> <command> options...)\n"
	       "\n"
	       "Commands:\n"
	       "   list         List all zone's KASP keys.\n"
	       "   generate     Generate new KASP key.\n"
	       "                (syntax: generate <attribute_name>=<value>...)\n"
	       "   import-bind  Import BIND-style key file pair (.key + .private).\n"
	       "                (syntax: import_bind <key_file_name>)\n"
	       "   ds           Generate DS record(s) for specified key.\n"
	       "                (syntax: ds <key_spec>)\n"
	       "   share        Make an existing key of another zone to be shared with"
	       " the specified zone.\n"
	       "                (syntax: share <full_key_ID>\n"
	       "   delete       Remove the specified key from zone.\n"
	       "                (syntax: delete <key_spec>)\n"
	       "   set          Set existing key's timing attribute.\n"
	       "                (syntax: set <key_spec> <attribute_name>=<value>...)\n",
	       PROGRAM_NAME);
}

static bool init_conf(const char *confdb)
{
	conf_flag_t flags = CONF_FNOHOSTNAME;
	if (confdb != NULL) {
		flags |= CONF_FREADONLY;
	}

	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, conf_scheme, confdb, flags);
	if (ret != KNOT_EOK) {
		printf("Failed opening configuration database %s (%s)\n",
		       (confdb == NULL ? "" : confdb), knot_strerror(ret));
		return false;
	}
	conf_update(new_conf, CONF_UPD_FNONE);
	return true;
}

static bool init_confile(const char *confile)
{
	int ret = conf_import(conf(), confile, true);
	if (ret != KNOT_EOK) {
		printf("Failed opening configuration file %s (%s)\n",
		       confile, knot_strerror(ret));
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
	char *kasp_path = NULL;

	if (argc <= 1) {
		print_help();
		return EXIT_SUCCESS;
	}

	if (strcmp(argv[1], "--help") == 0) {
		print_help();
		return EXIT_SUCCESS;
	}
	if (strcmp(argv[1], "--version") == 0) {
		print_version(PROGRAM_NAME);
		return EXIT_SUCCESS;
	}

	if (strlen(argv[1]) != 2 || argv[1][0] != '-') {
		printf("Bad argument: %s\n", argv[1]);
		print_help();
		return EXIT_FAILURE;
	}

#define check_argc_three if (argc < 3) { \
	printf("Option %s requires an argument.\n", argv[1]); \
	print_help(); \
	return EXIT_FAILURE; \
}

	switch (argv[1][1]) {
	case 'h':
		print_help();
		return EXIT_SUCCESS;
	case 'V':
		print_version(PROGRAM_NAME);
		return EXIT_SUCCESS;
	case 'd':
		check_argc_three
		if (!init_conf(NULL)) {
			return EXIT_FAILURE;
		}
		kasp_path = strdup(argv[2]);
		break;
	case 'c':
		check_argc_three
		if (!init_conf(NULL) || !init_confile(argv[2])) {
			return EXIT_FAILURE;
		}
		kasp_path = conf_kaspdir(conf());
		break;
	case 'C':
		check_argc_three
		if (!init_conf(argv[2])) {
			return EXIT_FAILURE;
		}
		kasp_path = conf_kaspdir(conf());
		break;
	case 't':
		check_argc_three
		int tret = keymgr_generate_tsig(argv[2], (argc >= 4 ? argv[3] : "hmac-sha256"),
		                                (argc >= 5 ? atol(argv[4]) : 0));
		if (tret != KNOT_EOK) {
			printf("Failed to generate TSIG (%s)\n", knot_strerror(tret));
		}
		return (tret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE);
	default:
		printf("Wrong option: %s\n", argv[1]);
		print_help();
		return EXIT_FAILURE;
	}

#undef check_argc_three

	if (kasp_path == NULL) {
		printf("Unable to gather KASP db path from %s\n", argv[2]);
		print_help();
		return EXIT_FAILURE;
	}

	if (argc < 5) {
		printf("Zone name and/or command not specified.\n");
		print_help();
		free(kasp_path);
		return EXIT_FAILURE;
	}
	knot_dname_t *zone_name = knot_dname_from_str_alloc(argv[3]);
	if (zone_name == NULL) {
		free(kasp_path);
		return EXIT_FAILURE;
	}
	(void)knot_dname_to_lower(zone_name);

	kdnssec_ctx_t kctx = { 0 };

	int ret = kasp_db_init(kaspdb(), kasp_path, 500*1024*1024 /* TODO */);
	if (ret != KNOT_EOK) {
		printf("Failed to initialize KASP db (%s)\n", knot_strerror(ret));
		goto main_end;
	}

	ret = kdnssec_kasp_init(&kctx, kasp_path, 500*1024*1024 /* TODO */, zone_name, "default");
	if (ret != KNOT_EOK) {
		printf("Failed to initializize KASP (%s)\n", knot_strerror(ret));
		goto main_end;
	}

	if (strcmp(argv[4], "generate") == 0) {
		ret = keymgr_generate_key(&kctx, argc - 5, argv + 5);
	} else if (strcmp(argv[4], "import-bind") == 0) {
		if (argc < 6) {
			printf("BIND-style key to import not specified.\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		ret = keymgr_import_bind(&kctx, argv[5]);
	} else if (strcmp(argv[4], "set") == 0) {
		if (argc < 6) {
			printf("Key is not specified.\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		knot_kasp_key_t *key2set;
		ret = keymgr_get_key(&kctx, argv[5], &key2set);
		if (ret == KNOT_EOK) {
			ret = keymgr_set_timing(key2set, argc - 6, argv + 6);
			if (ret == KNOT_EOK) {
				ret = kdnssec_ctx_commit(&kctx);
			}
		}
	} else if (strcmp(argv[4], "list") == 0) {
		ret = keymgr_list_keys(&kctx);
	} else if (strcmp(argv[4], "ds") == 0) {
		if (argc < 6) {
			printf("Key is not specified.\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		knot_kasp_key_t *key2ds;
		ret = keymgr_get_key(&kctx, argv[5], &key2ds);
		if (ret == KNOT_EOK) {
			ret = keymgr_generate_ds(zone_name, key2ds);
		}
	} else if (strcmp(argv[4], "share") == 0) {
		if (argc < 6) {
			printf("Key ID is not specified.\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		ret = kasp_db_share_key(*kctx.kasp_db, zone_name, argv[5]);
	} else if (strcmp(argv[4], "delete") == 0) {
		if (argc < 6) {
			printf("Key is not specified.\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		knot_kasp_key_t *key2del;
		ret = keymgr_get_key(&kctx, argv[5], &key2del);
		if (ret == KNOT_EOK) {
			ret = kdnssec_delete_key(&kctx, key2del);
		}
	} else {
		printf("Wrong zone-key command: %s\n", argv[4]);
		goto main_end;
	}

	if (ret == KNOT_EOK) {
		printf("OK\n");
	} else {
		printf("Error (%s)\n", knot_strerror(ret));
	}

main_end:
	kdnssec_ctx_deinit(&kctx);
	kasp_db_close(kaspdb());
	free(kasp_path);
	free(zone_name);

	return (ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE);
}
