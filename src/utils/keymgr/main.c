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
#include <sys/stat.h>

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
	       "                (syntax: import-bind <key_file_name>)\n"
	       "   import-pem   Import key in PEM format. Specify its parameters manually.\n"
	       "                (syntax: import-pem <pem_file_path> <attribute_name>=<value>...)\n"
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

static int key_command(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Zone name and/or command not specified\n");
		print_help();
		return KNOT_EINVAL;
	}
	knot_dname_t *zone_name = knot_dname_from_str_alloc(argv[0]);
	if (zone_name == NULL) {
		return KNOT_ENOMEM;
	}
	(void)knot_dname_to_lower(zone_name);

	kdnssec_ctx_t kctx = { 0 };

	conf_val_t mapsize = conf_default_get(conf(), C_KASP_DB_MAPSIZE);
	char *kasp_dir = conf_kaspdir(conf());
	int ret = kasp_db_init(kaspdb(), kasp_dir, conf_int(&mapsize));
	free(kasp_dir);
	if (ret != KNOT_EOK) {
		printf("Failed to initialize KASP db (%s)\n", knot_strerror(ret));
		goto main_end;
	}

	ret = kdnssec_ctx_init(conf(), &kctx, zone_name, NULL);
	if (ret != KNOT_EOK) {
		printf("Failed to initializize KASP (%s)\n", knot_strerror(ret));
		goto main_end;
	}

	if (strcmp(argv[1], "generate") == 0) {
		ret = keymgr_generate_key(&kctx, argc - 2, argv + 2);
	} else if (strcmp(argv[1], "import-bind") == 0) {
		if (argc < 3) {
			printf("BIND-style key to import not specified\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		ret = keymgr_import_bind(&kctx, argv[2]);
	} else if (strcmp(argv[1], "import-pem") == 0) {
		if (argc < 3) {
			printf("PEM file to import not specified\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		ret = keymgr_import_pem(&kctx, argv[2], argc - 3, argv + 3);
	} else if (strcmp(argv[1], "set") == 0) {
		if (argc < 3) {
			printf("Key is not specified\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		knot_kasp_key_t *key2set;
		ret = keymgr_get_key(&kctx, argv[2], &key2set);
		if (ret == KNOT_EOK) {
			ret = keymgr_set_timing(key2set, argc - 3, argv + 3);
			if (ret == KNOT_EOK) {
				ret = kdnssec_ctx_commit(&kctx);
			}
		}
	} else if (strcmp(argv[1], "list") == 0) {
		ret = keymgr_list_keys(&kctx);
	} else if (strcmp(argv[1], "ds") == 0) {
		if (argc < 3) {
			printf("Key is not specified\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		knot_kasp_key_t *key2ds;
		ret = keymgr_get_key(&kctx, argv[2], &key2ds);
		if (ret == KNOT_EOK) {
			ret = keymgr_generate_ds(zone_name, key2ds);
		}
	} else if (strcmp(argv[1], "share") == 0) {
		knot_dname_t *other_zone = NULL;
		char *key_to_share = NULL;
		if (keymgr_foreign_key_id(argc - 2, argv + 2, "be shared", &other_zone, &key_to_share) == KNOT_EOK) {
			ret = kasp_db_share_key(*kctx.kasp_db, other_zone, kctx.zone->dname, key_to_share);
		}
		free(other_zone);
		free(key_to_share);
	} else if (strcmp(argv[1], "delete") == 0) {
		if (argc < 3) {
			printf("Key is not specified\n");
			ret = KNOT_EINVAL;
			goto main_end;
		}
		knot_kasp_key_t *key2del;
		ret = keymgr_get_key(&kctx, argv[2], &key2del);
		if (ret == KNOT_EOK) {
			ret = kdnssec_delete_key(&kctx, key2del);
		}
	} else {
		printf("Wrong zone-key command: %s\n", argv[1]);
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
	free(zone_name);

	return ret;
}

static bool init_conf(const char *confdb)
{
	conf_flag_t flags = CONF_FNOHOSTNAME | CONF_FOPTMODULES;
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

static bool init_conf_blank(const char *kasp_dir)
{
	char confstr[200 + strlen(kasp_dir)];
	snprintf(confstr, sizeof(confstr),
	"template:\n  - id: default\n    storage: .\n    kasp-db: %s\n", kasp_dir);
	int ret = conf_import(conf(), confstr, false);
	if (ret != KNOT_EOK) {
		printf("Failed creating fake configuration (%s)\n",
		       knot_strerror(ret));
		return false;
	}
	return true;
}

int main(int argc, char *argv[])
{
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

	int argpos = 1;

	if (strlen(argv[1]) == 2 && argv[1][0] == '-') {

#define check_argc_three if (argc < 3) { \
	printf("Option %s requires an argument\n", argv[1]); \
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
			if (!init_conf(NULL) || !init_conf_blank(argv[2])) {
				return EXIT_FAILURE;
			}
			break;
		case 'c':
			check_argc_three
			if (!init_conf(NULL) || !init_confile(argv[2])) {
				return EXIT_FAILURE;
			}
			break;
		case 'C':
			check_argc_three
			if (!init_conf(argv[2])) {
				return EXIT_FAILURE;
			}
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

		argpos = 3;
	} else {
		struct stat st;
		if (stat(CONF_DEFAULT_DBDIR, &st) == 0 && init_conf(CONF_DEFAULT_DBDIR)) {
			// initialized conf from default DB location
		} else if (stat(CONF_DEFAULT_FILE, &st) == 0 &&
			   init_conf(NULL) && init_confile(CONF_DEFAULT_FILE)) {
			// initialized conf from default confile
		} else {
			printf("Couldn't initialize configuration, please provide -c, -C or -d option\n");
			return EXIT_FAILURE;
		}
	}

	int ret = key_command(argc - argpos, argv + argpos);


	conf_free(conf());

	return (ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE);
}
