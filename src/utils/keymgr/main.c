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

#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "contrib/string.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/libknot.h"
#include "utils/common/params.h"
#include "utils/keymgr/functions.h"

#define PROGRAM_NAME	"keymgr"

static void print_help(void)
{
	printf("Usage:\n"
	       "  %s -h | -V\n"
	       "  %s -t <tsig_name> [<algorithm>] [<bits>]\n"
	       "  %s [-c | -C | -d <path>] <zone> <command> [<argument>...]\n"
	       "\n"
	       "Parameters:\n"
	       "  -c, --config <file>      Use a textual configuration file.\n"
	       "                            (default %s)\n"
	       "  -C, --confdb <dir>       Use a binary configuration database directory.\n"
	       "                            (default %s)\n"
	       "  -d, --dir <path>         Use specified KASP database path and default configuration.\n"
	       "  -t, --tsig <name> [alg]  Generate a TSIG key.\n"
	       "  -h, --help               Print the program help.\n"
	       "  -V, --version            Print the program version.\n"
	       "\n"
	       "Commands:\n"
	       "  list         List all zone's DNSSEC keys.\n"
	       "  generate     Generate new DNSSEC key.\n"
	       "                (syntax: generate <attribute_name>=<value>...)\n"
	       "  import-bind  Import BIND-style key file pair (.key + .private).\n"
	       "                (syntax: import-bind <key_file_name>)\n"
	       "  import-pub   Import public-only key to be published in the zone (in BIND .key format).\n"
	       "                (syntax: import-pub <key_file_name>)\n"
	       "  import-pem   Import key in PEM format. Specify its parameters manually.\n"
	       "                (syntax: import-pem <pem_file_path> <attribute_name>=<value>...)\n"
	       "  ds           Generate DS record(s) for specified key.\n"
	       "                (syntax: ds <key_spec>)\n"
	       "  dnskey       Generate DNSKEY record for specified key.\n"
	       "                (syntax: dnskey <key_spec>)\n"
	       "  share        Share an existing key of another zone with the specified zone.\n"
	       "                (syntax: share <full_key_ID>\n"
	       "  delete       Remove the specified key from zone.\n"
	       "                (syntax: delete <key_spec>)\n"
	       "  set          Set existing key's timing attribute.\n"
	       "                (syntax: set <key_spec> <attribute_name>=<value>...)\n"
	       "\n"
	       "Key specification:\n"
	       "  either the key tag (number) or [a prefix of] key ID.\n"
	       "\n"
	       "Key attributes:\n"
	       "  algorithm  The key cryptographic algorithm: either name (e.g. RSASHA256) or\n"
	       "             number.\n"
	       "  size       The key size in bits.\n"
	       "  ksk        Whether the generated/imported key shall be Key Signing Key.\n"
	       "  created/publish/ready/active/retire/remove  The timestamp of the key\n"
	       "             lifetime event (e.g. published=+1d active=1499770874)\n",
	       PROGRAM_NAME, PROGRAM_NAME, PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR);
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

	conf_val_t mapsize = conf_default_get(conf(), C_MAX_KASP_DB_SIZE);
	char *kasp_dir = conf_kaspdir(conf());
	int ret = kasp_db_init(kaspdb(), kasp_dir, conf_int(&mapsize));
	free(kasp_dir);
	if (ret != KNOT_EOK) {
		printf("Failed to initialize KASP db (%s)\n", knot_strerror(ret));
		goto main_end;
	}

	ret = kdnssec_ctx_init(conf(), &kctx, zone_name, NULL);
	if (ret != KNOT_EOK) {
		printf("Failed to initialize KASP (%s)\n", knot_strerror(ret));
		goto main_end;
	}

#define CHECK_MISSING_ARG(msg) \
	if (argc < 3) { \
		printf("%s\n", (msg)); \
		ret = KNOT_EINVAL; \
		goto main_end; \
	}

	bool print_ok_on_succes = true;
	if (strcmp(argv[1], "generate") == 0) {
		ret = keymgr_generate_key(&kctx, argc - 2, argv + 2);
		print_ok_on_succes = false;
	} else if (strcmp(argv[1], "import-bind") == 0) {
		CHECK_MISSING_ARG("BIND-style key to import not specified");
		ret = keymgr_import_bind(&kctx, argv[2], false);
	} else if (strcmp(argv[1], "import-pub") == 0) {
		CHECK_MISSING_ARG("BIND-style key to import not specified");
		ret = keymgr_import_bind(&kctx, argv[2], true);
	} else if (strcmp(argv[1], "import-pem") == 0) {
		CHECK_MISSING_ARG("PEM file to import not specified");
		ret = keymgr_import_pem(&kctx, argv[2], argc - 3, argv + 3);
	} else if (strcmp(argv[1], "set") == 0) {
		CHECK_MISSING_ARG("Key is not specified");
		knot_kasp_key_t *key2set;
		ret = keymgr_get_key(&kctx, argv[2], &key2set);
		if (ret == KNOT_EOK) {
			ret = keymgr_set_timing(key2set, argc - 3, argv + 3);
			if (ret == KNOT_EOK) {
				ret = kdnssec_ctx_commit(&kctx);
			}
		}
	} else if (strcmp(argv[1], "list") == 0) {
		knot_time_print_t format = TIME_PRINT_UNIX;
		if (argc > 2 && strcmp(argv[2], "human") == 0) {
			format = TIME_PRINT_HUMAN_MIXED;
		} else if (argc > 2 && strcmp(argv[2], "iso") == 0) {
			format = TIME_PRINT_ISO8601;
		}
		ret = keymgr_list_keys(&kctx, format);
		print_ok_on_succes = false;
	} else if (strcmp(argv[1], "ds") == 0 || strcmp(argv[1], "dnskey") == 0) {
		int (*generate_rr)(const knot_dname_t *, const knot_kasp_key_t *) = keymgr_generate_dnskey;
		if (strcmp(argv[1], "ds") == 0) {
			generate_rr = keymgr_generate_ds;
		}
		if (argc < 3) {
			for (int i = 0; i < kctx.zone->num_keys && ret == KNOT_EOK; i++) {
				if (dnssec_key_get_flags(kctx.zone->keys[i].key) == DNSKEY_FLAGS_KSK) {
					ret = generate_rr(zone_name, &kctx.zone->keys[i]);
				}
			}
		} else {
			knot_kasp_key_t *key2rr;
			ret = keymgr_get_key(&kctx, argv[2], &key2rr);
			if (ret == KNOT_EOK) {
				ret = generate_rr(zone_name, key2rr);
			}
		}
		print_ok_on_succes = false;
	} else if (strcmp(argv[1], "share") == 0) {
		CHECK_MISSING_ARG("Key to be shared is not specified");
		knot_dname_t *other_zone = NULL;
		char *key_to_share = NULL;
		ret = keymgr_foreign_key_id(argv, &other_zone, &key_to_share);
		if (ret == KNOT_EOK) {
			ret = kasp_db_share_key(*kctx.kasp_db, other_zone, kctx.zone->dname, key_to_share);
		}
		free(other_zone);
		free(key_to_share);
	} else if (strcmp(argv[1], "delete") == 0) {
		CHECK_MISSING_ARG("Key is not specified");
		knot_kasp_key_t *key2del;
		ret = keymgr_get_key(&kctx, argv[2], &key2del);
		if (ret == KNOT_EOK) {
			ret = kdnssec_delete_key(&kctx, key2del);
		}
	} else {
		printf("Wrong zone-key command: %s\n", argv[1]);
		goto main_end;
	}

#undef CHECK_MISSING_ARG

	if (ret == KNOT_EOK) {
		printf("%s", print_ok_on_succes ? "OK\n" : "");
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
	int ret = conf_new(&new_conf, conf_schema, confdb, flags);
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
	char *confstr = sprintf_alloc("template:\n"""
	                              "  - id: default\n"
	                              "    storage: .\n"
	                              "    kasp-db: %s\n", kasp_dir);
	int ret = conf_import(conf(), confstr, false);
	free(confstr);
	if (ret != KNOT_EOK) {
		printf("Failed creating fake configuration (%s)\n",
		       knot_strerror(ret));
		return false;
	}
	return true;
}

static void update_privileges(void)
{
	int uid, gid;
	if (conf_user(conf(), &uid, &gid) != KNOT_EOK) {
		return;
	}

	// Just try to alter process privileges if different from configured.
	int unused __attribute__((unused));
	if ((gid_t)gid != getgid()) {
		unused = setregid(gid, gid);
	}
	if ((uid_t)uid != getuid()) {
		unused = setreuid(uid, uid);
	}
}

static bool conf_initialized = false; // This is a singleton as well as conf() is.

#define CHECK_CONF_UNINIT \
	if ((conf_initialized = !conf_initialized) == false) { \
		printf("Error: multiple arguments attempting configuration initializatioin.\n"); \
		return EXIT_FAILURE; \
	}

int main(int argc, char *argv[])
{
	int ret;

	struct option opts[] = {
		{ "config",  required_argument, NULL, 'c' },
		{ "confdb",  required_argument, NULL, 'C' },
		{ "dir",     required_argument, NULL, 'd' },
		{ "tsig",    required_argument, NULL, 't' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	int opt = 0, li = 0;
	while ((opt = getopt_long(argc, argv, "hVd:c:C:t:", opts, &li)) != -1) {
		switch (opt) {
		case 'h':
			print_help();
			return EXIT_SUCCESS;
		case 'V':
			print_version(PROGRAM_NAME);
			return EXIT_SUCCESS;
		case 'd':
			CHECK_CONF_UNINIT
			if (!init_conf(NULL) || !init_conf_blank(optarg)) {
				return EXIT_FAILURE;
			}
			break;
		case 'c':
			CHECK_CONF_UNINIT
			if (!init_conf(NULL) || !init_confile(optarg)) {
				return EXIT_FAILURE;
			}
			break;
		case 'C':
			CHECK_CONF_UNINIT
			if (!init_conf(argv[2])) {
				return EXIT_FAILURE;
			}
			break;
		case 't':
			ret = keymgr_generate_tsig(optarg, (argc > optind ? argv[optind] : "hmac-sha256"),
			                           (argc > optind + 1 ? atol(argv[optind + 1]) : 0));
			if (ret != KNOT_EOK) {
				printf("Failed to generate TSIG (%s)\n", knot_strerror(ret));
			}
			return (ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE);
		default:
			print_help();
			return EXIT_FAILURE;
		}
	}

	if (!conf_initialized) {
		struct stat st;
		if (stat(CONF_DEFAULT_DBDIR, &st) == 0 && init_conf(CONF_DEFAULT_DBDIR)) {
			// initialized conf from default DB location
		} else if (stat(CONF_DEFAULT_FILE, &st) == 0 &&
			   init_conf(NULL) && init_confile(CONF_DEFAULT_FILE)) {
			// initialized conf from default confile
		} else {
			printf("Couldn't initialize configuration, please provide -c, -C, or -d option\n");
			return EXIT_FAILURE;
		}
	}

	update_privileges();

	ret = key_command(argc - optind, argv + optind);

	conf_free(conf());

	return (ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE);
}
