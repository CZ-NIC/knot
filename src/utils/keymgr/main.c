/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "contrib/string.h"
#include "contrib/strtonum.h"
#include "knot/conf/conf.h"
#include "knot/dnssec/zone-keys.h"
#include "libknot/libknot.h"
#include "utils/common/params.h"
#include "utils/keymgr/functions.h"
#include "utils/keymgr/offline_ksk.h"

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
	       "  list          List all zone's DNSSEC keys.\n"
	       "  generate      Generate new DNSSEC key.\n"
	       "                 (syntax: generate <attribute_name>=<value>...)\n"
	       "  import-bind   Import BIND-style key file pair (.key + .private).\n"
	       "                 (syntax: import-bind <key_file_name>)\n"
	       "  import-pub    Import public-only key to be published in the zone (in BIND .key format).\n"
	       "                 (syntax: import-pub <key_file_name>)\n"
	       "  import-pem    Import key in PEM format. Specify its parameters manually.\n"
	       "                 (syntax: import-pem <pem_file_path> <attribute_name>=<value>...)\n"
	       "  import-pkcs11 Import key stored in PKCS11 storage. Specify its parameters manually.\n"
	       "                 (syntax: import-pkcs11 <key_id> <attribute_name>=<value>...)\n"
	       "  nsec3-salt    Print current NSEC3 salt. If a parameter is specified, set new salt.\n"
	       "                 (syntax: nsec3salt [<new_salt>])\n"
	       "  local-serial  Print SOA serial stored in KASP database when using on-slave signing.\n"
	       "                 If a parameter is specified, set new serial.\n"
	       "                 (syntax: serial <new_serial>)\n"
	       "  ds            Generate DS record(s) for specified key.\n"
	       "                 (syntax: ds <key_spec>)\n"
	       "  dnskey        Generate DNSKEY record for specified key.\n"
	       "                 (syntax: dnskey <key_spec>)\n"
	       "  share         Share an existing key of another zone with the specified zone.\n"
	       "                 (syntax: share <full_key_ID> <zone2share_from>\n"
	       "  delete        Remove the specified key from zone.\n"
	       "                 (syntax: delete <key_spec>)\n"
	       "  set           Set existing key's timing attribute.\n"
	       "                 (syntax: set <key_spec> <attribute_name>=<value>...)\n"
	       "\n"
	       "Commands related to Offline KSK feature:\n"
	       "  pregenerate   Pre-generate ZSKs for later rollovers with offline KSK.\n"
	       "                 (syntax: pregenerate <timestamp>)\n"
	       "  show-offline  Print pre-generated offline key-related records for specified time interval (possibly to infinity).\n"
	       "                 (syntax: show-offline <from> [<to>])\n"
	       "  del-offline   Delete pre-generated offline key-related records in specified time interval.\n"
	       "                 (syntax: del-offline <from> <to>)\n"
	       "  del-all-old   Delete old keys that are in state 'removed'.\n"
	       "  generate-ksr  Print to stdout KeySigningRequest based on pre-generated ZSKS.\n"
	       "                 (syntax: generate-ksr <from> <to>)\n"
	       "  sign-ksr      Read KeySigningRequest from a file, sign it and print SignedKeyResponse to stdout.\n"
	       "                 (syntax: sign-ksr <ksr_file>)\n"
	       "  validate-skr  Validate RRSIGs in a SignedKeyResponse (if not corrupt).\n"
	       "                 (syntax: validate-skr <skr_file>)\n"
	       "  import-skr    Import DNSKEY record signatures from a SignedKeyResponse.\n"
	       "                 (syntax: import-skr <skr_file>)\n"
	       "\n"
	       "Key specification:\n"
	       "  either the key tag (number) or [a prefix of] key ID, with an optional\n"
	       "  [id=|keytag=] prefix.\n"
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

static int key_command(int argc, char *argv[], int opt_ind)
{
	if (argc < opt_ind + 2) {
		printf("Zone name and/or command not specified\n");
		print_help();
		return KNOT_EINVAL;
	}
	argc -= opt_ind;
	argv += opt_ind;

	knot_dname_t *zone_name = knot_dname_from_str_alloc(argv[0]);
	if (zone_name == NULL) {
		return KNOT_ENOMEM;
	}
	knot_dname_to_lower(zone_name);

	knot_lmdb_db_t kaspdb = { 0 };
	kdnssec_ctx_t kctx = { 0 };

	conf_val_t mapsize = conf_db_param(conf(), C_KASP_DB_MAX_SIZE, C_MAX_KASP_DB_SIZE);
	char *kasp_dir = conf_db(conf(), C_KASP_DB);
	knot_lmdb_init(&kaspdb, kasp_dir, conf_int(&mapsize), 0, "keys_db");
	free(kasp_dir);

	int ret = kdnssec_ctx_init(conf(), &kctx, zone_name, &kaspdb, NULL);
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

#define CHECK_MISSING_ARG2(msg) \
	if (argc < 4) { \
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
	} else if (strcmp(argv[1], "import-pkcs11") == 0) {
		CHECK_MISSING_ARG("Key ID to import not specified");
		ret = keymgr_import_pkcs11(&kctx, argv[2], argc - 3, argv + 3);
	} else if (strcmp(argv[1], "nsec3-salt") == 0) {
		if (argc > 2) {
			ret = keymgr_nsec3_salt_set(&kctx, argv[2]);
		} else {
			ret = keymgr_nsec3_salt_print(&kctx);
			print_ok_on_succes = false;
		}
	} else if (strcmp(argv[1], "local-serial") == 0) {
		if (argc > 2) {
			uint32_t new_serial = 0;
			if ((ret = str_to_u32(argv[2], &new_serial)) == KNOT_EOK) {
				ret = keymgr_serial_set(&kctx, new_serial);
			}
		} else {
			ret = keymgr_serial_print(&kctx);
			print_ok_on_succes = false;
		}
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
				if (kctx.zone->keys[i].is_ksk) {
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
		CHECK_MISSING_ARG2("Zone to be shared from not specified");
		knot_dname_t *other_zone = NULL;
		char *key_to_share = NULL;
		ret = keymgr_foreign_key_id(argv, &kaspdb, &other_zone, &key_to_share);
		if (ret == KNOT_EOK) {
			ret = kasp_db_share_key(kctx.kasp_db, other_zone, kctx.zone->dname, key_to_share);
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
	} else if (strcmp(argv[1], "pregenerate") == 0) {
		CHECK_MISSING_ARG("Period not specified");
		ret = keymgr_pregenerate_zsks(&kctx, argv[2]);
	} else if (strcmp(argv[1], "show-offline") == 0) {
		CHECK_MISSING_ARG("Timestamp not specified");
		ret = keymgr_print_offline_records(&kctx, argv[2], argc > 3 ? argv[3] : NULL);
	} else if (strcmp(argv[1], "del-offline") == 0) {
		CHECK_MISSING_ARG2("Timestamps from-to not specified");
		ret = keymgr_delete_offline_records(&kctx, argv[2], argv[3]);
	} else if (strcmp(argv[1], "del-all-old") == 0) {
		ret = keymgr_del_all_old(&kctx);
	} else if (strcmp(argv[1], "generate-ksr") == 0) {
		CHECK_MISSING_ARG2("Timestamps from-to not specified");
		ret = keymgr_print_ksr(&kctx, argv[2], argv[3]);
		print_ok_on_succes = false;
	} else if (strcmp(argv[1], "sign-ksr") == 0) {
		CHECK_MISSING_ARG("Input file not specified");
		ret = keymgr_sign_ksr(&kctx, argv[2]);
		print_ok_on_succes = false;
	} else if (strcmp(argv[1], "validate-skr") == 0) {
		CHECK_MISSING_ARG("Input file not specified");
		ret = keymgr_validate_skr(&kctx, argv[2]);
	} else if (strcmp(argv[1], "import-skr") == 0) {
		CHECK_MISSING_ARG("Input file not specified");
		ret = keymgr_import_skr(&kctx, argv[2]);
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
	knot_lmdb_deinit(&kaspdb);
	free(zone_name);

	return ret;
}

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

static bool init_confile(const char *confile)
{
	int ret = conf_import(conf(), confile, true, false);
	if (ret != KNOT_EOK) {
		printf("Failed opening configuration file %s (%s)\n",
		       confile, knot_strerror(ret));
		return false;
	}
	return true;
}

static bool init_conf_blank(const char *kasp_dir)
{
	char *confstr = sprintf_alloc("database:\n"
	                              "  storage: .\n"
	                              "  kasp-db: \"%s\"\n", kasp_dir);
	int ret = conf_import(conf(), confstr, false, false);
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

	tzset();

	int opt = 0, parm = 0;
	while ((opt = getopt_long(argc, argv, "hVd:c:C:t:", opts, NULL)) != -1) {
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
			if (argc > optind + 1) {
				(void)str_to_int(argv[optind + 1], &parm, 0, 65536);
			}
			ret = keymgr_generate_tsig(optarg, (argc > optind ? argv[optind] : "hmac-sha256"), parm);
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
		if (conf_db_exists(CONF_DEFAULT_DBDIR) && init_conf(CONF_DEFAULT_DBDIR)) {
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

	ret = key_command(argc, argv, optind);

	conf_free(conf());

	return (ret == KNOT_EOK ? EXIT_SUCCESS : EXIT_FAILURE);
}
