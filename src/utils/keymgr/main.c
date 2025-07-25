/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "contrib/strtonum.h"
#include "knot/dnssec/zone-keys.h"
#include "libdnssec/crypto.h"
#include "libknot/libknot.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "utils/common/signal.h"
#include "utils/common/util_conf.h"
#include "utils/keymgr/functions.h"
#include "utils/keymgr/keystore.h"
#include "utils/keymgr/offline_ksk.h"

#define PROGRAM_NAME	"keymgr"

signal_ctx_t signal_ctx = { 0 }; // global, needed by signal handler

static void print_help(void)
{
	printf("Usage:\n"
	       "  %s [-c | -C | -D <path>] [options] <zone_name> <command>\n"
	       "  %s [-c | -C | -D <path>] [options] <keystore_id> <command>\n"
	       "  %s [-c | -C | -D <path>] [-j] -l\n"
	       "  %s -t <tsig_name> [<algorithm> [<bits>]]\n"
	       "\n"
	       "Config options:\n"
	       "  -c, --config <file>      Path to a textual configuration file.\n"
	       "                            (default %s)\n"
	       "  -C, --confdb <dir>       Path to a configuration database directory.\n"
	       "                            (default %s)\n"
	       "  -D, --dir <path>         Path to a KASP database directory, use default configuration.\n"
	       "\n"
	       "Options:\n"
	       "  -t, --tsig <name> [alg]  Generate a TSIG key.\n"
	       "  -e, --extended           Extended output (listing of keys with full description).\n"
	       "  -j, --json               Print the zones or keys in JSON format.\n"
	       "  -l, --list               List all zones that have at least one key in KASP database.\n"
	       "  -x, --mono               Don't color the output.\n"
	       "  -X, --color              Force output colorization in the normal mode.\n"
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
	       "                 (syntax: nsec3-salt [<new_salt>])\n"
	       "  local-serial  Print SOA serial stored in KASP database when using on-slave signing.\n"
	       "                 If a parameter is specified, set new serial.\n"
	       "                 (syntax: local-serial <new_serial>)\n"
	       "  master-serial Print SOA serial of the remote master stored in KASP database when using on-slave signing.\n"
	       "                 If a parameter is specified, set new master serial.\n"
	       "                 (syntax: master-serial <new_serial>)\n"
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
	       "Keystore commands:\n"
	       "  keystore-test   Conduct some tests on the specified keystore.\n"
	       "                   Use a configured keystore id or '-' for the default.\n"
	       "  keystore-bench  Conduct a signing benchmark for each supported algorithm.\n"
	       "                   Use a configured keystore id or '-' for the default.\n"
	       "                   (syntax: keystore_bench [<num_threads>])\n"
	       "\n"
	       "Commands related to Offline KSK feature:\n"
	       "  pregenerate   Pre-generate ZSKs for later rollovers with offline KSK.\n"
	       "                 (syntax: pregenerate [<from>] <to>)\n"
	       "  show-offline  Print pre-generated offline key-related records for specified time interval (possibly to infinity).\n"
	       "                 (syntax: show-offline [<from>] [<to>])\n"
	       "  del-offline   Delete pre-generated offline key-related records in specified time interval.\n"
	       "                 (syntax: del-offline <from> <to>)\n"
	       "  del-all-old   Delete old keys that are in state 'removed'.\n"
	       "  generate-ksr  Print to stdout KeySigningRequest based on pre-generated ZSKS.\n"
	       "                 (syntax: generate-ksr [<from>] <to>)\n"
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
	       "  algorithm  The key cryptographic algorithm: either name (e.g. RSASHA256) or number.\n"
	       "  size       The key size in bits.\n"
	       "  ksk        The key is KSK.\n"
	       "  zsk        The key is ZSK.\n"
	       "  sep        Overrides the standard setting of SEP.\n"
	       "  for-later  The key is for later use.\n"
	       "  created/publish/ready/active/retire/remove/pre_active/post_active/retire_active/revoke"
	       "             The timestamp of the key lifetime event (e.g. published=+1d active=1499770874)\n",
	       PROGRAM_NAME, PROGRAM_NAME, PROGRAM_NAME, PROGRAM_NAME, CONF_DEFAULT_FILE,
	       CONF_DEFAULT_DBDIR);
}

static int key_command(int argc, char *argv[], int opt_ind, knot_lmdb_db_t *kaspdb,
                       keymgr_list_params_t *list_params)
{
	if (argc < opt_ind + 2) {
		ERR2("zone name or command not specified");
		print_help();
		return KNOT_EINVAL;
	}
	argc -= opt_ind;
	argv += opt_ind;

	const char *id_str = argv[0];
	knot_dname_t *zone_name = knot_dname_from_str_alloc(id_str);
	if (zone_name == NULL) {
		return KNOT_ENOMEM;
	}
	knot_dname_to_lower(zone_name);

	kdnssec_ctx_t kctx = { 0 };

	int ret = kdnssec_ctx_init(conf(), &kctx, zone_name, kaspdb, NULL);
	if (ret != KNOT_EOK) {
		ERR2("failed to initialize KASP (%s)", knot_strerror(ret));
		goto main_end;
	}

#define CHECK_MISSING_ARG(msg) \
	if (argc < 3) { \
		ERR2("%s", (msg)); \
		ret = KNOT_EINVAL; \
		goto main_end; \
	}

#define CHECK_MISSING_ARG2(msg) \
	if (argc < 4) { \
		ERR2("%s", (msg)); \
		ret = KNOT_EINVAL; \
		goto main_end; \
	}

	bool print_ok_on_succes = true;
	if (same_command(argv[1], "generate", false)) {
		ret = keymgr_generate_key(&kctx, argc - 2, argv + 2);
		print_ok_on_succes = false;
	} else if (same_command(argv[1], "import-bind", false)) {
		CHECK_MISSING_ARG("BIND-style key to import not specified");
		ret = keymgr_import_bind(&kctx, argv[2], false);
	} else if (same_command(argv[1], "import-pub", false)) {
		CHECK_MISSING_ARG("BIND-style key to import not specified");
		ret = keymgr_import_bind(&kctx, argv[2], true);
	} else if (same_command(argv[1], "import-pem", false)) {
		CHECK_MISSING_ARG("PEM file to import not specified");
		ret = keymgr_import_pem(&kctx, argv[2], argc - 3, argv + 3);
	} else if (same_command(argv[1], "import-pkcs11", false)) {
		CHECK_MISSING_ARG("Key ID to import not specified");
		ret = keymgr_import_pkcs11(&kctx, argv[2], argc - 3, argv + 3);
	} else if (same_command(argv[1], "nsec3-salt", false)) {
		if (argc > 2) {
			ret = keymgr_nsec3_salt_set(&kctx, argv[2]);
		} else {
			ret = keymgr_nsec3_salt_print(&kctx);
			print_ok_on_succes = false;
		}
	} else if (same_command(argv[1], "local-serial", false) || same_command(argv[1], "master-serial", false)) {
		kaspdb_serial_t type = (argv[1][0] == 'm' ? KASPDB_SERIAL_MASTER : KASPDB_SERIAL_LASTSIGNED);
		if (argc > 2) {
			uint32_t new_serial = 0;
			if ((ret = str_to_u32(argv[2], &new_serial)) == KNOT_EOK) {
				ret = keymgr_serial_set(&kctx, type, new_serial);
			}
		} else {
			ret = keymgr_serial_print(&kctx, type);
			print_ok_on_succes = false;
		}
	} else if (same_command(argv[1], "set", false)) {
		CHECK_MISSING_ARG("Key is not specified");
		knot_kasp_key_t *key2set;
		ret = keymgr_get_key(&kctx, argv[2], &key2set);
		if (ret == KNOT_EOK) {
			ret = keymgr_set_timing(key2set, argc - 3, argv + 3);
			if (ret == KNOT_EOK) {
				ret = kdnssec_ctx_commit(&kctx);
			}
		}
	} else if (same_command(argv[1], "list", false)) {
		list_params->format = TIME_PRINT_UNIX;
		if (argc > 2 && same_command(argv[2], "human", false)) {
			list_params->format = TIME_PRINT_HUMAN_MIXED;
		} else if (argc > 2 && same_command(argv[2], "iso", false)) {
			list_params->format = TIME_PRINT_ISO8601;
		}
		ret = keymgr_list_keys(&kctx, list_params);
		print_ok_on_succes = false;
	} else if (same_command(argv[1], "ds", false) || same_command(argv[1], "dnskey", false)) {
		int (*generate_rr)(const knot_dname_t *, const knot_kasp_key_t *) = keymgr_generate_dnskey;
		if (same_command(argv[1], "ds", false)) {
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
	} else if (same_command(argv[1], "share", false)) {
		CHECK_MISSING_ARG("Key to be shared is not specified");
		CHECK_MISSING_ARG2("Zone to be shared from not specified");
		knot_dname_t *other_zone = NULL;
		char *key_to_share = NULL;
		ret = keymgr_foreign_key_id(argv, kaspdb, &other_zone, &key_to_share);
		if (ret == KNOT_EOK) {
			ret = kasp_db_share_key(kctx.kasp_db, other_zone, kctx.zone->dname, key_to_share);
		}
		free(other_zone);
		free(key_to_share);
	} else if (same_command(argv[1], "delete", false)) {
		CHECK_MISSING_ARG("Key is not specified");
		knot_kasp_key_t *key2del;
		ret = keymgr_get_key(&kctx, argv[2], &key2del);
		if (ret == KNOT_EOK) {
			ret = kdnssec_delete_key(&kctx, key2del);
		}
	} else if (same_command(argv[1], "pregenerate", false)) {
		CHECK_MISSING_ARG("Timestamp to not specified");
		ret = keymgr_pregenerate_zsks(&kctx, argc > 3 ? argv[2] : NULL,
		                                     argc > 3 ? argv[3] : argv[2]);
	} else if (same_command(argv[1], "show-offline", false)) {
		ret = keymgr_print_offline_records(&kctx, argc > 2 ? argv[2] : NULL,
		                                          argc > 3 ? argv[3] : NULL);
		print_ok_on_succes = false;
	} else if (same_command(argv[1], "del-offline", false)) {
		CHECK_MISSING_ARG2("Timestamps from-to not specified");
		ret = keymgr_delete_offline_records(&kctx, argv[2], argv[3]);
	} else if (same_command(argv[1], "del-all-old", false)) {
		ret = keymgr_del_all_old(&kctx);
	} else if (same_command(argv[1], "generate-ksr", false)) {
		CHECK_MISSING_ARG("Timestamps to not specified");
		ret = keymgr_print_ksr(&kctx, argc > 3 ? argv[2] : NULL,
		                              argc > 3 ? argv[3] : argv[2]);
		print_ok_on_succes = false;
	} else if (same_command(argv[1], "sign-ksr", false)) {
		CHECK_MISSING_ARG("Input file not specified");
		ret = keymgr_sign_ksr(&kctx, argv[2]);
		print_ok_on_succes = false;
	} else if (same_command(argv[1], "validate-skr", false)) {
		CHECK_MISSING_ARG("Input file not specified");
		ret = keymgr_validate_skr(&kctx, argv[2]);
	} else if (same_command(argv[1], "import-skr", false)) {
		CHECK_MISSING_ARG("Input file not specified");
		ret = keymgr_import_skr(&kctx, argv[2]);
	} else if (same_command(argv[1], "keystore-test", false)) {
		ret = keymgr_keystore_test(id_str, list_params);
		print_ok_on_succes = false;
	} else if (same_command(argv[1], "keystore-bench", false)) {
		uint16_t threads = 1;
		if (argc > 2) {
			ret = str_to_u16(argv[2], &threads);
		}
		if (ret == KNOT_EOK && threads > 0) {
			ret = keymgr_keystore_bench(id_str, list_params, threads);
		} else {
			ret = KNOT_EINVAL;
		}
		print_ok_on_succes = false;
	} else {
		ERR2("invalid command '%s'", argv[1]);
		goto main_end;
	}

#undef CHECK_MISSING_ARG

	if (ret == KNOT_EOK) {
		printf("%s", print_ok_on_succes ? "OK\n" : "");
	} else {
		ERR2("%s", knot_strerror(ret));
	}

main_end:
	kdnssec_ctx_deinit(&kctx);
	free(zone_name);

	return ret;
}

int main(int argc, char *argv[])
{
	knot_lmdb_db_t kaspdb = { 0 };

	struct option opts[] = {
		{ "config",   required_argument, NULL, 'c' },
		{ "confdb",   required_argument, NULL, 'C' },
		{ "dir",      required_argument, NULL, 'D' },
		{ "tsig",     required_argument, NULL, 't' },
		{ "extended", no_argument,       NULL, 'e' },
		{ "list",     no_argument,       NULL, 'l' },
		{ "mono",     no_argument,       NULL, 'x' },
		{ "color",    no_argument,       NULL, 'X' },
		{ "help",     no_argument,       NULL, 'h' },
		{ "version",  optional_argument, NULL, 'V' },
		{ "json",     no_argument,       NULL, 'j' },
		{ NULL }
	};

	tzset();

	dnssec_crypto_init();

	signal_ctx.close_db = &kaspdb;
	signal_init_std();
	struct sigaction sigact = { .sa_handler = SIG_IGN };
	sigaction(SIGALRM, &sigact, NULL);

	int ret;
	bool just_list = false;
	keymgr_list_params_t list_params = { 0 };

	list_params.color = isatty(STDOUT_FILENO);

	int opt = 0, parm = 0;
	while ((opt = getopt_long(argc, argv, "c:C:D:t:ejlxXhV::", opts, NULL)) != -1) {
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
		case 'D':
			if (util_conf_init_justdb("kasp-db", optarg) != KNOT_EOK) {
				goto failure;
			}
			break;
		case 't':
			if (argc > optind + 1) {
				(void)str_to_int(argv[optind + 1], &parm, 0, 65536);
			}
			ret = keymgr_generate_tsig(optarg, (argc > optind ? argv[optind] : "hmac-sha256"), parm);
			if (ret != KNOT_EOK) {
				ERR2("failed to generate TSIG (%s)", knot_strerror(ret));
				goto failure;
			}
			goto success;
		case 'e':
			list_params.extended = true;
			break;
		case 'j':
			list_params.json = true;
			break;
		case 'l':
			just_list = true;
			break;
		case 'x':
			list_params.color = false;
			break;
		case 'X':
			list_params.color = true;
			break;
		case 'h':
			print_help();
			goto success;
		case 'V':
			print_version(PROGRAM_NAME, optarg != NULL);
			goto success;
		default:
			print_help();
			goto failure;
		}
	}

	signal_ctx.color = list_params.color;

	if (util_conf_init_default(true) != KNOT_EOK) {
		goto failure;
	}

	util_update_privileges();

	conf_val_t mapsize = conf_db_param(conf(), C_KASP_DB_MAX_SIZE);
	char *kasp_dir = conf_db(conf(), C_KASP_DB);
	knot_lmdb_init(&kaspdb, kasp_dir, conf_int(&mapsize), 0, "keys_db");
	free(kasp_dir);

	if (just_list) {
		ret = keymgr_list_zones(&kaspdb, list_params.json);
	} else {
		ret = key_command(argc, argv, optind, &kaspdb, &list_params);
	}
	knot_lmdb_deinit(&kaspdb);
	if (ret != KNOT_EOK) {
		goto failure;
	}

success:
	util_conf_deinit();
	dnssec_crypto_cleanup();
	return EXIT_SUCCESS;
failure:
	util_conf_deinit();
	dnssec_crypto_cleanup();
	return EXIT_FAILURE;
}
