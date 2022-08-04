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
#include <sys/stat.h>
#include <unistd.h>

#include "libknot/libknot.h"
#include "knot/journal/journal_basic.h"
#include "knot/journal/journal_metadata.h"
#include "knot/journal/journal_read.h"
#include "knot/journal/serialization.h"
#include "knot/zone/zone-dump.h"
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "utils/common/util_conf.h"
#include "contrib/color.h"
#include "contrib/strtonum.h"
#include "contrib/string.h"

#define PROGRAM_NAME	"kjournalprint"

static void print_help(void)
{
	printf("Usage:\n"
	       " %s [-c | -C | -D <path>] [parameters] <zone_name>\n"
	       " %s [-c | -C | -D <path>] -z\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>  Path to a textual configuration file.\n"
	       "                       (default %s)\n"
	       " -C, --confdb <dir>   Path to a configuration database directory.\n"
	       "                       (default %s)\n"
	       " -D, --dir <path>     Path to a journal database directory, use default configuration.\n"
	       " -z, --zone-list      Instead of reading the journal, display the list\n"
	       "                      of zones in the DB.\n"
	       " -l, --limit <num>    Read only <num> newest changes.\n"
	       " -s, --serial <soa>   Start with a specific SOA serial.\n"
	       " -H, --check          Additional journal semantic checks.\n"
	       " -d, --debug          Debug mode output.\n"
	       " -x, --mono           Get output without coloring.\n"
	       " -n, --no-color       An alias for -x, deprecated.\n"
	       " -X, --color          Force output coloring.\n"
	       " -h, --help           Print the program help.\n"
	       " -V, --version        Print the program version.\n",
	       PROGRAM_NAME, PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR);
}

typedef struct {
	bool debug;
	bool color;
	bool check;
	int limit;
	int counter;
	uint32_t serial;
	bool from_serial;
	size_t changes;
} print_params_t;

static void print_changeset(const changeset_t *chs, print_params_t *params)
{
	static size_t count = 1;
	if (chs->soa_from == NULL) {
		printf("%s;; Zone-in-journal, serial: %u, changeset: %zu%s\n",
		       COL_YELW(params->color),
		       knot_soa_serial(chs->soa_to->rrs.rdata),
		       count++,
		       COL_RST(params->color));
	} else {
		printf("%s;; Changes between zone versions: %u -> %u, changeset: %zu%s\n",
		       COL_YELW(params->color),
		       knot_soa_serial(chs->soa_from->rrs.rdata),
		       knot_soa_serial(chs->soa_to->rrs.rdata),
		       count++,
		       COL_RST(params->color));
	}
	changeset_print(chs, stdout, params->color);
}

knot_dynarray_declare(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC, 100)
knot_dynarray_define(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC)

typedef struct {
	rrtype_dynarray_t *arr;
	size_t *counter;
} rrtypelist_ctx_t;

static void rrtypelist_add(rrtype_dynarray_t *arr, uint16_t add_type)
{
	bool already_present = false;
	knot_dynarray_foreach(rrtype, uint16_t, i, *arr) {
		if (*i == add_type) {
			already_present = true;
			break;
		}
	}
	if (!already_present) {
		rrtype_dynarray_add(arr, &add_type);
	}
}

static int rrtypelist_callback(zone_node_t *node, void *data)
{
	rrtypelist_ctx_t *ctx = data;
	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		rrtypelist_add(ctx->arr, rrset.type);
		*ctx->counter += rrset.rrs.count;
	}
	return KNOT_EOK;
}

static void print_changeset_debugmode(const changeset_t *chs)
{
	// detect all types
	rrtype_dynarray_t types = { 0 };
	size_t count_minus = 1, count_plus = 1; // 1 for SOA which is always present but not iterated
	rrtypelist_ctx_t ctx_minus = { &types, &count_minus }, ctx_plus = { &types, &count_plus };
	(void)zone_contents_apply(chs->remove, rrtypelist_callback, &ctx_minus);
	(void)zone_contents_nsec3_apply(chs->remove, rrtypelist_callback, &ctx_minus);
	(void)zone_contents_apply(chs->add, rrtypelist_callback, &ctx_plus);
	(void)zone_contents_nsec3_apply(chs->add, rrtypelist_callback, &ctx_plus);

	if (chs->soa_from == NULL) {
		printf("Zone-in-journal %u  +++: %zu\t size: %zu\t", knot_soa_serial(chs->soa_to->rrs.rdata),
		       count_plus, changeset_serialized_size(chs));
	} else {
		printf("%u -> %u  ---: %zu\t  +++: %zu\t size: %zu\t", knot_soa_serial(chs->soa_from->rrs.rdata),
		       knot_soa_serial(chs->soa_to->rrs.rdata), count_minus, count_plus, changeset_serialized_size(chs));
	}

	char temp[100];
	knot_dynarray_foreach(rrtype, uint16_t, i, types) {
		(void)knot_rrtype_to_string(*i, temp, sizeof(temp));
		printf(" %s", temp);
	}
	printf("\n");
}

static int count_changeset_cb(_unused_ bool special, const changeset_t *ch, void *ctx)
{
	print_params_t *params = ctx;
	if (ch != NULL) {
		params->counter++;
	}
	return KNOT_EOK;
}

static int print_changeset_cb(bool special, const changeset_t *ch, void *ctx)
{
	print_params_t *params = ctx;
	if (ch != NULL && params->counter++ >= params->limit) {
		if (params->debug) {
			print_changeset_debugmode(ch);
			params->changes++;
		} else {
			print_changeset(ch, params);
		}
		if (special && params->debug) {
			printf("---------------------------------------------\n");
		}
	}
	return KNOT_EOK;
}

int print_journal(char *path, knot_dname_t *name, print_params_t *params)
{
	knot_lmdb_db_t jdb = { 0 };
	zone_journal_t j = { &jdb, name };
	bool exists;
	uint64_t occupied, occupied_all;

	knot_lmdb_init(&jdb, path, 0, journal_env_flags(JOURNAL_MODE_ROBUST, true), NULL);
	int ret = knot_lmdb_exists(&jdb);
	if (ret == KNOT_EOK) {
		ret = knot_lmdb_open(&jdb);
	}
	if (ret != KNOT_EOK) {
		knot_lmdb_deinit(&jdb);
		return ret;
	}

	ret = journal_info(j, &exists, NULL, NULL, NULL, NULL, NULL, &occupied, &occupied_all);
	if (ret != KNOT_EOK || !exists) {
		ERR2("zone not exists in the journal DB %s", path);
		knot_lmdb_deinit(&jdb);
		return ret == KNOT_EOK ? KNOT_ENOENT : ret;
	}

	if (params->check) {
		ret = journal_sem_check(j);
		if (ret > 0) {
			ERR2("semantic check failed with code %d", ret);
		} else if (ret != KNOT_EOK) {
			ERR2("semantic check failed (%s)", knot_strerror(ret));
		}
	}

	if (params->limit >= 0 && ret == KNOT_EOK) {
		if (params->from_serial) {
			ret = journal_walk_from(j, params->serial, count_changeset_cb, params);
		} else {
			ret = journal_walk(j, count_changeset_cb, params);
		}
	}
	if (ret == KNOT_EOK) {
		if (params->limit < 0 || params->counter <= params->limit) {
			params->limit = 0;
		} else {
			params->limit = params->counter - params->limit;
		}
		params->counter = 0;
		if (params->from_serial) {
			ret = journal_walk_from(j, params->serial, print_changeset_cb, params);
		} else {
			ret = journal_walk(j, print_changeset_cb, params);
		}
	}

	if (params->debug && ret == KNOT_EOK) {
		printf("Total number of changesets:  %zu\n", params->changes);
		printf("Occupied this zone (approx): %"PRIu64" KiB\n", occupied / 1024);
		printf("Occupied all zones together: %"PRIu64" KiB\n", occupied_all / 1024);
	}

	knot_lmdb_deinit(&jdb);
	return ret;
}

static int add_zone_to_list(const knot_dname_t *zone, void *list)
{
	knot_dname_t *copy = knot_dname_copy(zone, NULL);
	if (copy == NULL) {
		return KNOT_ENOMEM;
	}
	return ptrlist_add(list, copy, NULL) == NULL ? KNOT_ENOMEM : KNOT_EOK;
}

static int list_zone(const knot_dname_t *zone, bool detailed, knot_lmdb_db_t *jdb, uint64_t *occupied_all)
{
	knot_dname_txt_storage_t zone_str;
	if (knot_dname_to_str(zone_str, zone, sizeof(zone_str)) == NULL) {
		return KNOT_EINVAL;
	}

	if (detailed) {
		zone_journal_t j = { jdb, zone };
		bool exists;
		uint64_t occupied;

		int ret = journal_info(j, &exists, NULL, NULL, NULL, NULL, NULL, &occupied, occupied_all);
		if (ret != KNOT_EOK) {
			return ret;
		}
		assert(exists);
		printf("%s \t%"PRIu64" KiB\n", zone_str, occupied / 1024);
	} else {
		printf("%s\n", zone_str);
	}
	return KNOT_EOK;
}

int list_zones(char *path, bool detailed)
{
	knot_lmdb_db_t jdb = { 0 };
	knot_lmdb_init(&jdb, path, 0, journal_env_flags(JOURNAL_MODE_ROBUST, true), NULL);

	list_t zones;
	init_list(&zones);
	ptrnode_t *zone;
	uint64_t occupied_all = 0;

	int ret = journals_walk(&jdb, add_zone_to_list, &zones);
	WALK_LIST(zone, zones) {
		if (ret != KNOT_EOK) {
			break;
		}
		ret = list_zone(zone->d, detailed, &jdb, &occupied_all);
	}

	knot_lmdb_deinit(&jdb);
	ptrlist_deep_free(&zones, NULL);

	if (detailed && ret == KNOT_EOK) {
		printf("Occupied all zones together: %"PRIu64" KiB\n", occupied_all / 1024);
	}
	return ret;
}

int main(int argc, char *argv[])
{
	bool justlist = false;

	print_params_t params = {
		.debug = false,
		.color = isatty(STDOUT_FILENO),
		.check = false,
		.limit = -1,
		.from_serial = false,
	};

	struct option opts[] = {
		{ "config",    required_argument, NULL, 'c' },
		{ "confdb",    required_argument, NULL, 'C' },
		{ "dir",       required_argument, NULL, 'D' },
		{ "limit",     required_argument, NULL, 'l' },
		{ "serial",    required_argument, NULL, 's' },
		{ "zone-list", no_argument,       NULL, 'z' },
		{ "check",     no_argument,       NULL, 'H' },
		{ "debug",     no_argument,       NULL, 'd' },
		{ "no-color",  no_argument,       NULL, 'n' },
		{ "mono",      no_argument,       NULL, 'x' },
		{ "color",     no_argument,       NULL, 'X' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "c:C:D:l:s:zHdnxXhV", opts, NULL)) != -1) {
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
			if (util_conf_init_justdb("journal-db", optarg) != KNOT_EOK) {
				goto failure;
			}
			break;
		case 'l':
			if (str_to_int(optarg, &params.limit, 0, INT_MAX) != KNOT_EOK) {
				print_help();
				goto failure;
			}
			break;
		case 's':
			if (str_to_u32(optarg, &params.serial) != KNOT_EOK) {
				print_help();
				goto failure;
			}
			params.from_serial = true;
			break;
		case 'z':
			justlist = true;
			break;
		case 'H':
			params.check = true;
			break;
		case 'd':
			params.debug = true;
			break;
		case 'n':
		case 'x':
			params.color = false;
			break;
		case 'X':
			params.color = true;
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

	// Backward compatibility.
	if ((justlist && (argc - optind > 0)) || (!justlist && (argc - optind > 1))) {
		WARN2("obsolete parameter specified");
		if (util_conf_init_justdb("journal-db", argv[optind]) != KNOT_EOK) {
			goto failure;
		}
		optind++;
	}

	if (util_conf_init_default(true) != KNOT_EOK) {
		goto failure;
	}

	char *db = conf_db(conf(), C_JOURNAL_DB);

	if (justlist) {
		int ret = list_zones(db, params.debug);
		free(db);
		switch (ret) {
		case KNOT_ENOENT:
			INFO2("No zones in journal DB");
			// FALLTHROUGH
		case KNOT_EOK:
			goto success;
		case KNOT_ENODB:
			ERR2("the journal DB does not exist");
			goto failure;
		case KNOT_EMALF:
			ERR2("the journal DB is broken");
			goto failure;
		default:
			ERR2("failed to load zone list (%s)", knot_strerror(ret));
			goto failure;
		}
	} else {
		if (argc - optind != 1) {
			print_help();
			free(db);
			goto failure;
		}
		knot_dname_t *name = knot_dname_from_str_alloc(argv[optind]);
		knot_dname_to_lower(name);

		int ret = print_journal(db, name, &params);
		free(name);
		free(db);
		switch (ret) {
		case KNOT_ENOENT:
			if (params.from_serial) {
				INFO2("The journal is empty or the serial not present");
			} else {
				INFO2("The journal is empty");
			}
			break;
		case KNOT_ENODB:
			ERR2("the journal DB does not exist");
			goto failure;
		case KNOT_EOUTOFZONE:
			ERR2("the journal DB does not contain the specified zone");
			goto failure;
		case KNOT_EOK:
			break;
		default:
			ERR2("failed to load changesets (%s)", knot_strerror(ret));
			goto failure;
		}
	}

success:
	util_conf_deinit();
	return EXIT_SUCCESS;
failure:
	util_conf_deinit();
	return EXIT_FAILURE;
}
