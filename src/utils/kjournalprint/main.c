/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>
#include <getopt.h>
#include <sys/stat.h>

#include "libknot/libknot.h"
#include "knot/journal/journal_basic.h"
#include "knot/journal/journal_metadata.h"
#include "knot/journal/journal_read.h"
#include "knot/zone/zone-dump.h"
#include "utils/common/exec.h"
#include "contrib/dynarray.h"
#include "contrib/strtonum.h"
#include "contrib/string.h"

#define PROGRAM_NAME	"kjournalprint"

#define RED		"\x1B[31m"
#define GRN		"\x1B[32m"
#define YLW		"\x1B[93m"
#define RESET		"\x1B[0m"

static void print_help(void)
{
	printf("Usage: %s [parameter] <journal_db> <zone_name>\n"
	       "\n"
	       "Parameters:\n"
	       " -l, --limit <num>  Read only <num> newest changes.\n"
	       " -n, --no-color     Get output without terminal coloring.\n"
	       " -z, --zone-list    Instead of reading jurnal, display the list\n"
	       "                    of zones in the DB (<zone_name> not needed).\n"
	       " -d, --debug        Debug mode output.\n"
	       " -h, --help         Print the program help.\n"
	       " -V, --version      Print the program version.\n",
	       PROGRAM_NAME);
}

static void print_changeset(const changeset_t *chs, bool color)
{
	printf(color ? YLW : "");
	if (chs->soa_from == NULL) {
		printf(";; Zone-in-journal, serial: %u\n",
		       knot_soa_serial(chs->soa_to->rrs.rdata));
	} else {
		printf(";; Changes between zone versions: %u -> %u\n",
		       knot_soa_serial(chs->soa_from->rrs.rdata),
		       knot_soa_serial(chs->soa_to->rrs.rdata));
	}
	changeset_print(chs, stdout, color);
}

dynarray_declare(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC, 100)
dynarray_define(rrtype, uint16_t, DYNARRAY_VISIBILITY_STATIC)

typedef struct {
	rrtype_dynarray_t *arr;
	size_t *counter;
} rrtypelist_ctx_t;

static void rrtypelist_add(rrtype_dynarray_t *arr, uint16_t add_type)
{
	bool already_present = false;
	dynarray_foreach(rrtype, uint16_t, i, *arr) {
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
	dynarray_foreach(rrtype, uint16_t, i, types) {
		(void)knot_rrtype_to_string(*i, temp, sizeof(temp));
		printf(" %s", temp);
	}
	printf("\n");
}

static int print_changeset_cb(bool special, const changeset_t *ch, void *ctx)
{
	bool *parm = ctx;
	if (ch != NULL) {
		if (parm[0]) {
			print_changeset_debugmode(ch);
		} else {
			print_changeset(ch, parm[1]);
		}
		if (special && parm[0]) {
			printf("---------------------------------------------\n");
		}
	}
	return KNOT_EOK;
}

int print_journal(char *path, knot_dname_t *name, uint32_t limit, bool color, bool debugmode, bool do_check)
{
	knot_lmdb_db_t jdb = { 0 };
	zone_journal_t j = { &jdb, name };
	bool exists;
	uint64_t occupied, occupied_all;

	knot_lmdb_init(&jdb, path, 0, journal_env_flags(JOURNAL_MODE_ROBUST), NULL);
	int ret = knot_lmdb_open(&jdb);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = journal_info(j, &exists, NULL, NULL, NULL, NULL, &occupied, &occupied_all);
	if (ret != KNOT_EOK || !exists) {
		fprintf(stderr, "This zone does not exist in DB %s\n", path);
		knot_lmdb_deinit(&jdb);
		return ret == KNOT_EOK ? KNOT_ENOENT : ret;
	}

	if (do_check) {
		ret = journal_sem_check(j);
		if (ret > 0) {
			fprintf(stderr, "Journal semantic check error: %d\n", ret);
		} else if (ret != KNOT_EOK) {
			fprintf(stderr, "Journal semnatic check failed (%s).\n", knot_strerror(ret));
		}
	}

	bool parm[2] = { debugmode, color };
	ret = journal_walk(j, print_changeset_cb, (void *)parm);

	if (debugmode && ret == KNOT_EOK) {
		printf("Occupied this zone (approx): %"PRIu64" KiB\n", occupied / 1024);
		printf("Occupied all zones together: %"PRIu64" KiB\n", occupied_all / 1024);
	}

	knot_lmdb_deinit(&jdb);
	return ret;
}

static int list_zone(const knot_dname_t *zone, void *ctx)
{
	char zone_str[KNOT_DNAME_TXT_MAXLEN + 1];
	(void)ctx;
	printf("%s\n", knot_dname_to_str(zone_str, zone, sizeof(zone_str)));
	return KNOT_EOK;
}

int list_zones(char *path)
{
	knot_lmdb_db_t jdb = { 0 };
	knot_lmdb_init(&jdb, path, 0, journal_env_flags(JOURNAL_MODE_ROBUST), NULL);

	int ret = journals_walk(&jdb, list_zone, NULL);
	knot_lmdb_deinit(&jdb);
	return ret;
}

int main(int argc, char *argv[])
{
	uint32_t limit = 0;
	bool color = true, justlist = false, debugmode = false, docheck = false;

	struct option opts[] = {
		{ "limit",     required_argument, NULL, 'l' },
		{ "no-color",  no_argument,       NULL, 'n' },
		{ "zone-list", no_argument,       NULL, 'z' },
		{ "debug",     no_argument,       NULL, 'd' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "l:nzcdhV", opts, NULL)) != -1) {
		switch (opt) {
		case 'l':
			if (str_to_u32(optarg, &limit) != KNOT_EOK) {
				print_help();
				return EXIT_FAILURE;
			}
			break;
		case 'n':
			color = false;
			break;
		case 'z':
			justlist = true;
			break;
		case 'c':
			docheck = true;
			break;
		case 'd':
			debugmode = true;
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

	char *db = NULL;
	knot_dname_t *name = NULL;

	switch (argc - optind) {
	case 2:
		name = knot_dname_from_str_alloc(argv[optind + 1]);
		knot_dname_to_lower(name);
		// FALLTHROUGH
	case 1:
		db = argv[optind];
		break;
	default:
		print_help();
		return EXIT_FAILURE;
	}

	if (db == NULL) {
		fprintf(stderr, "Journal DB path not specified\n");
		return EXIT_FAILURE;
	}

	if (justlist) {
		int ret = list_zones(db);
		switch (ret) {
		case KNOT_ENOENT:
			printf("No zones in journal DB\n");
			// FALLTHROUGH
		case KNOT_EOK:
			return EXIT_SUCCESS;
		case KNOT_EMALF:
			fprintf(stderr, "The journal DB is broken\n");
			return EXIT_FAILURE;
		default:
			fprintf(stderr, "Failed to load zone list (%s)\n", knot_strerror(ret));
			return EXIT_FAILURE;
		}
	}

	if (name == NULL) {
		fprintf(stderr, "Zone not specified\n");
		return EXIT_FAILURE;
	}

	int ret = print_journal(db, name, limit, color, debugmode, docheck);
	free(name);

	switch (ret) {
	case KNOT_ENOENT:
		printf("The journal is empty\n");
		break;
	case KNOT_EOUTOFZONE:
		fprintf(stderr, "The specified journal DB does not contain the specified zone\n");
		return EXIT_FAILURE;
	case KNOT_EOK:
		break;
	default:
		fprintf(stderr, "Failed to load changesets (%s)\n", knot_strerror(ret));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
