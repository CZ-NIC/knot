/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <getopt.h>

#include "libknot/libknot.h"
#include "knot/journal/journal.h"
#include "knot/zone/zone-dump.h"
#include "utils/common/exec.h"
#include "contrib/strtonum.h"

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
	       "                    of zones in the DB (<zone_name> not needed).\n",
	       PROGRAM_NAME);
}

static inline char *get_rrset(knot_rrset_t *rrset, char **buff, size_t *len)
{
	int ret = knot_rrset_txt_dump(rrset, buff, len, &KNOT_DUMP_STYLE_DEFAULT);
	return (ret > 0) ? *buff : "Corrupted or missing!\n";
}

int print_journal(char *path, knot_dname_t *name, uint32_t limit, bool color)
{
	list_t db;
	init_list(&db);

	size_t buflen = 8192;
	char *buff = malloc(buflen);
	if (buff == NULL) {
		return KNOT_ENOMEM;
	}

	journal_db_t *jdb = NULL;
	journal_t *j = journal_new();
	int ret;

	ret = journal_db_init(&jdb, path, 1);
	if (ret != KNOT_EOK) {
		journal_free(&j);
		free(buff);
		return ret;
	}

	if (!journal_exists(&jdb, name)) {
		fprintf(stderr, "This zone does not exist in DB %s\n", path);
		ret = KNOT_ENOENT;
	}

	if (ret == KNOT_EOK) {
		ret = journal_open(j, &jdb, name);
	}
	if (ret != KNOT_EOK) {
		journal_free(&j);
		journal_db_close(&jdb);
		free(buff);
		return ret;
	}

	bool is_empty;
	uint32_t serial_from, serial_to;
	journal_metadata_info(j, &is_empty, &serial_from, &serial_to);
	if (is_empty) {
		ret = KNOT_ENOENT;
		goto pj_finally;
	}

	ret = journal_load_bootstrap(j, &db);
	if (ret == KNOT_ENOENT) {
		ret = journal_load_changesets(j, &db, serial_from);
	}
	if (ret != KNOT_EOK) {
		goto pj_finally;
	}

	changeset_t *chs = NULL;

	size_t db_remains = list_size(&db);

	WALK_LIST(chs, db) {
		if (--db_remains >= limit && limit > 0) {
			continue;
		}

		printf(color ? YLW : "");
		if (chs->soa_from == NULL) {
			printf(";; Zone-in-journal, serial: %u\n",
			       knot_soa_serial(&chs->soa_to->rrs));

			printf(color ? GRN : "");
			printf("%s", get_rrset(chs->soa_to, &buff, &buflen));
			zone_dump_text(chs->add, stdout, false);
			printf(color ? RESET : "");
		} else {
			printf(";; Changes between zone versions: %u -> %u\n",
			       knot_soa_serial(&chs->soa_from->rrs),
			       knot_soa_serial(&chs->soa_to->rrs));

			printf(color ? RED : "");
			printf(";; Removed\n");
			printf("%s", get_rrset(chs->soa_from, &buff, &buflen));
			zone_dump_text(chs->remove, stdout, false);

			printf(color ? GRN : "");
			printf(";; Added\n");
			printf("%s", get_rrset(chs->soa_to, &buff, &buflen));
			zone_dump_text(chs->add, stdout, false);
			printf(color ? RESET : "");
		}
	}

	changesets_free(&db);

pj_finally:
	free(buff);
	journal_close(j);
	journal_free(&j);
	journal_db_close(&jdb);

	return ret;
}

int list_zones(char *path)
{
	journal_db_t *jdb = NULL;
	int ret = journal_db_init(&jdb, path, 1);
	if (ret != KNOT_EOK) {
		return ret;
	}

	list_t zones;
	init_list(&zones);
	ret = journal_db_list_zones(&jdb, &zones);
	if (ret == KNOT_EOK) {
		ptrnode_t *zn;
		WALK_LIST(zn, zones) {
			printf("%s\n", (char *)zn->d);
			free(zn->d);
		}
		ptrlist_free(&zones, NULL);
	}

	journal_db_close(&jdb);
	return ret;
}

int main(int argc, char *argv[])
{
	uint32_t limit = 0;
	bool color = true, justlist = false;

	struct option opts[] = {
		{ "limit",     required_argument, NULL, 'l' },
		{ "no-color",  no_argument,       NULL, 'n' },
		{ "zone-list", no_argument,       NULL, 'z' },
		{ "help",      no_argument,       NULL, 'h' },
		{ "version",   no_argument,       NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "l:nzhV", opts, NULL)) != -1) {
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

	int ret = print_journal(db, name, limit, color);
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
