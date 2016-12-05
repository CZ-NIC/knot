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
#include "knot/server/serialization.h"
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
	printf("Usage: %s [parameter] <journal> <zone_name>\n"
	       "\n"
	       "Parameters:\n"
	       " -n, --no-color       Get output without terminal coloring.\n"
	       " -l, --limit <Limit>  Read only x newest changes.\n",
	       PROGRAM_NAME);
}

static inline char *get_rrset(knot_rrset_t *rrset, char *buff, size_t len)
{
	int ret = knot_rrset_txt_dump(rrset, buff, len, &KNOT_DUMP_STYLE_DEFAULT);
	return (ret > 0) ? buff : "Corrupted or missing!\n";
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

	// Open journal for reading.
	journal_t *journal = NULL;
	int ret = journal_open(&journal, path, ~((size_t)0));
	if (ret != KNOT_EOK) {
		free(buff);
		return ret;
	}

	// Load changesets from journal.
	if (journal->qtail == journal->qhead) {
		journal_close(journal);
		free(buff);
		return KNOT_ENOENT;
	}

	size_t i = (limit && journal->qtail - limit) ?
	           journal->qtail - limit : journal->qhead;
	for (; i < journal->qtail; i = (i + 1) % journal->max_nodes) {
		// Skip invalid nodes.
		journal_node_t *n = journal->nodes + i;
		if (!(n->flags & JOURNAL_VALID)) {
			printf("%zu. node invalid\n", i);
			continue;
		}
		load_changeset(journal, n, name, &db);
	}

	// Unpack and print changsets.
	changeset_t *chs = NULL;
	for (chs = (void *)(db.head); (node_t *)((node_t *)chs)->next; chs = (void *)((node_t *) chs)->next) {
		ret = changesets_unpack(chs);
		if (ret != KNOT_EOK) {
			break;
		}

		printf(color ? YLW : "");
		printf(";; Changes between zone versions: %u -> %u\n",
		       knot_soa_serial(&chs->soa_from->rrs),
		       knot_soa_serial(&chs->soa_to->rrs));

		// Removed.
		printf(color ? RED : "");
		printf(";; Removed\n");
		printf("%s", get_rrset(chs->soa_from, buff, buflen));
		zone_dump_text(chs->remove, stdout, false);

		// Added.
		printf(color ? GRN : "");
		printf(";; Added\n");
		printf("%s", get_rrset(chs->soa_to, buff, buflen));
		zone_dump_text(chs->add, stdout, false);
		printf(color ? RESET : "");
	}

	free(buff);
	changesets_free(&db);
	journal_close(journal);

	return ret;
}

int main(int argc, char *argv[])
{
	uint32_t limit = 0;
	bool color = true;

	struct option opts[] = {
		{ "limit",    required_argument, NULL, 'l' },
		{ "no-color", no_argument,       NULL, 'n' },
		{ "help",     no_argument,       NULL, 'h' },
		{ "version",  no_argument,       NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "l:nhV", opts, NULL)) != -1) {
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
		fprintf(stderr, "Journal file not specified\n");
		return EXIT_FAILURE;
	}
	if (name == NULL) {
		fprintf(stderr, "Zone not specified\n");
		return EXIT_FAILURE;
	}

	int ret = print_journal(db, name, limit, color);
	free(name);

	switch (ret) {
	case KNOT_ENOENT:
		printf("The journal is empty.\n");
		break;
	case KNOT_EOUTOFZONE:
		fprintf(stderr, "The specified journal DB does not contain the specified zone.\n");
		return EXIT_FAILURE;
	case KNOT_EOK:
		break;
	default:
		fprintf(stderr, "Failed to load changesets (%s).\n", knot_strerror(ret));
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
