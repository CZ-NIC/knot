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
#include <string.h>

#include "knot/catalog/catalog_db.h"
#include "utils/common/params.h"

#define PROGRAM_NAME	"kcatalogprint"

static knot_dname_t *filter_member = NULL;
static knot_dname_t *filter_catalog = NULL;

static void print_help(void)
{
	printf("Usage: %s [parameters] <catalog_dir>\n"
	       "\n"
	       "Parameters:\n"
	       " -a, --catalog <name>  Filter the output by catalog zone name.\n"
	       " -m, --member <name>   Filter the output by member zone name.\n"
	       " -h, --help            Print the program help.\n"
	       " -V, --version         Print the program version.\n",
	       PROGRAM_NAME);
}

static void print_dname(const knot_dname_t *d)
{
	knot_dname_txt_storage_t tmp;
	knot_dname_to_str(tmp, d, sizeof(tmp));
	printf("%s  ", tmp);
}

static int catalog_print_cb(const knot_dname_t *mem, const knot_dname_t *ow,
                            const knot_dname_t *cz, const char *group, void *ctx)
{
	if (filter_catalog != NULL && !knot_dname_is_equal(filter_catalog, cz)) {
		return KNOT_EOK;
	}
	print_dname(mem);
	print_dname(ow);
	print_dname(cz);
	printf("%s\n", group);
	(*(ssize_t *)ctx)++;
	return KNOT_EOK;
}

static void catalog_print(catalog_t *cat)
{
	ssize_t total = 0;

	printf(";; <member zone> <record owner> <catalog zone> <group>\n");

	if (cat != NULL) {
		int ret = catalog_open(cat);
		if (ret == KNOT_EOK) {
			ret = catalog_apply(cat, filter_member, catalog_print_cb, &total, false);
		}
		if (ret != KNOT_EOK) {
			printf("Catalog print failed (%s)\n", knot_strerror(ret));
			return;
		}
	}

	printf("Total records: %zd\n", total);
}

static void params_cleanup(void)
{
	free(filter_member);
	free(filter_catalog);
}

int main(int argc, char *argv[])
{
	struct option options[] = {
		{ "catalog", required_argument, NULL, 'a' },
		{ "member",  required_argument, NULL, 'm' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "a:m:hV", options, NULL)) != -1) {
		switch (opt) {
		case 'a':
			free(filter_catalog);
			filter_catalog = knot_dname_from_str_alloc(optarg);
			knot_dname_to_lower(filter_catalog);
			break;
		case 'm':
			free(filter_member);
			filter_member = knot_dname_from_str_alloc(optarg);
			knot_dname_to_lower(filter_member);
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

	if (argc - optind != 1) {
		print_help();
		return EXIT_FAILURE;
	}

	catalog_t c = { { 0 } };

	catalog_init(&c, argv[optind], 0); // mapsize grows automatically
	catalog_print(&c);
	params_cleanup();
	if (catalog_deinit(&c) != KNOT_EOK) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
