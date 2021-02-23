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
#include <string.h>

#include "knot/catalog/catalog_db.h"
#include "utils/common/params.h"

#define PROGRAM_NAME	"kcatalogprint"

static void print_help(void)
{
	printf("Usage: %s [parameters] <catalog_dir>\n"
	       "\n"
	       "Parameters:\n"
	       " -h, --help         Print the program help.\n"
	       " -V, --version      Print the program version.\n",
	       PROGRAM_NAME);
}

int main(int argc, char *argv[])
{
	struct option options[] = {
		{ "help",    no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "hV", options, NULL)) != -1) {
		switch (opt) {
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

	if (argc != 2) {
		print_help();
		return EXIT_FAILURE;
	}

	catalog_t c = { { 0 } };

	catalog_init(&c, argv[1], 0); // mapsize grows automatically
	catalog_print(&c);
	if (catalog_deinit(&c) != KNOT_EOK) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
