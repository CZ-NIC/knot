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

#include <stdlib.h>
#include <string.h>

#include "knot/zone/catalog.h"
#include "utils/common/exec.h"

#define PROGRAM_NAME	"kcatalogprint"

static void print_help(void)
{
	printf("Usage: %s [parameter] <journal_dir>\n"
	       "\n"
	       "Parameters:\n"
	       " -h, --help         Print the program help.\n"
	       " -V, --version      Print the program version.\n",
	       PROGRAM_NAME);
}

int main(int argc, char *argv[])
{
	if (argc > 1 && strcmp(argv[1], "-V") == 0) {
		print_version(PROGRAM_NAME);
		return 0;
	}
	if (argc <= 1 || argv[1][0] == '-') {
		print_help();
		return 1;
	}
	catalog_t c;
	memset(&c, 0, sizeof(c));
	catalog_init(&c, argv[1], 0); // mapsize grows automatically
	catalog_update_print("Catalog:", &c, NULL);
	return catalog_deinit(&c) == KNOT_EOK ? 0 : 1;
}
