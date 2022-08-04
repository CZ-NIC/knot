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
#include "utils/common/msg.h"
#include "utils/common/params.h"
#include "utils/common/util_conf.h"

#define PROGRAM_NAME	"kcatalogprint"

static knot_dname_t *filter_member = NULL;
static knot_dname_t *filter_catalog = NULL;

static void print_help(void)
{
	printf("Usage: %s [-c | -C | -D <path>] [parameters]\n"
	       "\n"
	       "Parameters:\n"
	       " -c, --config <file>   Path to a textual configuration file.\n"
	       "                        (default %s)\n"
	       " -C, --confdb <dir>    Path to a configuration database directory.\n"
	       "                        (default %s)\n"
	       " -D, --dir <path>      Path to a catalog database directory, use default\n"
	       "                       configuration.\n"
	       " -a, --catalog <name>  Filter the output by catalog zone name.\n"
	       " -m, --member <name>   Filter the output by member zone name.\n"
	       " -h, --help            Print the program help.\n"
	       " -V, --version         Print the program version.\n",
	       PROGRAM_NAME, CONF_DEFAULT_FILE, CONF_DEFAULT_DBDIR);
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
			ERR2("failed to print catalog (%s)", knot_strerror(ret));
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
	struct option opts[] = {
		{ "config",  required_argument, NULL, 'c' },
		{ "confdb",  required_argument, NULL, 'C' },
		{ "dir",     required_argument, NULL, 'D' },
		{ "catalog", required_argument, NULL, 'a' },
		{ "member",  required_argument, NULL, 'm' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "version", no_argument,       NULL, 'V' },
		{ NULL }
	};

	int opt = 0;
	while ((opt = getopt_long(argc, argv, "c:C:D:a:m:hV", opts, NULL)) != -1) {
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
			if (util_conf_init_justdb("catalog-db", optarg) != KNOT_EOK) {
				goto failure;
			}
			break;
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
	if (argc - optind > 0) {
		WARN2("obsolete parameter specified");
		if (util_conf_init_justdb("catalog-db", argv[optind]) != KNOT_EOK) {
			goto failure;
		}
		optind++;
	}

	if (util_conf_init_default(true) != KNOT_EOK) {
		goto failure;
	}

	catalog_t c = { { 0 } };

	char *db = conf_db(conf(), C_CATALOG_DB);
	catalog_init(&c, db, 0); // mapsize grows automatically
	free(db);
	catalog_print(&c);
	catalog_deinit(&c);

success:
	params_cleanup();
	util_conf_deinit();
	return EXIT_SUCCESS;
failure:
	params_cleanup();
	util_conf_deinit();
	return EXIT_FAILURE;
}
