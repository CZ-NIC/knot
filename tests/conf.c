/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include "test_conf.h"

#define ZONE1	"0/25.2.0.192.in-addr.arpa."
#define ZONE2	"."
#define ZONE3	"x."

static void test_conf_zonefile(void)
{
	int ret;
	char *file;

	knot_dname_t *zone1 = knot_dname_from_str_alloc(ZONE1);
	ok(zone1 != NULL, "create dname "ZONE1);
	knot_dname_t *zone2 = knot_dname_from_str_alloc(ZONE2);
	ok(zone2 != NULL, "create dname "ZONE2);
	knot_dname_t *zone3 = knot_dname_from_str_alloc(ZONE3);
	ok(zone3 != NULL, "create dname "ZONE3);

	const char *conf_str =
		"template:\n"
		"  - id: default\n"
		"    storage: /tmp\n"
		"\n"
		"zone:\n"
		"  - domain: "ZONE1"\n"
		"    file: dir/a%%b/%s.suffix/%a\n"
		"  - domain: "ZONE2"\n"
		"    file: /%s\n"
		"  - domain: "ZONE3"\n"
		"    file: /%s\n";

	ret = test_conf(conf_str, NULL);
	ok(ret == KNOT_EOK, "Prepare configuration");

	// Relative path with formatters.
	file = conf_zonefile(conf(), zone1);
	ok(file != NULL, "Get zonefile path for "ZONE1);
	if (file != NULL) {
		ok(strcmp(file, "/tmp/dir/a%b/0_25.2.0.192.in-addr.arpa.suffix/") == 0,
		          "Zonefile path compare for "ZONE1);
		free(file);
	}

	// Absolute path without formatters.
	file = conf_zonefile(conf(), zone2);
	ok(file != NULL, "Get zonefile path for "ZONE2);
	if (file != NULL) {
		ok(strcmp(file, "/.") == 0,
		          "Zonefile path compare for "ZONE2);
		free(file);
	}

	// Absolute path without formatters.
	file = conf_zonefile(conf(), zone3);
	ok(file != NULL, "Get zonefile path for "ZONE3);
	if (file != NULL) {
		ok(strcmp(file, "/x") == 0,
		          "Zonefile path compare for "ZONE3);
		free(file);
	}

	conf_free(conf(), false);
	knot_dname_free(&zone1, NULL);
	knot_dname_free(&zone2, NULL);
	knot_dname_free(&zone3, NULL);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	test_conf_zonefile();

	return 0;
}
