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

#include "knot/conf/conf.c"
#include "test_conf.h"

#define ZONE1	"0/25.2.0.192.in-addr.arpa."
#define ZONE2	"."
#define ZONE3	"x."
#define ZONE4	"abc.ab.a."

static void check_name(const char *zone, const char *name, const char *ref)
{
	knot_dname_t *z = knot_dname_from_str_alloc(zone);

	char *file = get_filename(NULL, NULL, z, name);
	ok(file != NULL, "Get zonefile path for %s", zone);
	if (file != NULL) {
		ok(strcmp(file, ref) == 0, "Zonefile path compare %s", name);
		free(file);
	}

	knot_dname_free(&z, NULL);
}

static void check_name_err(const char *zone, const char *name)
{
	knot_dname_t *z = knot_dname_from_str_alloc(zone);

	ok(get_filename(NULL, NULL, z, name) == NULL, "Invalid name %s", name);

	knot_dname_free(&z, NULL);
}

static void test_get_filename(void)
{
	// Char formatter.
	char *zone = "abc.def.gh";
	check_name(zone, "/%c[0]", "/a");
	check_name(zone, "/%c[9]", "/h");
	check_name(zone, "/%c[3]", "/.");
	check_name(zone, "/%c[0-1]", "/ab");
	check_name(zone, "/%c[1-1]", "/b");
	check_name(zone, "/%c[1-3]", "/bc.");
	check_name(zone, "/%c[1-4]", "/bc.d");
	check_name_err(zone, "/%c");
	check_name_err(zone, "/%cx");
	check_name_err(zone, "/%c[a]");
	check_name_err(zone, "/%c[:]");
	check_name_err(zone, "/%c[/]");
	check_name_err(zone, "/%c[12]");
	check_name_err(zone, "/%c[");
	check_name_err(zone, "/%c[1");
	check_name_err(zone, "/%c[1-");
	check_name_err(zone, "/%c[1-2");
	check_name_err(zone, "/%c[1-b]");
	check_name_err(zone, "/%c[9-0]");

	zone = "abcd";
	check_name(zone, "/%c[2-9]", "/cd");
	check_name(zone, "/%c[3]", "/d");
	check_name(zone, "/%c[4]", "/");

	zone = ".";
	check_name(zone, "/%c[0]", "/");
	check_name(zone, "/%c[1]", "/");

	// Label formatter.
	zone = "abc.def.gh";
	check_name(zone, "/%l[0]", "/gh");
	check_name(zone, "/%l[1]", "/def");
	check_name(zone, "/%l[2]", "/abc");
	check_name(zone, "/%l[3]", "/");
	check_name(zone, "/%l[0]-%l[1]-%l[2]", "/gh-def-abc");
	check_name_err(zone, "/%l[0-1]");

	zone = ".";
	check_name(zone, "/%l[0]", "/.");
	check_name(zone, "/%l[1]", "/");
}

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
	knot_dname_t *zone4 = knot_dname_from_str_alloc(ZONE4);
	ok(zone4 != NULL, "create dname "ZONE4);

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
		"    file: /%s\n"
		"  - domain: "ZONE4"\n";

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

	// Absolute path without formatters - root zone.
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

	// Default zonefile path.
	file = conf_zonefile(conf(), zone4);
	ok(file != NULL, "Get zonefile path for "ZONE4);
	if (file != NULL) {
		ok(strcmp(file, "/tmp/"ZONE4"zone") == 0,
		          "Zonefile path compare for "ZONE4);
		free(file);
	}

	conf_free(conf());
	knot_dname_free(&zone1, NULL);
	knot_dname_free(&zone2, NULL);
	knot_dname_free(&zone3, NULL);
	knot_dname_free(&zone4, NULL);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	diag("get_filename");
	test_get_filename();

	diag("conf_zonefile");
	test_conf_zonefile();

	return 0;
}
