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

#include <tap/basic.h>

#include "knot/conf/conf.c"
#include "test_conf.h"

#define ZONE_ARPA	"0/25.2.0.192.in-addr.arpa."
#define ZONE_ROOT	"."
#define ZONE_1LABEL	"x."
#define ZONE_3LABEL	"abc.ab.a."
#define ZONE_UNKNOWN	"unknown."

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
	// Name formatter.
	char *zone = "abc";
	check_name(zone, "/%s", "/abc");

	zone = ".";
	check_name(zone, "/%s", "/");

	// Char formatter.
	zone = "abc.def.g";
	check_name(zone, "/%c[0]", "/a");
	check_name(zone, "/%c[3]", "/.");
	check_name(zone, "/%c[8]", "/g");
	check_name(zone, "/%c[9]", "/.");
	check_name(zone, "/%c[0-1]", "/ab");
	check_name(zone, "/%c[1-1]", "/b");
	check_name(zone, "/%c[1-3]", "/bc.");
	check_name(zone, "/%c[1-4]", "/bc.d");
	check_name_err(zone, "/%c");
	check_name_err(zone, "/%cx");
	check_name_err(zone, "/%c[a]");
	check_name_err(zone, "/%c[:]");
	check_name_err(zone, "/%c[/]");
	check_name_err(zone, "/%c[10]");
	check_name_err(zone, "/%c[");
	check_name_err(zone, "/%c[1");
	check_name_err(zone, "/%c[1-");
	check_name_err(zone, "/%c[1-2");
	check_name_err(zone, "/%c[1-b]");
	check_name_err(zone, "/%c[8-0]");

	zone = "abcd";
	check_name(zone, "/%c[2-9]", "/cd.");
	check_name(zone, "/%c[3]", "/d");
	check_name(zone, "/%c[4]", "/.");

	zone = ".";
	check_name(zone, "/%c[0]", "/.");
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
	check_name(zone, "/%l[0]", "/");
	check_name(zone, "/%l[1]", "/");
}

static void test_conf_zonefile(void)
{
	int ret;
	char *file;

	knot_dname_t *zone_arpa = knot_dname_from_str_alloc(ZONE_ARPA);
	ok(zone_arpa != NULL, "create dname "ZONE_ARPA);
	knot_dname_t *zone_root = knot_dname_from_str_alloc(ZONE_ROOT);
	ok(zone_root != NULL, "create dname "ZONE_ROOT);
	knot_dname_t *zone_1label = knot_dname_from_str_alloc(ZONE_1LABEL);
	ok(zone_1label != NULL, "create dname "ZONE_1LABEL);
	knot_dname_t *zone_3label = knot_dname_from_str_alloc(ZONE_3LABEL);
	ok(zone_3label != NULL, "create dname "ZONE_3LABEL);
	knot_dname_t *zone_unknown = knot_dname_from_str_alloc(ZONE_UNKNOWN);
	ok(zone_unknown != NULL, "create dname "ZONE_UNKNOWN);

	const char *conf_str =
		"template:\n"
		"  - id: default\n"
		"    storage: /tmp\n"
		"\n"
		"zone:\n"
		"  - domain: "ZONE_ARPA"\n"
		"    file: dir/a%%b/%s.suffix/%a\n"
		"  - domain: "ZONE_ROOT"\n"
		"    file: /%s\n"
		"  - domain: "ZONE_1LABEL"\n"
		"    file: /%s\n"
		"  - domain: "ZONE_3LABEL"\n";

	ret = test_conf(conf_str, NULL);
	ok(ret == KNOT_EOK, "Prepare configuration");

	// Relative path with formatters.
	file = conf_zonefile(conf(), zone_arpa);
	ok(file != NULL, "Get zonefile path for "ZONE_ARPA);
	if (file != NULL) {
		ok(strcmp(file, "/tmp/dir/a%b/0_25.2.0.192.in-addr.arpa.suffix/") == 0,
		          "Zonefile path compare for "ZONE_ARPA);
		free(file);
	}

	// Absolute path without formatters - root zone.
	file = conf_zonefile(conf(), zone_root);
	ok(file != NULL, "Get zonefile path for "ZONE_ROOT);
	if (file != NULL) {
		ok(strcmp(file, "/") == 0,
		          "Zonefile path compare for "ZONE_ROOT);
		free(file);
	}

	// Absolute path without formatters - non-root zone.
	file = conf_zonefile(conf(), zone_1label);
	ok(file != NULL, "Get zonefile path for "ZONE_1LABEL);
	if (file != NULL) {
		ok(strcmp(file, "/x") == 0,
		          "Zonefile path compare for "ZONE_1LABEL);
		free(file);
	}

	// Default zonefile path.
	file = conf_zonefile(conf(), zone_3label);
	ok(file != NULL, "Get zonefile path for "ZONE_3LABEL);
	if (file != NULL) {
		ok(strcmp(file, "/tmp/abc.ab.a.zone") == 0,
		          "Zonefile path compare for "ZONE_3LABEL);
		free(file);
	}

	// Unknown zone zonefile path.
	file = conf_zonefile(conf(), zone_unknown);
	ok(file != NULL, "Get zonefile path for "ZONE_UNKNOWN);
	if (file != NULL) {
		ok(strcmp(file, "/tmp/unknown.zone") == 0,
		          "Zonefile path compare for "ZONE_UNKNOWN);
		free(file);
	}

	conf_free(conf());
	knot_dname_free(&zone_arpa, NULL);
	knot_dname_free(&zone_root, NULL);
	knot_dname_free(&zone_1label, NULL);
	knot_dname_free(&zone_3label, NULL);
	knot_dname_free(&zone_unknown, NULL);
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
