/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <tap/basic.h>

#include "kasp/dir/file.h"

struct test {
	const char *dir;
	const char *type;
	const char *name;
	const char *expected;
};

static const struct test TESTS[] = {
	{ "kasp",  "zone",   "example.com", "kasp/zone_example.com.json"    },
	{ "zo/ne", "zone",   "test@zone",   "zo/ne/zone_test\\x40zone.json" },
	{ "kasp",  "policy", "default",     "kasp/policy_default.json"      },
	{ NULL }
};

int main(int argc, char *argv[])
{
	plan_lazy();

	for (const struct test *t = TESTS; t->dir; t++) {
		char *file = file_from_entity(t->dir, t->type, t->name);
		is_string(t->expected, file, "file_from_entity(%s, %s, %s)",
					     t->dir, t->type, t->name);
		free(file);

		const char *basename = rindex(t->expected, '/');
		assert(basename);
		basename += 1;

		char *entity = file_to_entity(t->type, basename);
		is_string(t->name, entity, "file_to_entity(%s, %s)",
					   t->type, basename);
		free(entity);
	}

	return 0;
}
