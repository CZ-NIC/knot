/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "libknot/lookup.h"

const knot_lookup_t test_table[] = {
	{  0, "test item 0" },
	{ 10, "" },
	{  2, "test item 2" },
	{ -1, "test item -1" },
	{  0, NULL }
};

int main(int argc, char *argv[])
{
	plan(9);

	/* Lookup by ID. */
	const knot_lookup_t *found = knot_lookup_by_id(test_table, 3);
	ok(found == NULL, "lookup table: find by id - non-existent ID");

	found = knot_lookup_by_id(test_table, 2);
	ok(found && found->id == 2 && strcmp(found->name, "test item 2") == 0,
	   "lookup table: find by id - ID 2 (unordered IDs)");

	found = knot_lookup_by_id(NULL, 2);
	ok(found == NULL, "lookup table: find by id - table == NULL");

	/* Lookup by name. */
	found = knot_lookup_by_name(test_table, "test item 2");
	ok(found && found->id == 2 && strcmp(found->name, "test item 2") == 0,
	   "lookup table: find by name - existent");

	found = knot_lookup_by_name(test_table, "");
	ok(found && found->id == 10 && strcmp(found->name, "") == 0,
	   "lookup table: find by name - empty string");

	found = knot_lookup_by_name(test_table, NULL);
	ok(found == NULL, "lookup table: find by name - NULL name");

	found = knot_lookup_by_name(NULL, "test item 2");
	ok(found == NULL, "lookup table: find by name - NULL table");

	found = knot_lookup_by_name(NULL, NULL);
	ok(found == NULL, "lookup table: find by name - NULL table & NULL name");

	found = knot_lookup_by_name(test_table, "non existent name");
	ok(found == NULL, "lookup table: find by name - non-existent name");

	return 0;
}
