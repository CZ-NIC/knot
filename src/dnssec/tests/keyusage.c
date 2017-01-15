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
#include <tap/files.h>
#include <string.h>
#include <stdio.h>

#include "dnssec.h"

static void test_keyusage_empty(const char *json_file)
{
	diag("%s", __func__);

	dnssec_keyusage_t *k = dnssec_keyusage_new();

	ok(dnssec_keyusage_load(k, json_file)== DNSSEC_NOT_FOUND, "keyusage_load empty, no keyusage");

	ok(dnssec_list_is_empty(k), "List of records is empty.");

	ok(dnssec_keyusage_save(k, json_file) == DNSSEC_EOK , "keyusage_save empty");

	ok(dnssec_keyusage_load(k, json_file)== DNSSEC_EOK , "keyusage_load empty");

	ok(dnssec_list_is_empty(k), "List of records is empty.");

	dnssec_keyusage_free(k);
}

static void test_keyusage_basic(void)
{
	diag("%s", __func__);

	dnssec_keyusage_t *k = NULL;

	k = dnssec_keyusage_new();
	ok(dnssec_list_is_empty(k), "List of records is empty.");

	dnssec_keyusage_add(k, "prvni", "zona");

	ok(!dnssec_list_is_empty(k), "List of records is not empty.");
	// Check added key being used
	ok(dnssec_keyusage_is_used(k, "prvni"), "Key is used.");
	// Remove added key and check empty record
	dnssec_keyusage_remove(k, "prvni", "zona");
	ok(dnssec_list_is_empty(k), "List of records is empty.");
	ok(!dnssec_keyusage_is_used(k, "prvni"), "Key is not used.");
	// Check if key is used when one of zones is deleted
	dnssec_keyusage_add(k, "prvni", "zona");
	dnssec_keyusage_add(k, "prvni", "zona2");
	dnssec_keyusage_remove(k, "prvni", "zona");
	ok(dnssec_keyusage_is_used(k, "prvni"), "Key is used.");

	// Check if key is unused after deleting both zones
	dnssec_keyusage_remove(k, "prvni", "zona2");
	ok(!dnssec_keyusage_is_used(k, "prvni"), "Key is not used.");

	dnssec_keyusage_free(k);
}

static void test_keyusage_file(const char *json_file)
{
	dnssec_keyusage_t *k = NULL;
	k = dnssec_keyusage_new();
	dnssec_keyusage_add(k, "prvni", "zona");
	dnssec_keyusage_add(k, "prvni", "zona2");
	dnssec_keyusage_add(k, "druhy", "zona");

	ok(dnssec_keyusage_save(k, json_file) == DNSSEC_EOK , "kayusage_save");

	dnssec_keyusage_free(k);
	k = dnssec_keyusage_new();

	ok(!dnssec_keyusage_is_used(k, "prvni"), "Key is not used - freed succesfully.");
	ok(!dnssec_keyusage_is_used(k, "druhy"), "Key is not used - freed succesfully.");

	ok(dnssec_keyusage_load(k, json_file)== DNSSEC_EOK , "kayusage_load");

	ok(dnssec_keyusage_is_used(k, "prvni"), "Key is used - loaded succesfully.");
	ok(dnssec_keyusage_is_used(k, "druhy"), "Key is used - loaded succesfully.");

	dnssec_keyusage_free(k);
}

int main(void)
{
	plan_lazy();

	char *json_path = NULL, *json_file = NULL;

	json_path = test_mkdtemp();
	if (!json_path) {
		fprintf(stderr, "Failed to create teporary path.");
		return -1;
	}

	int r = asprintf(&json_file, "%s/keyusage.json", json_path);
	if (r == -1) {
		fprintf(stderr, "Failed to create teporary file path.");
		return -1;
	}

	test_keyusage_empty(json_file);
	test_keyusage_basic();
	test_keyusage_file(json_file);

	test_rm_rf(json_path);
	free(json_path);

	return 0;
}
