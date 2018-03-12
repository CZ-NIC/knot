/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "keyid.h"

static void test_keyid_is_valid_run(const char *param, bool should_ok)
{
	ok(dnssec_keyid_is_valid(param) == should_ok,
	   "dnssec_keyid_is_valid(\"%s\")", param);
}

static void test_keyid_is_valid(void)
{
	test_keyid_is_valid_run(NULL, false);
	test_keyid_is_valid_run("3e90c5cb1fad5f8512da2028fda3808e749d3bf", false);
	test_keyid_is_valid_run("9aa6dAAC706fb6fe4aceb327452a7b5FEA457544", true);
	test_keyid_is_valid_run("eac45c184b7f476472c16d5b0c4f0c52389848001", false);
	test_keyid_is_valid_run("9aa6daac706fb6fe4aceb32g452a7b5fea457544", false);
}

static void test_keyid_normalize(void)
{
	char id[] = "3711927404f64CE7df88253d763e442CE39f9B5c";
	const char *id_norm = "3711927404f64ce7df88253d763e442ce39f9b5c";

	dnssec_keyid_normalize(id);
	ok(strcmp(id, id_norm) == 0, "dnssec_keyid_normalize()");
}

static void test_keyid_copy(void)
{
	const char *id = "21669f1eca6418f9aBBBf0007e6f73463d467424";
	const char *expected = "21669f1eca6418f9abbbf0007e6f73463d467424";

	char *copy = dnssec_keyid_copy(id);
	ok(copy && strcmp(copy, expected) == 0, "dnssec_keyid_copy()");

	free(copy);
}

static void test_keyid_equal(void)
{
	const char *id = "dd63237d4a07867de715499690c9ad12990519f0";
	const char *id_case = "dd63237d4a07867de715499690C9AD12990519F0";
	const char *id_diff = "dd63237d4a07867de715499690c9ad12990519f1";

	ok(dnssec_keyid_equal(id, NULL) == false, "dnssec_keyid_equal(id, NULL)");
	ok(dnssec_keyid_equal(id, id) == true, "dnssec_keyid_equal(id, id)");
	ok(dnssec_keyid_equal(id, id_case) == true, "dnssec_keyid_equal(id, ID)");
	ok(dnssec_keyid_equal(id, id_diff) == false, "dnssec_keyid_equal(ida, idb)");
}

int main(void)
{
	plan_lazy();

	test_keyid_is_valid();
	test_keyid_normalize();
	test_keyid_copy();
	test_keyid_equal();

	return 0;
}
