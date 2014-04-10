#include <tap/basic.h>
#include <string.h>

#include "error.h"
#include "key.h"

#include "sample_keys.h"

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
