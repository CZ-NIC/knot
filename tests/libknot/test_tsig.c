/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include "libknot/errcode.h"
#include "libknot/tsig.h"

static bool key_is_eq(const knot_tsig_key_t *a, const knot_tsig_key_t *b)
{
	if (a == NULL && b == NULL) {
		return true;
	}

	if (a == NULL || b == NULL) {
		return false;
	}

	return a->algorithm == b->algorithm &&
	       knot_dname_is_equal(a->name, b->name) &&
	       dnssec_binary_cmp(&a->secret, &b->secret) == 0;
}

#define test_function(function, msg, expected, ...) \
	knot_tsig_key_t key = { 0 }; \
	int r = function(&key, __VA_ARGS__); \
	ok((r != KNOT_EOK && expected == NULL) || \
	   (r == KNOT_EOK && key_is_eq(&key, expected)), \
	   "%s: %s", #function, msg); \
	knot_tsig_key_deinit(&key);

static void test_init(const char *msg, const knot_tsig_key_t *expected,
                      const char *algo, const char *name, const char *secret)
{
	test_function(knot_tsig_key_init, msg, expected, algo, name, secret);
}

static void test_init_str(const char *msg, const knot_tsig_key_t *expected,
                          const char *params)
{
	test_function(knot_tsig_key_init_str, msg, expected, params);
}

static void test_init_file(const char *msg, const knot_tsig_key_t *expected,
                           const char *filename)
{
	test_function(knot_tsig_key_init_file, msg, expected, filename);
}

static void test_init_file_content(const char *msg,
                                   const knot_tsig_key_t *expected,
                                   const char *content)
{
	char filename[] = "testkey.XXXXXX";

	int fd = mkstemp(filename);
	if (fd == -1) {
		bail("failed to create temporary file");
		return;
	}

	ok(write(fd, content, strlen(content)) != -1, "file write");
	close(fd);

	test_init_file(msg, expected, filename);

	unlink(filename);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// initialization from parameters

	test_init("missing name", NULL, "hmac-md5", NULL, "Wg==");
	test_init("missing secret", NULL, "hmac-md5", "name", NULL);
	test_init("invalid HMAC", NULL, "hmac-sha11", "name", "Wg==");
	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA256,
			.name = (uint8_t *)"\x3""key""\x4""name",
			.secret.size = 1,
			.secret.data = (uint8_t *)"\x5a"
		};
		test_init("default algorithm", &key, NULL, "key.name", "Wg==");
	}
	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA1,
			.name = (uint8_t *)"\x4""knot""\x3""dns",
			.secret.size = 6,
			.secret.data = (uint8_t *)"secret"
		};
		test_init("sha1", &key, "hmac-sha1", "knot.dns.", "c2VjcmV0");
	}

	// initialization from string

	test_init_str("missing value", NULL, NULL);
	test_init_str("malformed", NULL, "this is malformed");
	test_init_str("invalid HMAC", NULL, "hmac-sha51299:key:Wg==");
	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA256,
			.name = (uint8_t *)"\x4""tsig""\x3""key",
			.secret.size = 9,
			.secret.data = (uint8_t *)"bananakey"
		};
		test_init_str("default algorithm", &key, "tsig.key:YmFuYW5ha2V5");
	}
	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA384,
			.name = (uint8_t *)"\x6""strong""\x3""key",
			.secret.size = 8,
			.secret.data = (uint8_t *)"applekey"
		};
		test_init_str("sha384", &key, "hmac-sha384:strong.KEY:YXBwbGVrZXk=");
	}

	// initialization from a file

	test_init_file("no filename", NULL, NULL);
	test_init_file("not-existing", NULL, "/this-really-should-not-exist");
	test_init_file_content("malformed content", NULL, "malformed\n");
	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA512,
			.name = (uint8_t *)"\x6""django""\x3""one",
			.secret.size = 40,
			.secret.data = (uint8_t *)"Who's that stumbling around in the dark?"
		};
		test_init_file_content("sha512", &key,
		                       "hmac-sha512:django.one:V2hvJ3MgdGhhdCB"
		                       "zdHVtYmxpbmcgYXJvdW5kIGluIHRoZSBkYXJrP"
		                       "w==\n\n\n");
	}
	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA512,
			.name = (uint8_t *)"\x6""django""\x3""two",
			.secret.size = 22,
			.secret.data = (uint8_t *)"Prepare to get winged!"
		};
		test_init_file_content("sha512 without newline", &key,
		                       "hmac-sha512:django.two:UHJlcGFyZSB0byB"
		                       "nZXQgd2luZ2VkIQ==");
	}
	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA1,
			.name = (uint8_t *)"\x4""test",
			.secret.size = 1,
			.secret.data = (uint8_t *)"\x5a"
		};
		test_init_file_content("leading and trailing white spaces", &key,
		                       "\thmac-sha1:test:Wg== \n");
	}

	// tsig key duplication

	{
		static const knot_tsig_key_t key = {
			.algorithm = DNSSEC_TSIG_HMAC_SHA1,
			.name = (uint8_t *)"\x4""copy""\x2""me",
			.secret.size = 6,
			.secret.data = (uint8_t *)"orange"
		};

		knot_tsig_key_t copy = { 0 };
		int r;

		r = knot_tsig_key_copy(NULL, &key);
		ok(r != KNOT_EOK, "knot_tsig_key_copy: no destination");
		r = knot_tsig_key_copy(&copy, NULL);
		ok(r != KNOT_EOK, "knot_tsig_key_copy: no source");
		r = knot_tsig_key_copy(&copy, &key);
		ok(r == KNOT_EOK && key_is_eq(&copy, &key) &&
		   copy.secret.data != key.secret.data && copy.name != key.name,
		   "knot_tsig_key_copy: simple copy");

		knot_tsig_key_deinit(&copy);
	}

	return 0;
}
