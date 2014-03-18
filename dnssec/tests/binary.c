#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "binary.h"
#include "error.h"

typedef struct test_string {
	const char *encoded;
	size_t encoded_size;
	const char *decoded;
	size_t decoded_size;
} test_string_t;

static void test_base64(void)
{
	test_string_t data[] = {
		{ "YQ==",     4, "a",      1 },
		{ "YWI=",     4, "ab",     2 },
		{ "YWJj",     4, "abc",    3 },
		{ "YWJjZA==", 8, "abcd",   4 },
		{ "YWJjZGU=", 8, "abcde",  5 },
		{ "YWJjZGVm", 8, "abcdef", 6 },
		{ NULL }
	};

	for (int i = 0; data[i].encoded != NULL; i++) {
		test_string_t *ts = &data[i];

		const dnssec_binary_t base64 = {
			.size = ts->encoded_size,
			.data = (uint8_t *) ts->encoded
		};

		dnssec_binary_t binary = { 0 };

		int r = dnssec_binary_from_base64(&base64, &binary);
		ok(r == DNSSEC_EOK &&
		   binary.size == ts->decoded_size &&
		   memcmp(binary.data, ts->decoded, binary.size) == 0,
		   "dnssec_binary_from_base64() for '%s'", ts->encoded);

		dnssec_binary_free(&binary);
	}
}

static void test_dup(void)
{
	dnssec_binary_t src = { .size = 5, .data = (uint8_t *) "ahoj" };
	dnssec_binary_t dst = { 0 };

	int r = dnssec_binary_dup(&src, &dst);
	ok(r == DNSSEC_EOK &&
	   src.size == dst.size && memcmp(src.data, dst.data, src.size) == 0,
	   "dnssec_binary_dup()");

	dnssec_binary_free(&dst);
}

static void test_ltrim(void)
{
	dnssec_binary_t trim_me = {
		.size = 4,
		.data = (uint8_t []) { 0x02, 0x00, 0x01, 0x00 }
	};

	dnssec_binary_ltrim(&trim_me);
	ok(trim_me.size == 4 && trim_me.data[0] == 0x02,
	   "dnssec_binary_ltrim() nothing to trim");

	trim_me.data[0] = 0x00;
	dnssec_binary_ltrim(&trim_me);
	ok(trim_me.size == 2 && trim_me.data[0] == 0x01,
	   "dnssec_binary_ltrim() trim a few");

	trim_me.data[0] = 0x00;
	dnssec_binary_ltrim(&trim_me);
	ok(trim_me.size == 1 && trim_me.data[0] == 0x00,
	   "dnssec_binary_ltrim() preserve last zero");
}

int main(void)
{
	plan_lazy();

	test_base64();
	test_dup();
	test_ltrim();

	return 0;
}
