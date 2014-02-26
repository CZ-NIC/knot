#include <tap/basic.h>
#include <string.h>

#include "binary.h"
#include "error.h"

typedef struct test_string {
	const char *encoded;
	size_t encoded_size;
	const char *decoded;
	size_t decoded_size;
} test_string_t;

int main(void)
{
	plan_lazy();

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
		dnssec_binary_t _cleanup_binary_ binary = { 0 };
		int r = dnssec_binary_from_base64(&binary,
						 (const uint8_t *)ts->encoded,
						 ts->encoded_size);

		ok(r == DNSSEC_EOK, "[%d] conversion performed", i);

		ok(binary.size == ts->decoded_size &&
		   memcmp(binary.data, ts->decoded, binary.size) == 0,
		   "[%d] conversion is correct", i);
	}

	return 0;
}
