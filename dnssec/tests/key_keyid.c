#include <tap/basic.h>
#include <string.h>

#include "error.h"
#include "key.h"

#include "sample_keys.h"

static void test_id_to_str(void)
{
	char *str = NULL;
	dnssec_key_id_t id = {
		0x17, 0xda, 0x10, 0xb0, 0x18, 0xdf, 0xff, 0xb0, 0x8a, 0x25,
		0x1e, 0x74, 0xaf, 0x39, 0x75, 0x2a, 0x54, 0x6e, 0x8c, 0x85
	};

	int result = dnssec_key_id_to_string(id, &str);
	ok(result == DNSSEC_EOK &&
	   strcmp(str, "17da10b018dfffb08a251e74af39752a546e8c85") == 0,
	   "dnssec_key_id_to_string()");
	free(str);
}

static void test_str_to_id(void)
{
	const char *str = "72f8c23503c077be382280ef046f6435981bfe4f";
	dnssec_key_id_t id = { 0 };

	const dnssec_key_id_t expected_id = {
		0x72, 0xf8, 0xc2, 0x35, 0x03, 0xc0, 0x77, 0xbe, 0x38, 0x22,
		0x80, 0xef, 0x04, 0x6f, 0x64, 0x35, 0x98, 0x1b, 0xfe, 0x4f
	};

	int result = dnssec_key_id_from_string(str, id);
	ok(result == DNSSEC_EOK && memcmp(id, expected_id, 20) == 0,
	   "dnssec_key_id_from_string()");
}

int main(void)
{
	plan_lazy();

	test_id_to_str();
	test_str_to_id();

	return 0;
}
