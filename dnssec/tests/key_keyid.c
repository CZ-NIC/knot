#include <tap/basic.h>
#include <string.h>

#include "key.h"

#include "sample_keys.h"

int main(void)
{
	plan_lazy();

	dnssec_key_id_t key_id = {
		0x17, 0xda, 0x10, 0xb0, 0x18, 0xdf, 0xff, 0xb0, 0x8a, 0x25,
		0x1e, 0x74, 0xaf, 0x39, 0x75, 0x2a, 0x54, 0x6e, 0x8c, 0x85
	};
	char *key_id_str = dnssec_key_id_to_string(key_id);
	ok(strcmp(key_id_str, "17da10b018dfffb08a251e74af39752a546e8c85") == 0,
	   "dnssec_key_id_to_string()");
	free(key_id_str);

	return 0;
}
