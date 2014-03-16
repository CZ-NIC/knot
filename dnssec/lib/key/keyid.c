#include <string.h>

#include "hex.h"
#include "key.h"

char *dnssec_key_id_to_string(const dnssec_key_id_t id)
{
	const dnssec_binary_t binary = {
		.data = (uint8_t *)id,
		.size = DNSSEC_KEY_ID_SIZE
	};

	return hex_to_string(&binary);
}

void dnssec_key_id_copy(const dnssec_key_id_t from, dnssec_key_id_t to)
{
	if (!from || !to || from == to) {
		return;
	}

	memmove(to, from, DNSSEC_KEY_ID_SIZE);
}

int dnssec_key_id_cmp(const dnssec_key_id_t one, const dnssec_key_id_t two)
{
	if (one == two) {
		return 0;
	} else {
		return memcmp(one, two, DNSSEC_KEY_ID_SIZE);
	}
}
