#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"

// TODO: verify conditions
// TODO: write tests
static uint16_t keytag_rsa_md5(const dnssec_binary_t *rdata)
{
	assert(rdata);
	assert(rdata->data);

	uint16_t ac = 0;
	if (rdata->size > 4) {
		memmove(&ac, rdata->data + rdata->size - 3, 2);
	}

	return ntohs(ac);
}


uint16_t keytag(const dnssec_binary_t *rdata)
{
	if (!rdata || !rdata->data || rdata->size < 4) {
		return 0;
	}

	uint32_t ac = 0;

	if (rdata->data[3] == 1) {
		return keytag_rsa_md5(rdata);
	}

	for(int i = 0; i < rdata->size; i++) {
		ac += (i & 1) ? rdata->data[i] : rdata->data[i] << 8;
	}

	ac += (ac >> 16) & 0xFFFF;
	return (uint16_t)ac & 0xFFFF;
}
