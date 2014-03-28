#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stddef.h>
#include <stdint.h>

#include "error.h"
#include "random.h"
#include "shared.h"

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_random_buffer(uint8_t *data, size_t size)
{
	if (!data) {
		return DNSSEC_EINVAL;
	}

	int result = gnutls_rnd(GNUTLS_RND_RANDOM, data, size);
	if (result != 0) {
		assert(0);
		return DNSSEC_ERROR;
	}

	return DNSSEC_EOK;
}

_public_
int dnssec_random_binary(dnssec_binary_t *binary)
{
	if (!binary) {
		return DNSSEC_EINVAL;
	}

	return dnssec_random_buffer(binary->data, binary->size);
}
