/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stddef.h>
#include <stdint.h>

#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libdnssec/shared/shared.h"

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_random_buffer(uint8_t *data, size_t size)
{
	if (!data) {
		return DNSSEC_EINVAL;
	}

	int result = gnutls_rnd(GNUTLS_RND_RANDOM, data, size);
	if (result != 0) {
		assert_unreachable();
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
