/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "libdnssec/binary.h"
#include "libdnssec/error.h"
#include "libdnssec/key/dnskey.h"
#include "libdnssec/shared/shared.h"

/*!
 * Compute keytag for RSA/MD5 key.
 *
 * \see RFC 2537 (section 2), RFC 4034 (appendix B.1)
 */
static uint16_t keytag_compat(const dnssec_binary_t *rdata)
{
	assert(rdata);
	assert(rdata->data);

	if (rdata->size < 9) { // in fact, the condition could be stricter
		return 0;
	}

	uint8_t msb = rdata->data[rdata->size - 3];
	uint8_t lsb = rdata->data[rdata->size - 2];

	return (msb << 8) + lsb;
}

/*!
 * Compute keytag for other than RSA/MD5 key.
 *
 * \see RFC 4034 (appendix B)
 */
static uint16_t keytag_current(const dnssec_binary_t *rdata)
{
	assert(rdata);
	assert(rdata->data);

	uint32_t ac = 0;
	for (int i = 0; i < rdata->size; i++) {
		ac += (i & 1) ? rdata->data[i] : rdata->data[i] << 8;
	}

	return (ac >> 16) + ac;
}

/* -- public API ----------------------------------------------------------- */

/*!
 * Compute keytag for a DNSSEC key.
 */
_public_
int dnssec_keytag(const dnssec_binary_t *rdata, uint16_t *keytag)
{
	if (!rdata || !keytag) {
		return DNSSEC_EINVAL;
	}

	if (!rdata->data || rdata->size < DNSKEY_RDATA_OFFSET_PUBKEY) {
		return DNSSEC_MALFORMED_DATA;
	}

	uint8_t algorithm = rdata->data[DNSKEY_RDATA_OFFSET_ALGORITHM];
	if (algorithm == 1) {
		*keytag = keytag_compat(rdata);
	} else {
		*keytag = keytag_current(rdata);
	}

	return DNSSEC_EOK;
}
