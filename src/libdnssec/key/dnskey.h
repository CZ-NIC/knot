/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <gnutls/abstract.h>

#include "libdnssec/binary.h"
#include "libdnssec/error.h"

/*!
 * DNSKEY RDATA fields offsets.
 *
 * \see RFC 4034 (section 2.1)
 */
enum dnskey_rdata_offsets {
	DNSKEY_RDATA_OFFSET_FLAGS = 0,
	DNSKEY_RDATA_OFFSET_PROTOCOL = 2,
	DNSKEY_RDATA_OFFSET_ALGORITHM = 3,
	DNSKEY_RDATA_OFFSET_PUBKEY = 4,
};

/*!
 * Update 'Public key' field of DNSKEY RDATA.
 */
int dnskey_rdata_set_pubkey(dnssec_binary_t *rdata,
			    const dnssec_binary_t *pubkey);

/*!
 * Create a GnuTLS public key from DNSKEY RDATA.
 */
int dnskey_rdata_to_crypto_key(const dnssec_binary_t *rdata,
			       gnutls_pubkey_t *key_ptr);
