/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "libknot/dnssec/binary.h"
#include "libknot/errcode.h"
#include "libknot/dnssec/key/dnskey.h"
#include "libknot/dnssec/key/convert.h"
#include "libknot/dnssec/shared/binary_wire.h"

/* -- internal API --------------------------------------------------------- */

/*!
 * Update 'Public key' field of DNSKEY RDATA.
 */
int dnskey_rdata_set_pubkey(dnssec_binary_t *rdata, const dnssec_binary_t *pubkey)
{
	assert(rdata);
	assert(pubkey);

	size_t new_size = DNSKEY_RDATA_OFFSET_PUBKEY + pubkey->size;
	int result = dnssec_binary_resize(rdata, new_size);
	if (result != KNOT_EOK) {
		return result;
	}

	wire_ctx_t wire = binary_init(rdata);
	wire_ctx_set_offset(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	binary_write(&wire, pubkey);
	assert(wire_ctx_offset(&wire) == rdata->size);

	return KNOT_EOK;
}

/*!
 * Create a GnuTLS public key from DNSKEY RDATA.
 *
 * \param rdata    DNSKEY RDATA.
 * \param key_ptr  Resulting public key.
 */
int dnskey_rdata_to_crypto_key(const dnssec_binary_t *rdata, gnutls_pubkey_t *key_ptr)
{
	assert(rdata);
	assert(key_ptr);

	uint8_t algorithm = 0, protocol = 0, flags_hi = 0;
	dnssec_binary_t rdata_pubkey = { 0 };

	wire_ctx_t wire = binary_init(rdata);

	wire_ctx_set_offset(&wire, DNSKEY_RDATA_OFFSET_FLAGS);
	flags_hi = wire_ctx_read_u8(&wire);
	wire_ctx_set_offset(&wire, DNSKEY_RDATA_OFFSET_PROTOCOL);
	protocol = wire_ctx_read_u8(&wire);
	if (!(flags_hi & 0x1) || protocol != 0x3) {
		return KNOT_INVALID_PUBLIC_KEY;
	}

	wire_ctx_set_offset(&wire, DNSKEY_RDATA_OFFSET_ALGORITHM);
	algorithm = wire_ctx_read_u8(&wire);
	wire_ctx_set_offset(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	binary_available(&wire, &rdata_pubkey);

	gnutls_pubkey_t key = NULL;
	int result = gnutls_pubkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return KNOT_ENOMEM;
	}

	result = convert_dnskey_to_pubkey(algorithm, &rdata_pubkey, key);
	if (result != KNOT_EOK) {
		gnutls_pubkey_deinit(key);
		return result;
	}

	*key_ptr = key;

	return KNOT_EOK;
}
