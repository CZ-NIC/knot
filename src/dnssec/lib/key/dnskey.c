/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "binary.h"
#include "error.h"
#include "key/dnskey.h"
#include "key/convert.h"
#include "wire.h"
#include "binary_wire.h"

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
	if (result != DNSSEC_EOK) {
		return result;
	}

	wire_ctx_t wire = binary_init(rdata);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	binary_write(&wire, pubkey);
	assert(wire_tell(&wire) == rdata->size);

	return DNSSEC_EOK;
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

	uint8_t algorithm = 0;
	dnssec_binary_t rdata_pubkey = { 0 };

	wire_ctx_t wire = binary_init(rdata);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_ALGORITHM);
	algorithm = wire_read_u8(&wire);
	wire_seek(&wire, DNSKEY_RDATA_OFFSET_PUBKEY);
	binary_available(&wire, &rdata_pubkey);

	gnutls_pubkey_t key = NULL;
	int result = gnutls_pubkey_init(&key);
	if (result != GNUTLS_E_SUCCESS) {
		return DNSSEC_ENOMEM;
	}

	result = convert_dnskey_to_pubkey(algorithm, &rdata_pubkey, key);
	if (result != DNSSEC_EOK) {
		gnutls_pubkey_deinit(key);
		return result;
	}

	*key_ptr = key;

	return DNSSEC_EOK;
}
