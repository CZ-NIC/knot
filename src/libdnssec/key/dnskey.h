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

#pragma once

#include <gnutls/abstract.h>

#include "binary.h"
#include "error.h"

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
