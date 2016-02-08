/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>

#include "key.h"
#include "dname.h"

/*!
 * DNSSEC key.
 */
struct dnssec_key {
	uint8_t *dname;
	dnssec_binary_t rdata;

	gnutls_pubkey_t public_key;
	gnutls_privkey_t private_key;
	unsigned bits;
};

static const uint16_t DNSKEY_FLAGS_KSK = 257;
static const uint16_t DNSKEY_FLAGS_ZSK = 256;

static inline uint16_t dnskey_flags(bool is_ksk)
{
	return is_ksk ? DNSKEY_FLAGS_KSK : DNSKEY_FLAGS_ZSK;
}
