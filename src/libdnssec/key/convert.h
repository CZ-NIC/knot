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
#include "key.h"

/*!
 * Encode public key into the format used in DNSKEY RDATA.
 *
 * \param[in]  key    Public key to be encoded.
 * \param[out] rdata  Encoded key (allocated).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int convert_pubkey_to_dnskey(gnutls_pubkey_t key, dnssec_binary_t *rdata);

/*!
 * Create public key from the format encoded in DNSKEY RDATA.
 *
 * \param[in]  algorithm  DNSSEC algorithm identification.
 * \param[in]  rdata      Public key in DNSKEY RDATA format.
 * \param[out] key        GnuTLS public key (initialized).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int convert_dnskey_to_pubkey(uint8_t algorithm, const dnssec_binary_t *rdata,
			     gnutls_pubkey_t key);
