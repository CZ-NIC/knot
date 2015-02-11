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
/*!
 * \file
 *
 * Low-level key tag computation API.
 *
 * \defgroup keytag Key tag
 *
 * Low-level key tag computation API.
 *
 * The module provides simple interface for DNSKEY key id computation.
 *
 * Example:
 *
 * ~~~~~ {.c}
 *
 * dnssec_binary_t dnskey_rdata = // ... ;
 *
 * int result;
 * uint16_t keytag = 0;
 *
 * result = dnssec_keytag(&dnskey_rdata, &keytag);
 * if (result != DNSSEC_EOK) {
 *     return result;
 * }
 *
 * printf("keytag: %s\n", keytag);
 *
 * ~~~~~
 *
 * @{
 */

#pragma once

#include <stdint.h>
#include <dnssec/binary.h>

/*!
 * Compute a key tag for a DNSSEC key.
 *
 * \param[in]  rdata   DNSKEY RDATA.
 * \param[out] keytag  Computed keytag.
 *
 * \return Error code, DNSSEC_EOK of successful.
 */
int dnssec_keytag(const dnssec_binary_t *rdata, uint16_t *keytag);

/*!
 * @}
 */
