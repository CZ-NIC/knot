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

#include <dnssec/key.h>
#include <dnssec/binary.h>

/*!
 * Parse legacy key files and get a DNSKEY and private key in PEM.
 *
 * \param[in]  filename  File name of private key, public key, or without extension.
 * \param[out] key       Resulting DNSKEY.
 * \param[out] pem       Private key material in PEM format.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int legacy_key_parse(const char *filename, dnssec_key_t **key, dnssec_binary_t *pem);
