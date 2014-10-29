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

/*!
 * Get ID from GnuTLS public key and convert it into library format.
 */
char *gnutls_pubkey_hex_key_id(gnutls_pubkey_t key);

/*!
 * Get ID from GnuTLS X.509 private key and convert it into library format.
 */
char *gnutls_x509_privkey_hex_key_id(gnutls_x509_privkey_t key);
