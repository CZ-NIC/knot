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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#pragma once

#include <gnutls/gnutls.h>

#include "libdnssec/key.h"

/*!
 * Convert DNSKEY algorithm identifier to GnuTLS identifier.
 *
 * \param dnssec  DNSSEC DNSKEY algorithm identifier.
 *
 * \return GnuTLS private key algorithm identifier, GNUTLS_PK_UNKNOWN on error.
 */
gnutls_pk_algorithm_t algorithm_to_gnutls(dnssec_key_algorithm_t dnssec);
