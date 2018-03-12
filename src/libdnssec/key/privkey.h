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

#include "key.h"

/*!
 * Load a private key into a DNSSEC key, create a public part if necessary.
 *
 * If the public key is not loaded, at least an algorithm must be set.
 *
 * Updates private key, public key, RDATA, and key identifiers.
 *
 * \param key      DNSSEC key to be updated.
 * \param privkey  Private key to be set.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int key_set_private_key(dnssec_key_t *key, gnutls_privkey_t privkey);
