/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <gnutls/gnutls.h>
#include "binary.h"

int keyid_x509(gnutls_x509_privkey_t key, dnssec_binary_t *id);

int keyid_x509_hex(gnutls_x509_privkey_t key, char **id);

int keyid_pubkey(gnutls_pubkey_t pubkey, dnssec_binary_t *id);

int keyid_pubkey_hex(gnutls_pubkey_t pubkey, char **id);
