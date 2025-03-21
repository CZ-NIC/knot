/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>

#include "libdnssec/binary.h"

int keyid_x509(gnutls_x509_privkey_t key, dnssec_binary_t *id);

int keyid_x509_hex(gnutls_x509_privkey_t key, char **id);

int keyid_pubkey(gnutls_pubkey_t pubkey, dnssec_binary_t *id);

int keyid_pubkey_hex(gnutls_pubkey_t pubkey, char **id);
