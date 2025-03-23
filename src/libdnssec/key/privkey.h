/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <gnutls/abstract.h>

#include "libdnssec/key.h"

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
