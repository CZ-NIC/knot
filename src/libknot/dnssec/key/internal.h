/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <gnutls/abstract.h>
#include <stdint.h>

#include "libknot/dnssec/key.h"
#include "libknot/dnssec/shared/dname.h"

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
