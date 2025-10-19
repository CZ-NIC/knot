/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <gnutls/gnutls.h>
#include <gnutls/pkcs11.h>

#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/p11/p11.h"
#include "libknot/dnssec/shared/shared.h"

_public_
void dnssec_crypto_init(void)
{
	p11_init();
	gnutls_global_init();
}

_public_
void dnssec_crypto_cleanup(void)
{
	gnutls_global_deinit();
	p11_cleanup();
}

_public_
void dnssec_crypto_reinit(void)
{
	p11_reinit();
}
