/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "crypto.h"

int main(void)
{
	plan_lazy();

	// not much we can test

	dnssec_crypto_init();
	ok(1, "dnssec_crypto_init() didn't crash");

	dnssec_crypto_reinit();
	ok(1, "dnssec_crypto_reinit() didn't crash");

	dnssec_crypto_cleanup();
	ok(1, "dnssec_crypto_cleanup() didn't crash");

	return 0;
}
