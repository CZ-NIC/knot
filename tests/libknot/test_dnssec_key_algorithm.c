/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "libknot/errcode.h"
#include "libknot/dnssec/key.h"

static void ok_range(dnssec_key_algorithm_t algo,
		     unsigned exp_min, unsigned exp_max,
		     const char *name)
{
	unsigned min = 0, max = 0;
	int r = dnssec_algorithm_key_size_range(algo, &min, &max);
	ok(r == KNOT_EOK && min == exp_min && max == exp_max,
	   "dnssec_algorithm_key_size_range() for %s", name);
}

static void null_range(void)
{
	dnssec_key_algorithm_t algo = DNSSEC_KEY_ALGORITHM_RSA_SHA256;
	unsigned val = 0;
	int r;

	r = dnssec_algorithm_key_size_range(algo, NULL, NULL);
	ok(r == KNOT_EINVAL, "dnssec_algorithm_key_size_range() all null");
	r = dnssec_algorithm_key_size_range(algo, &val, NULL);
	ok(r == KNOT_EOK && val == 1024, "dnssec_algorithm_key_size_range() min only");
	r = dnssec_algorithm_key_size_range(algo, NULL, &val);
	ok(r == KNOT_EOK && val == 4096, "dnssec_algorithm_key_size_range() max only");
}

static void check_borders(void)
{
	dnssec_key_algorithm_t rsa = DNSSEC_KEY_ALGORITHM_RSA_SHA1;

	ok(dnssec_algorithm_key_size_check(rsa, 1023) == false, "rsa 1023");
	ok(dnssec_algorithm_key_size_check(rsa, 1024) == true,  "rsa 1024");
	ok(dnssec_algorithm_key_size_check(rsa, 1025) == true,  "rsa 1025");
	ok(dnssec_algorithm_key_size_check(rsa, 4095) == true,  "rsa 4095");
	ok(dnssec_algorithm_key_size_check(rsa, 4096) == true,  "rsa 4096");
	ok(dnssec_algorithm_key_size_check(rsa, 4097) == false, "rsa 4097");
}

static void check_defaults(void)
{
	is_int(2048, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3),   "rsa default");
	is_int(256, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256), "ecc default");
	is_int(256, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_ED25519),           "ed25519 default");
#ifdef HAVE_ED448
	is_int(456, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_ED448),             "ed448 default");
#endif
}

int main(void)
{
	plan_lazy();

	// ranges
	ok_range(DNSSEC_KEY_ALGORITHM_RSA_SHA512, 1024, 4096, "RSA/SHA256");
	ok_range(DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, 384, 384, "ECDSA/SHA384");
	ok_range(DNSSEC_KEY_ALGORITHM_ED25519, 256, 256, "ED25519");
#ifdef HAVE_ED448
	ok_range(DNSSEC_KEY_ALGORITHM_ED448, 456, 456, "ED448");
#endif
	null_range();

	check_borders();

	check_defaults();

	return 0;
}
