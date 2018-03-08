/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include "error.h"
#include "key.h"

static void ok_range(dnssec_key_algorithm_t algo,
		     unsigned exp_min, unsigned exp_max,
		     const char *name)
{
	unsigned min = 0, max = 0;
	int r = dnssec_algorithm_key_size_range(algo, &min, &max);
	ok(r == DNSSEC_EOK && min == exp_min && max == exp_max,
	   "dnssec_algorithm_key_size_range() for %s", name);
}

static void null_range(void)
{
	dnssec_key_algorithm_t algo = DNSSEC_KEY_ALGORITHM_RSA_SHA256;
	unsigned val = 0;
	int r;

	r = dnssec_algorithm_key_size_range(algo, NULL, NULL);
	ok(r == DNSSEC_EINVAL, "dnssec_algorithm_key_size_range() all null");
	r = dnssec_algorithm_key_size_range(algo, &val, NULL);
	ok(r == DNSSEC_EOK && val == 1024, "dnssec_algorithm_key_size_range() min only");
	r = dnssec_algorithm_key_size_range(algo, NULL, &val);
	ok(r == DNSSEC_EOK && val == 4096, "dnssec_algorithm_key_size_range() max only");
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
#ifdef HAVE_ED25519
	is_int(256, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_ED25519),           "ed25519 default");
#endif
}

int main(void)
{
	plan_lazy();

	// ranges
	ok_range(DNSSEC_KEY_ALGORITHM_RSA_SHA512, 1024, 4096, "RSA/SHA256");
	ok_range(DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, 384, 384, "ECDSA/SHA384");
#ifdef HAVE_ED25519
	ok_range(DNSSEC_KEY_ALGORITHM_ED25519, 256, 256, "ED25519");
#endif
	null_range();

	check_borders();

	check_defaults();

	return 0;
}
