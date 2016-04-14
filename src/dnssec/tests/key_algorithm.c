/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

static void check_borders(void)
{
	dnssec_key_algorithm_t rsa = DNSSEC_KEY_ALGORITHM_RSA_SHA1;

	ok(dnssec_algorithm_key_size_check(rsa, 511)  == false, "rsa 511");
	ok(dnssec_algorithm_key_size_check(rsa, 512)  == true,  "rsa 512");
	ok(dnssec_algorithm_key_size_check(rsa, 513)  == true,  "rsa 513");
	ok(dnssec_algorithm_key_size_check(rsa, 4095) == true,  "rsa 4095");
	ok(dnssec_algorithm_key_size_check(rsa, 4096) == true,  "rsa 4096");
	ok(dnssec_algorithm_key_size_check(rsa, 4097) == false, "rsa 4097");
}

static void check_defaults(void)
{
	is_int(1024, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3), "dsa default");
	is_int(2048, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_RSA_SHA1_NSEC3), "rsa default");
	is_int(256, dnssec_algorithm_key_size_default(DNSSEC_KEY_ALGORITHM_ECDSA_P256_SHA256), "ecc default");
}

int main(void)
{
	plan_lazy();

	// ranges
	ok_range(DNSSEC_KEY_ALGORITHM_DSA_SHA1, 512, 1024, "DSA/SHA1");
	ok_range(DNSSEC_KEY_ALGORITHM_RSA_SHA256, 512, 4096, "RSA/SHA256");
	ok_range(DNSSEC_KEY_ALGORITHM_RSA_SHA512, 1024, 4096, "RSA/SHA512");
	ok_range(DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, 384, 384, "ECDSA/SHA384");

	// special restrictions
	dnssec_key_algorithm_t dsa = DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3;
	ok(dnssec_algorithm_key_size_check(dsa, 512), "dsa 512");
	ok(dnssec_algorithm_key_size_check(dsa, 704), "dsa 704");
	ok(dnssec_algorithm_key_size_check(dsa, 832), "dsa 832");

	check_borders();

	check_defaults();

	return 0;
}
