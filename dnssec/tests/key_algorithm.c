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

void key_check_borders(void)
{
	dnssec_key_algorithm_t rsa = DNSSEC_KEY_ALGORITHM_RSA_SHA1;

	ok(dnssec_algorithm_key_size_check(rsa, 511)  == false, "rsa 511");
	ok(dnssec_algorithm_key_size_check(rsa, 512)  == true,  "rsa 512");
	ok(dnssec_algorithm_key_size_check(rsa, 513)  == true,  "rsa 513");
	ok(dnssec_algorithm_key_size_check(rsa, 4095) == true,  "rsa 4095");
	ok(dnssec_algorithm_key_size_check(rsa, 4096) == true,  "rsa 4096");
	ok(dnssec_algorithm_key_size_check(rsa, 4097) == false, "rsa 4097");
}

int main(void)
{
	plan_lazy();

	// default ranges

	ok_range(DNSSEC_KEY_ALGORITHM_DSA_SHA1, 512, 1024, "DSA/SHA1");
	ok_range(DNSSEC_KEY_ALGORITHM_RSA_SHA256, 512, 4096, "RSA/SHA256");
	ok_range(DNSSEC_KEY_ALGORITHM_RSA_SHA512, 1024, 4096, "RSA/SHA512");
	ok_range(DNSSEC_KEY_ALGORITHM_ECDSA_P384_SHA384, 384, 384, "ECDSA/SHA384");

	// key check borders

	key_check_borders();

	// special restrictions on DSA

	dnssec_key_algorithm_t dsa = DNSSEC_KEY_ALGORITHM_DSA_SHA1_NSEC3;
	ok(dnssec_algorithm_key_size_check(dsa, 512), "dsa 512");
	ok(dnssec_algorithm_key_size_check(dsa, 704), "dsa 704");
	ok(dnssec_algorithm_key_size_check(dsa, 832), "dsa 832");

	return 0;
}
