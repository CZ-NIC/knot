#include <tap/basic.h>

#include <binary.h>
#include <key.h>

static int legacy_main(void)
{
	dnssec_key_t _cleanup_key_ *rsa_key = NULL;
	dnssec_key_t _cleanup_key_ *dsa_key = NULL;
	dnssec_key_t _cleanup_key_ *ecdsa_key = NULL;
}

int main(void)
{
	plan_lazy();

	legacy_main();

	ok(0, "err");

	return 0;
}
