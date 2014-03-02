#include <tap/basic.h>
#include <string.h>

#include "binary.h"
#include "key.h"
#include "error.h"
#include "sample_keys.h"

static void check_key(const char *name, const key_parameters_t *params)
{
	int r;

	dnssec_key_t *key = NULL;
	r = dnssec_key_new(&key);
	ok(r == DNSSEC_EOK && key != NULL, "%s: dnssec_key_new()", name);

	// create from parameters

	r = dnssec_key_from_params(key, params->flags, params->protocol,
				   params->algorithm, &params->public_key);
	ok(r == DNSSEC_EOK, "%s: dnssec_key_from_params()", name);

	// get RDATA

	dnssec_binary_t rdata = { 0 };
	r = dnssec_key_get_dnskey(key, &rdata);
	ok(r == DNSSEC_EOK &&
	   rdata.size == params->rdata.size &&
	   memcmp(rdata.data, params->rdata.data, rdata.size) == 0,
	  "%s: dnssec_key_get_dnskey()", name);
	dnssec_binary_free(&rdata);

	// get identifiers

	dnssec_key_id_t key_id = { 0 };
	r = dnssec_key_get_id(key, key_id);
	ok(r == DNSSEC_EOK && 0 /* TBD */,
	   "%s: dnssec_key_get_id()", name);

	ok(dnssec_key_get_keytag(key) == params->keytag,
	   "%s: dnssec_key_get_keytag()", name);

	// create from RDATA

	dnssec_key_clear(key);
	r = dnssec_key_from_dnskey(key, &params->rdata);
	ok(r == DNSSEC_EOK, "%s: dnssec_key_from_dnskey()", name);

	ok(dnssec_key_get_flags(key) == params->flags,
	   "%s: dnssec_key_get_flags()", name);
	ok(dnssec_key_get_protocol(key) == params->protocol,
	   "%s: dnssec_key_get_protocol()", name);
	ok(dnssec_key_get_algorithm(key) == params->algorithm,
	   "%s: dnssec_key_get_algorithm()", name);

	dnssec_key_free(&key);
}

typedef struct keyinfo {
	const char *name;
	const key_parameters_t *parameters;
} keyinfo_t;

static void public_from_dnskey(void)
{
	keyinfo_t keys[] = {
		{ "rsa", &SAMPLE_RSA_KEY },
		{ "dsa", &SAMPLE_DSA_KEY },
		{ "ecdsa", &SAMPLE_ECDSA_KEY },
		{ NULL }
	};

	for (keyinfo_t *k = keys; k->name != NULL; k += 1) {
		check_key(k->name, k->parameters);
	}
}

int main(void)
{
	plan_lazy();

	public_from_dnskey();

	return 0;
}
