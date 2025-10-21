/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include <stddef.h>
#include <string.h>

#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/error.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/sample_keys.h"

static void test_key(const char *name, const struct key_parameters *params)
{
	dnssec_key_t *key = NULL;

	dnssec_key_new(&key);
	dnssec_key_set_dname(key, params->name);
	dnssec_key_set_rdata(key, &params->rdata);

	struct ds_type {
		const char *name;
		dnssec_key_digest_t digest;
		size_t params_offset;
	};

	static const struct ds_type DS_TYPES[] = {
		{ "SHA-1",   DNSSEC_KEY_DIGEST_SHA1,   offsetof(typeof(*params), ds_sha1)   },
		{ "SHA-256", DNSSEC_KEY_DIGEST_SHA256, offsetof(typeof(*params), ds_sha256) },
		{ "SHA-384", DNSSEC_KEY_DIGEST_SHA384, offsetof(typeof(*params), ds_sha384) },
		{ NULL }
	};

	for (const struct ds_type *dt = DS_TYPES; dt->name != NULL; dt++) {
		dnssec_binary_t ds = { 0 };
		int r = dnssec_key_create_ds(key, dt->digest, &ds);

		const dnssec_binary_t *expect = (void *)params + dt->params_offset;

		ok(r == KNOT_EOK &&
		   ds.size == expect->size &&
		   memcmp(ds.data, expect->data, ds.size) == 0,
		   "dnssec_key_create_ds() for %s/%s", name, dt->name);

		dnssec_binary_free(&ds);
	}

	dnssec_key_free(key);
}

static void test_errors(const struct key_parameters *params)
{
	dnssec_key_t *key = NULL;
	dnssec_binary_t ds = { 0 };

	int r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, &ds);
	is_int(KNOT_EINVAL, r, "dnssec_key_create_ds() no key");
	dnssec_binary_free(&ds);

	dnssec_key_new(&key);
	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, &ds);
	is_int(DNSSEC_INVALID_KEY_NAME, r, "dnssec_key_create_ds() no key name");

	dnssec_key_set_dname(key, params->name);
	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, &ds);
	is_int(DNSSEC_INVALID_PUBLIC_KEY, r, "dnssec_key_create_ds() no public key");

	dnssec_key_set_rdata(key, &params->rdata);
	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, NULL);
	is_int(KNOT_EINVAL, r, "dnssec_key_create_ds() no RDATA buffer");

	r = dnssec_key_create_ds(key, 3, &ds);
	is_int(DNSSEC_INVALID_DS_ALGORITHM, r, "dnssec_key_create_ds() unsupported algorithm");

	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, &ds);
	is_int(KNOT_EOK, r, "dnssec_key_create_ds() valid parameters");

	dnssec_binary_free(&ds);
	dnssec_key_free(key);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_crypto_init();

	test_key("RSA",     &SAMPLE_RSA_KEY);
	test_key("ECDSA",   &SAMPLE_ECDSA_KEY);
	test_key("ED25519", &SAMPLE_ED25519_KEY);
#ifdef HAVE_ED448
	test_key("ED448",   &SAMPLE_ED448_KEY);
#endif

	test_errors(&SAMPLE_ECDSA_KEY);
	test_errors(&SAMPLE_ED25519_KEY);
#ifdef HAVE_ED448
	test_errors(&SAMPLE_ED448_KEY);
#endif

	dnssec_crypto_cleanup();

	return 0;
}
