/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stddef.h>
#include <string.h>

#include "libdnssec/crypto.h"
#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "sample_keys.h"

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

		ok(r == DNSSEC_EOK &&
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
	is_int(DNSSEC_EINVAL, r, "dnssec_key_create_ds() no key");
	dnssec_binary_free(&ds);

	dnssec_key_new(&key);
	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, &ds);
	is_int(DNSSEC_INVALID_KEY_NAME, r, "dnssec_key_create_ds() no key name");

	dnssec_key_set_dname(key, params->name);
	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, &ds);
	is_int(DNSSEC_INVALID_PUBLIC_KEY, r, "dnssec_key_create_ds() no public key");

	dnssec_key_set_rdata(key, &params->rdata);
	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, NULL);
	is_int(DNSSEC_EINVAL, r, "dnssec_key_create_ds() no RDATA buffer");

	r = dnssec_key_create_ds(key, 13, &ds);
	is_int(DNSSEC_INVALID_DS_ALGORITHM, r, "dnssec_key_create_ds() unsupported algorithm");

	r = dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA1, &ds);
	is_int(DNSSEC_EOK, r, "dnssec_key_create_ds() valid parameters");

	dnssec_binary_free(&ds);
	dnssec_key_free(key);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	dnssec_crypto_init();

	test_key("RSA",     &SAMPLE_RSA_KEY);
	test_key("ECDSA",   &SAMPLE_ECDSA_KEY);
#ifdef HAVE_ED25519
	test_key("ED25519", &SAMPLE_ED25519_KEY);
#endif

	test_errors(&SAMPLE_ECDSA_KEY);
#ifdef HAVE_ED25519
	test_errors(&SAMPLE_ED25519_KEY);
#endif

	dnssec_crypto_cleanup();

	return 0;
}
