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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <tap/basic.h>
#include <string.h>

#include "binary.h"
#include "crypto.h"
#include "error.h"
#include "key.h"

#include "sample_keys.h"

#define check_attr_scalar(key, type, name, def_val, set_val) { \
	type value = dnssec_key_get_##name(key); \
	ok(value == def_val, #name " default"); \
	int r = dnssec_key_set_##name(key, set_val); \
	ok(r == DNSSEC_EOK, #name " set"); \
	value = dnssec_key_get_##name(key); \
	ok(value == set_val, #name " get"); \
}

static void check_key_tag(dnssec_key_t *key, const key_parameters_t *params)
{
	uint16_t keytag = dnssec_key_get_keytag(key);
	ok(keytag == params->keytag, "get keytag");
}

static void check_key_size(dnssec_key_t *key, const key_parameters_t *params)
{
	switch (params->algorithm) {
	case 13:
	case 14:
	case 15:
	case 16:
		if (!dnssec_key_can_sign(key)) {
			skip("key size without private key known to be broken");
			return;
		}
	}

	ok(dnssec_key_get_size(key) == params->bit_size,
	   "key size %u bits", params->bit_size);
}

static void check_usage(dnssec_key_t *key, bool ok_verify, bool ok_sign)
{
	ok(dnssec_key_can_verify(key) == ok_verify,
	  "%s verify", ok_verify ? "can" : "cannot");
	ok(dnssec_key_can_sign(key) == ok_sign,
	  "%s sign", ok_sign ? "can" : "cannot");
}

static void test_public_key(const key_parameters_t *params)
{
	dnssec_key_t *key = NULL;
	int r = dnssec_key_new(&key);
	ok(r == DNSSEC_EOK && key != NULL, "create key");

	// create from parameters

	r = dnssec_key_set_pubkey(key, &params->public_key);
	ok(r == DNSSEC_INVALID_KEY_ALGORITHM,
	   "set public key (fails, no algorithm set)");

	check_attr_scalar(key, uint16_t, flags,     256, params->flags);
	check_attr_scalar(key, uint8_t,  protocol,  3,   params->protocol);
	check_attr_scalar(key, uint8_t,  algorithm, 0,   params->algorithm);

	r = dnssec_key_set_pubkey(key, &params->public_key);
	ok(r == DNSSEC_EOK, "set public key (succeeds)");

	r = dnssec_key_set_pubkey(key, &params->public_key);
	ok(r == DNSSEC_KEY_ALREADY_PRESENT,
	   "set public key (fails, already present)");

	dnssec_binary_t rdata = { 0 };
	r = dnssec_key_get_rdata(key, &rdata);
	ok(r == DNSSEC_EOK && dnssec_binary_cmp(&rdata, &params->rdata) == 0,
	   "get RDATA");

	check_key_tag(key, params);

	// create from RDATA

	dnssec_key_clear(key);
	r = dnssec_key_set_rdata(key, &params->rdata);
	ok(r == DNSSEC_EOK, "set RDATA");

	check_key_tag(key, params);
	check_key_size(key, params);
	check_usage(key, true, false);

	// create copy

	dnssec_key_t *copy = dnssec_key_dup(key);
	ok(copy != NULL, "duplicate key");

	check_key_tag(copy, params);
	check_key_size(copy, params);
	check_usage(copy, true, false);

	dnssec_key_free(copy);
	dnssec_key_free(key);
}

static void test_private_key(const key_parameters_t *params)
{
	dnssec_key_t *key = NULL;
	int r = dnssec_key_new(&key);
	ok(r == DNSSEC_EOK && key != NULL, "create key");

	// import to public

	r = dnssec_key_set_rdata(key, &params->rdata);
	ok(r == DNSSEC_EOK, "set RDATA");

	r = dnssec_key_load_pkcs8(key, &params->pem);
	ok(r == DNSSEC_EOK, "load private key (1)");

	ok(dnssec_key_can_verify(key), "can verify");
	ok(dnssec_key_can_sign(key), "can sign");

	// purely from parameters

	dnssec_key_clear(key);

	dnssec_key_set_algorithm(key, params->algorithm);
	dnssec_key_set_flags(key, params->flags);
	r = dnssec_key_load_pkcs8(key, &params->pem);
	ok(r == DNSSEC_EOK, "load private key (2)");

	dnssec_binary_t rdata = { 0 };
	r = dnssec_key_get_rdata(key, &rdata);
	ok(r == DNSSEC_EOK && dnssec_binary_cmp(&rdata, &params->rdata) == 0,
	   "get RDATA");

	check_key_tag(key, params);
	check_key_size(key, params);
	check_usage(key, true, true);

	// create copy

	dnssec_key_t *copy = dnssec_key_dup(key);
	ok(copy != NULL, "duplicate key");

	check_key_tag(copy, params);
	check_key_size(copy, params);
	check_usage(copy, true, false);

	dnssec_key_free(copy);
	dnssec_key_free(key);
}

static void test_naming(void)
{
	dnssec_key_t *key = NULL;
	dnssec_key_new(&key);

	const uint8_t *input = (uint8_t *)"\x07""eXample""\x03""COM";
	const uint8_t *expected = (uint8_t *)"\x07""example""\x03""com";
	size_t expected_size = 13;

	ok(dnssec_key_get_dname(key) == NULL, "implicit key name");

	dnssec_key_set_dname(key, input);
	const uint8_t *output = dnssec_key_get_dname(key);

	ok(strlen((char *)output) + 1 == 13 &&
	   memcmp(output, expected, expected_size) == 0,
	   "set key name");

	dnssec_key_set_dname(key, NULL);
	ok(dnssec_key_get_dname(key) == NULL, "clear key name");

	dnssec_key_free(key);
}

typedef struct keyinfo {
	const char *name;
	const key_parameters_t *parameters;
} keyinfo_t;

int main(void)
{
	plan_lazy();

	dnssec_crypto_init();

	static const keyinfo_t keys[] = {
		{ "RSA",     &SAMPLE_RSA_KEY },
		{ "ECDSA",   &SAMPLE_ECDSA_KEY },
#ifdef HAVE_ED25519
		{ "ED25519", &SAMPLE_ED25519_KEY },
#endif
		{ NULL }
	};

	for (const keyinfo_t *k = keys; k->name != NULL; k += 1) {
		diag("%s key", k->name);
		test_public_key(k->parameters);
		test_private_key(k->parameters);
	}

	test_naming();

	dnssec_crypto_cleanup();

	return 0;
}
