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

#include <string.h>
#include <tap/basic.h>

#include "sample_keys.h"

#include "binary.h"
#include "crypto.h"
#include "error.h"
#include "key.h"
#include "sign.h"

static const dnssec_binary_t input_data = {
	.size = 25,
	.data = (uint8_t *)"Very good, young padawan."
};

static const dnssec_binary_t signed_rsa = { .size = 128, .data = (uint8_t []) {
	0x21, 0xba, 0xff, 0x0c, 0x15, 0x10, 0x73, 0x25, 0xa7, 0x8e,
	0xf4, 0x71, 0x4b, 0xd3, 0x97, 0x6d, 0x95, 0x52, 0xc2, 0x0b,
	0x43, 0xb3, 0x7d, 0x82, 0xe4, 0x3e, 0x2a, 0xc3, 0xb7, 0x17,
	0x5b, 0x05, 0xe9, 0x1e, 0x13, 0xac, 0x27, 0x6f, 0x20, 0x93,
	0x1a, 0xeb, 0xe2, 0x2c, 0x72, 0x70, 0x14, 0xe6, 0x49, 0xa7,
	0x62, 0xdd, 0x4c, 0x72, 0x1e, 0x1d, 0xd8, 0xf9, 0xba, 0xbc,
	0x96, 0x0e, 0xc3, 0xd4, 0xc1, 0x8f, 0x95, 0xdb, 0x01, 0x18,
	0x24, 0x43, 0xbd, 0x2b, 0x52, 0x9b, 0x10, 0x1f, 0xba, 0x0a,
	0x76, 0xbe, 0x0e, 0xaa, 0x91, 0x27, 0x7b, 0x9f, 0xed, 0x5a,
	0xad, 0x96, 0x1a, 0x02, 0x97, 0x42, 0x91, 0x30, 0x03, 0x2b,
	0x5c, 0xb8, 0xcc, 0x6b, 0xcf, 0x39, 0x62, 0x5e, 0x47, 0xae,
	0x6d, 0x5b, 0x43, 0xd2, 0xc2, 0xd8, 0x22, 0x5d, 0xf5, 0x5e,
	0x0a, 0x97, 0x65, 0x41, 0xc7, 0xaa, 0x28, 0x67,
}};

static const dnssec_binary_t signed_ecdsa = { .size = 64, .data = (uint8_t []) {
	0xa2, 0x95, 0x76, 0xb5, 0xf5, 0x7e, 0xbd, 0xdd, 0xf5, 0x62,
	0xa2, 0xc3, 0xa4, 0x8d, 0xd4, 0x53, 0x5c, 0xba, 0x29, 0x71,
	0x8c, 0xcc, 0x28, 0x7b, 0x58, 0xf3, 0x1e, 0x4e, 0x58, 0xe2,
	0x36, 0x7e,
	0xa0, 0x1a, 0xb6, 0xe6, 0x29, 0x71, 0x1b, 0xd3, 0x8c, 0x88,
	0xc3, 0xee, 0x12, 0x0e, 0x69, 0x70, 0x55, 0x99, 0xec, 0xd5,
	0xf6, 0x4f, 0x4b, 0xe2, 0x41, 0xd9, 0x10, 0x7e, 0x67, 0xe5,
	0xad, 0x2f,
}};

#ifdef HAVE_ED25519
static const dnssec_binary_t signed_ed25519 = { .size = 64, .data = (uint8_t []) {
		0x0a, 0x9e, 0x51, 0x5f, 0x16, 0x89, 0x49, 0x27,
		0x0e, 0x98, 0x34, 0xd3, 0x48, 0xef, 0x5a, 0x6e,
		0x85, 0x2f, 0x7c, 0xd6, 0xd7, 0xc8, 0xd0, 0xf4,
		0x2c, 0x68, 0x8c, 0x1f, 0xf7, 0xdf, 0xeb, 0x7c,
		0x25, 0xd6, 0x1a, 0x76, 0x3e, 0xaf, 0x28, 0x1f,
		0x1d, 0x08, 0x10, 0x20, 0x1c, 0x01, 0x77, 0x1b,
		0x5a, 0x48, 0xd6, 0xe5, 0x1c, 0xf9, 0xe3, 0xe0,
		0x70, 0x34, 0x5e, 0x02, 0x49, 0xfb, 0x9e, 0x05,
	}};
#endif

static dnssec_binary_t binary_set_string(char *str)
{
	dnssec_binary_t result = { .data = (uint8_t *)str, .size = strlen(str) };
	return result;
}

static void check_key(const key_parameters_t *key_data, const dnssec_binary_t *data,
		      const dnssec_binary_t *signature, bool signature_match)
{
	int r;

	// initialize key from public parameters

	dnssec_key_t *key = NULL;
	r = dnssec_key_new(&key);
	ok(r == DNSSEC_EOK && key != NULL, "create key");
	r = dnssec_key_set_rdata(key, &key_data->rdata);
	ok(r == DNSSEC_EOK, "set RDATA");

	// check validation on static signature

	dnssec_sign_ctx_t *ctx = NULL;
	r = dnssec_sign_new(&ctx, key);
	ok(r == DNSSEC_EOK, "create signing context");
	r = dnssec_sign_add(ctx, data);
	ok(r == DNSSEC_EOK, "add data to be signed");
	r = dnssec_sign_verify(ctx, signature);
	ok(r == DNSSEC_EOK, "signature verified");

	// create new signature and self-validate

	r = dnssec_key_load_pkcs8(key, &key_data->pem);
	ok(r == DNSSEC_EOK, "load private key");

	if (signature_match) {
		r = dnssec_sign_init(ctx);
		ok(r == DNSSEC_EOK, "reinitialize context");
		r = dnssec_sign_add(ctx, data);
		ok(r == DNSSEC_EOK, "add data to be signed");
		dnssec_binary_t new_signature = { 0 };
		r = dnssec_sign_write(ctx, &new_signature);
		ok(r == DNSSEC_EOK, "write the signature");
		ok(dnssec_binary_cmp(signature, &new_signature) == 0,
		   "signature exact match");
		r = dnssec_sign_verify(ctx, &new_signature);
		ok(r == DNSSEC_EOK, "reverify the new signature");
		dnssec_binary_free(&new_signature);
	}

	// context reinitialization

	dnssec_binary_t tmp = { 0 };

	r = dnssec_sign_init(ctx);
	ok(r == DNSSEC_EOK, "reinitialize context");

	tmp = binary_set_string("bind");
	r = dnssec_sign_add(ctx, &tmp);
	ok(r == DNSSEC_EOK, "add data (1)");

	r = dnssec_sign_init(ctx);
	ok(r == DNSSEC_EOK, "reinitialize context");

	tmp = binary_set_string("knot");
	r = dnssec_sign_add(ctx, &tmp);
	ok(r == DNSSEC_EOK, "add data (2)");

	tmp = binary_set_string(" is the best");
	r = dnssec_sign_add(ctx, &tmp);
	ok(r == DNSSEC_EOK, "add data (3)");

	dnssec_binary_t new_signature = { 0 };
	r = dnssec_sign_write(ctx, &new_signature);
	ok(r == DNSSEC_EOK, "write signature");

	r = dnssec_sign_init(ctx);
	ok(r == DNSSEC_EOK, "reinitialize context");

	tmp = binary_set_string("knot is the best");
	r = dnssec_sign_add(ctx, &tmp);
	ok(r == DNSSEC_EOK, "add data (4)");

	r = dnssec_sign_verify(ctx, &new_signature);
	ok(r == DNSSEC_EOK, "verify signature");

	dnssec_binary_free(&new_signature);

	// cleanup

	dnssec_sign_free(ctx);
	dnssec_key_free(key);
}

int main(void)
{
	plan_lazy();

	dnssec_crypto_init();

	diag("RSA signing");
	check_key(&SAMPLE_RSA_KEY, &input_data, &signed_rsa, true);
	diag("ECDSA signing");
	check_key(&SAMPLE_ECDSA_KEY, &input_data, &signed_ecdsa, false);
#ifdef HAVE_ED25519
	diag("ED25519 signing");
	check_key(&SAMPLE_ED25519_KEY, &input_data, &signed_ed25519, true);
#endif

	dnssec_crypto_cleanup();

	return 0;
}
