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

static const dnssec_binary_t signed_rsa = { .size = 64, .data = (uint8_t []) {
	0x93, 0x93, 0x5f, 0xd8, 0xa1, 0x2b, 0x4c, 0x0b, 0xf3, 0x67,
	0x42, 0x13, 0x52, 0x00, 0x35, 0xdc, 0x09, 0xe0, 0xdf, 0xe0,
	0x3e, 0xc2, 0xcf, 0x64, 0xab, 0x9f, 0x9f, 0x51, 0x5f, 0x5c,
	0x27, 0xbe, 0x13, 0xd6, 0x17, 0x07, 0xa6, 0xe4, 0x3b, 0x63,
	0x44, 0x85, 0x06, 0x13, 0xaa, 0x01, 0x3c, 0x58, 0x52, 0xa3,
	0x98, 0x20, 0x65, 0x03, 0xd0, 0x40, 0xc8, 0xa0, 0xe9, 0xd2,
	0xc0, 0x03, 0x5a, 0xab,
}};

static const dnssec_binary_t signed_dsa = { .size = 41, .data = (uint8_t []) {
	0x03,
	0x8c, 0xd9, 0x4b, 0xcc, 0xdb, 0xf4, 0x3f, 0x91, 0x0e, 0x7e,
	0x76, 0x1d, 0x87, 0xda, 0x48, 0xdd, 0x65, 0x7a, 0x57, 0x25,
	0x97, 0x0a, 0x13, 0xa5, 0x4a, 0xb3, 0xff, 0x62, 0xfd, 0x2c,
	0x88, 0x35, 0x6e, 0x38, 0xc4, 0xea, 0xe9, 0xc0, 0x72, 0x56,
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
		dnssec_binary_free(&new_signature);
		ok(DNSSEC_EOK == dnssec_sign_verify(ctx, &new_signature), "reverify the new signature");
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
	diag("DSA signing");
	check_key(&SAMPLE_DSA_KEY, &input_data, &signed_dsa, false);
	diag("ECDSA signing");
	check_key(&SAMPLE_ECDSA_KEY, &input_data, &signed_ecdsa, false);
	diag("ED25519 signing");
	check_key(&SAMPLE_ED25519_KEY, &input_data, &signed_ed25519, true);

	dnssec_crypto_cleanup();

	return 0;
}
