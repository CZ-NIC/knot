/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <config.h>
#include <assert.h>
#include <openssl/opensslconf.h>
#include <tap/basic.h>

#include "common/errcode.h"
#include "libknot/dnssec/config.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/sign.h"

static void test_algorithm(const char *alg, const knot_key_params_t *kp)
{
	int result;

	knot_dnssec_key_t key = { 0 };
	result = knot_dnssec_key_from_params(kp, &key);
	is_int(KNOT_EOK, result, "%s: create key from params", alg);

	knot_dnssec_sign_context_t *ctx;
	ctx = knot_dnssec_sign_init(&key);
	ok(ctx != NULL, "%s: create signing context", alg);

	if (ctx == NULL) {
		skip_block(12, "%s: required test failed", alg);
	} else {

		size_t sig_size = knot_dnssec_sign_size(&key);
		ok(sig_size > 0, "%s: get signature size", alg);

		uint8_t *sig = malloc(sig_size);
		assert(sig != NULL);

		result = knot_dnssec_sign_add(ctx, (uint8_t *)"test", 4);
		is_int(KNOT_EOK, result, "%s: add data A", alg);

		result = knot_dnssec_sign_new(ctx);
		is_int(KNOT_EOK, result, "%s: restart context", alg);

		result = knot_dnssec_sign_add(ctx, (uint8_t *)"hello", 5);
		is_int(KNOT_EOK, result, "%s: add data B", alg);

		result = knot_dnssec_sign_add(ctx, (uint8_t *)"dns", 3);
		is_int(KNOT_EOK, result, "%s: add data C", alg);

		result = knot_dnssec_sign_write(ctx, sig, sig_size);
		is_int(KNOT_EOK, result, "%s: write signature", alg);

		result = knot_dnssec_sign_new(ctx);
		is_int(KNOT_EOK, result, "%s: restart context", alg);

		result = knot_dnssec_sign_add(ctx, (uint8_t *)"wrong", 5);
		is_int(KNOT_EOK, result, "%s: add data D", alg);

		result = knot_dnssec_sign_verify(ctx, sig, sig_size);
		ok(result == KNOT_DNSSEC_EINVALID_SIGNATURE, "%s: verify invalid signature", alg);

		result = knot_dnssec_sign_new(ctx);
		is_int(KNOT_EOK, result, "%s: restart context", alg);

		result = knot_dnssec_sign_add(ctx, (uint8_t *)"hellodns", 8);
		is_int(KNOT_EOK, result, "%s: add data B + C", alg);

		result = knot_dnssec_sign_verify(ctx, sig, sig_size);
		is_int(KNOT_EOK, result, "%s: verify valid signature", alg);

		free(sig);
	}

	knot_dnssec_sign_free(ctx);
	knot_dnssec_key_free(&key);
}

int main(int argc, char *argv[])
{
	plan(4 * 14);

	knot_key_params_t kp = { 0 };

	// RSA

	kp.name = knot_dname_from_str("example.com.");
	kp.algorithm = 5;
	knot_binary_from_base64("pSxiFXG8wB1SSHdok+OdaAp6QdvqjpZ17ucNge21iYVfv+DZq52l21KdmmyEqoG9wG/87O7XG8XVLNyYPue8Mw==", &kp.modulus);
	knot_binary_from_base64("AQAB", &kp.public_exponent);
	knot_binary_from_base64("UuNK9Wf2SJJuUF9b45s9ypA3egVaV+O5mwHoDWO0ziWJxFXNMMsobDdusEDjCw64xnlLmrbzNJ3+ClrOnV04gQ==", &kp.private_exponent);
	knot_binary_from_base64("0/wjqkgVZxqrFi5OMzq2qQYpxKn3HgS87Io9UG6iqis=", &kp.prime_one);
	knot_binary_from_base64("x3gFCPpaJ4etPEM1hRd6WMAcmx5FBMjvuuzID6SWWhk=", &kp.prime_two);
	knot_binary_from_base64("Z8qUS9NvZ0QPcJTLhRnCRY/W84ukivYW6lnlG3SQAHE=", &kp.exponent_one);
	knot_binary_from_base64("C0kjH8rqZuoqRwqWcJ1Pcs4L0Er6JLcpuS3Ec/4f86E=", &kp.exponent_two);
	knot_binary_from_base64("VYc62FQX0Vnd27VxkX6hsBcl7Oh00wVCeh3WTDutndg=", &kp.coefficient);

	test_algorithm("RSA", &kp);
	knot_free_key_params(&kp);

	// DSA

	kp.name = knot_dname_from_str("example.com.");
	kp.algorithm = 6;
	knot_binary_from_base64("u7tr4jc7CH0+r2muVEZyjYu7hpMrQ1dHGAMv7hr5dBFYzkutfdBmDSW4C+qxaXWo14gi+jJ8XqFqQ7rQn23DdQ==", &kp.prime);
	knot_binary_from_base64("tgZ5X6pFoCOM2NzfiAYVG1434Mk=", &kp.subprime);
	knot_binary_from_base64("bHidtFIFYAHXp7ZxTFd6poJJG8brqO9eyJygvYSFCej/FGDqhF2TsboVvS/evW/qTaSvhkd/aiDg5eAfu1HvrQ==", &kp.base);
	knot_binary_from_base64("FiTBDsbFDNTw7IrhPeVbzM0DMmI=", &kp.private_value);
	knot_binary_from_base64("G1pX04Bcew8wyHsmno4Q0tNdmBLlaEdbqvQ03W5XVXUM6MPrtzxgc6jdOogqZsvGK4c+FbThBu42Z1t/ioQr8A==", &kp.public_value);

	test_algorithm("DSA", &kp);
	knot_free_key_params(&kp);

	// ECDSA

#ifdef KNOT_ENABLE_ECDSA
	kp.name = knot_dname_from_str("example.com");
	kp.algorithm = 13;
	knot_binary_from_base64("1N/PvpB8jZcvv+zr3Q987RKK1cBxDKULzEc5F/nnpSg=", &kp.private_key);
	knot_binary_from_base64("AAAAAH3t6EfkvHK5fQMGslhWcCfMF6Q3oNbol2f19DGAb8r49ZX7iQ12sFIyrs2CiwDxFR9Y7fF2zOZ005VV1LA3m1Q=", &kp.rdata);

	test_algorithm("ECDSA", &kp);
	knot_free_key_params(&kp);
#else
	skip_block(14, "ECDSA: not supported on this system");
#endif

#if KNOT_ENABLE_GOST
	kp.name = knot_dname_from_str("example.com");
	kp.algorithm = 12;
	knot_binary_from_base64("MEUCAQAwHAYGKoUDAgITMBIGByqFAwICIwEGByqFAwICHgEEIgIgN2CMRL538HmFM9+GHYM54rEDYO+tLDV3q7AtK1nZ4iA=", &kp.private_key);
	knot_binary_from_base64("eHh4eOJ4YHvlasoDRc4ZnvRzldoTUgwWSW0bPv7r9xJ074Dn8KzM4yU9fJgTwIT1TsaHmejYopDnVdjxZyrKNra8Keo=", &kp.rdata);

	test_algorithm("GOST", &kp);
	knot_free_key_params(&kp);
#else
	skip_block(14, "GOST: not supported on this system");
#endif

	knot_crypto_cleanup();

	return 0;
}
