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

#include "tests/libknot/dnssec_sign_tests.h"
#include "common/errcode.h"
#include "libknot/dnssec/sign.h"

static int dnssec_sign_tests_count(int argc, char *argv[]);
static int dnssec_sign_tests_run(int argc, char *argv[]);

#ifdef OPENSSL_NO_ECDSA
static const int ecdsa_supported = 0;
#else
static const int ecdsa_supported = 1;
#endif

unit_api dnssec_sign_tests_api = {
	"libknot/dnssec/sign",
	&dnssec_sign_tests_count,
	&dnssec_sign_tests_run
};

static void test_algorithm(const char *alg, const knot_key_params_t *kp)
{
	int result;

	knot_dnssec_key_t key = { 0 };
	result = knot_dnssec_key_from_params(kp, &key);
	ok(result == KNOT_EOK, "%s: create key from params", alg);

	knot_dnssec_sign_context_t *ctx;
	ctx = knot_dnssec_sign_init(&key);
	ok(ctx != NULL, "%s: create signing context", alg);

	skip(ctx == NULL, 12, "%s: required test failed", alg);

	size_t sig_size = knot_dnssec_sign_size(&key);
	ok(sig_size > 0, "%s: get signature size", alg);

	uint8_t *sig = malloc(sig_size);
	assert(sig != NULL);

	result = knot_dnssec_sign_add(ctx, (uint8_t *)"test", 4);
	ok(result == KNOT_EOK, "%s: add data A", alg);

	result = knot_dnssec_sign_new(ctx);
	ok(result == KNOT_EOK, "%s: restart context", alg);

	result = knot_dnssec_sign_add(ctx, (uint8_t *)"hello", 5);
	ok(result == KNOT_EOK, "%s: add data B", alg);

	result = knot_dnssec_sign_add(ctx, (uint8_t *)"dns", 3);
	ok(result == KNOT_EOK, "%s: add data C", alg);

	result = knot_dnssec_sign_write(ctx, sig);
	ok(result == KNOT_EOK, "%s: write signature", alg);

	result = knot_dnssec_sign_new(ctx);
	ok(result == KNOT_EOK, "%s: restart context", alg);

	result = knot_dnssec_sign_add(ctx, (uint8_t *)"wrong", 5);
	ok(result == KNOT_EOK, "%s: add data D", alg);

	result = knot_dnssec_sign_verify(ctx, sig, sig_size);
	ok(result == KNOT_DNSSEC_EINVALID_SIGNATURE, "%s: verify invalid signature", alg);

	result = knot_dnssec_sign_new(ctx);
	ok(result == KNOT_EOK, "%s: restart context", alg);

	result = knot_dnssec_sign_add(ctx, (uint8_t *)"hellodns", 8);
	ok(result == KNOT_EOK, "%s: add data B + C", alg);

	result = knot_dnssec_sign_verify(ctx, sig, sig_size);
	ok(result == KNOT_EOK, "%s: verify valid signature", alg);

	endskip;

	knot_dnssec_sign_free(ctx);
	knot_dnssec_key_free(&key);
}

static int dnssec_sign_tests_count(int argc, char *argv[])
{
	return 42;
}

static int dnssec_sign_tests_run(int argc, char *argv[])
{
	knot_key_params_t kp = { 0 };

	// RSA

	kp.name = knot_dname_from_str("example.com.", 12);
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

	kp.name = knot_dname_from_str("example.com.", 12);
	kp.algorithm = 6;
	knot_binary_from_base64("u7tr4jc7CH0+r2muVEZyjYu7hpMrQ1dHGAMv7hr5dBFYzkutfdBmDSW4C+qxaXWo14gi+jJ8XqFqQ7rQn23DdQ==", &kp.prime);
	knot_binary_from_base64("tgZ5X6pFoCOM2NzfiAYVG1434Mk=", &kp.subprime);
	knot_binary_from_base64("bHidtFIFYAHXp7ZxTFd6poJJG8brqO9eyJygvYSFCej/FGDqhF2TsboVvS/evW/qTaSvhkd/aiDg5eAfu1HvrQ==", &kp.base);
	knot_binary_from_base64("FiTBDsbFDNTw7IrhPeVbzM0DMmI=", &kp.private_value);
	knot_binary_from_base64("G1pX04Bcew8wyHsmno4Q0tNdmBLlaEdbqvQ03W5XVXUM6MPrtzxgc6jdOogqZsvGK4c+FbThBu42Z1t/ioQr8A==", &kp.public_value);

	test_algorithm("DSA", &kp);
	knot_free_key_params(&kp);

	// ECDSA

	skip(!ecdsa_supported, 14, "ECDSA: not supported on this system");

	kp.name = knot_dname_from_str("example.com", 12);
	kp.algorithm = 13;
	knot_binary_from_base64("1N/PvpB8jZcvv+zr3Q987RKK1cBxDKULzEc5F/nnpSg=", &kp.private_key);
	knot_binary_from_base64("fe3oR+S8crl9AwayWFZwJ8wXpDeg1uiXZ/X0MYBvyvj1lfuJDXawUjKuzYKLAPEVH1jt8XbM5nTTlVXUsDebVA==", &kp.rdata);

	test_algorithm("ECDSA", &kp);
	knot_free_key_params(&kp);

	endskip;

	return 0;
}
