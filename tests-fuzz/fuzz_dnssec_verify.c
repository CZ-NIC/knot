/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdint.h>
#include <stdlib.h>

#include "libknot/dnssec/binary.h"
#include "libknot/dnssec/crypto.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/sample_keys.h"
#include "libknot/dnssec/sign.h"
#include "libknot/errcode.h"

#define MAX_INPUT_SIZE (16 * 1024)

static const key_parameters_t *const sample_keys[] = {
	&SAMPLE_RSA1024_SHA256_KEY,
	&SAMPLE_ECDSA_P256_SHA256_KEY,
	&SAMPLE_ED25519_KEY,
	&SAMPLE_ED448_KEY,
};

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;

	dnssec_crypto_init();
	return 0;
}

static void fuzz_dnskey(const uint8_t *data, size_t size)
{
	static const uint8_t owner[] = "\x07" "example";
	dnssec_binary_t rdata = { .size = size, .data = (uint8_t *)data };
	dnssec_key_t *key = NULL;

	if (dnssec_key_new(&key) != KNOT_EOK) {
		return;
	}

	if (dnssec_key_set_rdata(key, &rdata) == KNOT_EOK) {
		dnssec_binary_t ds = { 0 };
		char *keyid = NULL;

		dnssec_key_set_dname(key, owner);
		dnssec_key_get_keytag(key);
		dnssec_key_get_keyid(key, &keyid);
		free(keyid);

		if (dnssec_key_create_ds(key, DNSSEC_KEY_DIGEST_SHA256, &ds) == KNOT_EOK) {
			dnssec_binary_free(&ds);
		}
	}

	dnssec_key_free(key);
}

static void fuzz_signature(const key_parameters_t *sample, const uint8_t *data,
                           size_t size, size_t message_size)
{
	size_t first_size = message_size / 2;
	dnssec_binary_t first = { .size = first_size, .data = (uint8_t *)data };
	dnssec_binary_t second = {
		.size = message_size - first_size,
		.data = (uint8_t *)data + first_size
	};
	dnssec_binary_t signature = {
		.size = size - message_size,
		.data = (uint8_t *)data + message_size
	};
	dnssec_key_t *key = NULL;
	dnssec_sign_ctx_t *ctx = NULL;

	if (dnssec_key_new(&key) != KNOT_EOK ||
	    dnssec_key_set_rdata(key, &sample->rdata) != KNOT_EOK ||
	    dnssec_sign_new(&ctx, key) != KNOT_EOK) {
		goto cleanup;
	}

	if (first.size > 0) {
		dnssec_sign_add(ctx, &first);
	}
	if (second.size > 0) {
		dnssec_sign_add(ctx, &second);
	}
	dnssec_sign_verify(ctx, false, &signature);

cleanup:
	dnssec_sign_free(ctx);
	dnssec_key_free(key);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 4 || size > MAX_INPUT_SIZE) {
		return 0;
	}

	if ((data[0] % 5) == 0) {
		fuzz_dnskey(data + 1, size - 1);
	} else {
		const key_parameters_t *sample = sample_keys[(data[0] % 5) - 1];
		size_t payload_size = size - 3;
		size_t message_size = ((((size_t)data[1] << 8) | data[2]) %
		                       (payload_size + 1));
		fuzz_signature(sample, data + 3, payload_size, message_size);
	}

	return 0;
}
