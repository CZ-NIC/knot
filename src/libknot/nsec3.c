/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "nsec3.h"
#include "common.h"
#include "util/descriptor.h"
#include "util/utils.h"
#include "util/tolower.h"
#include "util/error.h"
#include "util/debug.h"

/*----------------------------------------------------------------------------*/

int knot_nsec3_params_from_wire(knot_nsec3_params_t *params,
                                  const knot_rrset_t *nsec3param)
{
	if (params == NULL || nsec3param == NULL) {
		return KNOT_EBADARG;
	}

	assert(knot_rrset_type(nsec3param) == KNOT_RRTYPE_NSEC3PARAM);
	const knot_rdata_t *rdata = knot_rrset_rdata(nsec3param);

	assert(rdata->count == 4);

	params->algorithm = *(uint8_t *)
	                     (&knot_rdata_item(rdata, 0)->raw_data[1]);
	params->flags = *(uint8_t *)
			(&knot_rdata_item(rdata, 1)->raw_data[1]);
	params->iterations = knot_wire_read_u16(
			(uint8_t *)(knot_rdata_item(rdata, 2)->raw_data + 1));

	params->salt_length =
		((uint8_t *)knot_rdata_item(rdata, 3)->raw_data)[2];

	if (params->salt_length > 0) {
		/* It is called also on reload, so we need to free if exists. */
		if (params->salt != NULL) {
			free(params->salt);
			params->salt = NULL;
		}
		params->salt = (uint8_t *)malloc(params->salt_length);
		CHECK_ALLOC_LOG(params->salt, -1);
		memcpy(params->salt,
		       (uint8_t *)knot_rdata_item(rdata, 3)->raw_data + 3,
		       params->salt_length);
	} else {
		params->salt = NULL;
	}

	dbg_nsec3("Parsed NSEC3PARAM:\n");
	dbg_nsec3("Algorithm: %hu\n", params->algorithm);
	dbg_nsec3("Flags: %hu\n", params->flags);
	dbg_nsec3("Iterations: %hu\n", params->iterations);
	dbg_nsec3("Salt length: %hu\n", params->salt_length);
	dbg_nsec3("Salt: \n");
	if (params->salt != NULL) {
		dbg_nsec3_hex((char *)params->salt,
		                       params->salt_length);
		dbg_nsec3("\n");
	} else {
		dbg_nsec3("none\n");
	}

	return KNOT_EOK;
}

static uint8_t *knot_nsec3_to_lowercase(const uint8_t *data, size_t size)
{
	uint8_t *out = (uint8_t *)malloc(size);
	CHECK_ALLOC_LOG(out, NULL);

	for (int i = 0; i < size; ++i) {
		out[i] = knot_tolower(data[i]);
	}

	return out;
}

/*----------------------------------------------------------------------------*/
#if KNOT_NSEC3_SHA_USE_EVP
int knot_nsec3_sha1(const knot_nsec3_params_t *params,
                      const uint8_t *data, size_t size, uint8_t **digest,
                      size_t *digest_size)
{
	if (digest == NULL || digest_size == NULL || data == NULL) {
		return KNOT_EBADARG;
	}

	uint8_t *salt = params->salt;
	uint8_t salt_length = params->salt_length;
	uint16_t iterations = params->iterations;

	EVP_MD_CTX mdctx;
	EVP_MD_CTX_init(&mdctx);

	*digest = (uint8_t *)malloc(EVP_MD_size(EVP_sha1()));
	if (*digest == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	uint8_t *data_low = knot_nsec3_to_lowercase(data, size);
	if (data_low == NULL) {
		free(*digest);
		return -1;
	}

	const uint8_t *in = data_low;
	unsigned in_size = size;

	int res = 0;

#ifdef KNOT_NSEC3_DEBUG
	unsigned long long total_time = 0;
	unsigned long calls = 0;
	long time = 0;
#endif

	for (int i = 0; i <= iterations; ++i) {
#ifdef KNOT_NSEC3_DEBUG
		perf_begin();
#endif

		EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);

		res = EVP_DigestUpdate(&mdctx, in, in_size);

		if (salt_length > 0) {
			res = EVP_DigestUpdate(&mdctx, salt, salt_length);
		}

		EVP_DigestFinal_ex(&mdctx, *digest, digest_size);
		in = *digest;
		in_size = *digest_size;

#ifdef KNOT_NSEC3_DEBUG
		perf_end(time);
		total_time += time;
		++calls;
#endif

		if (res != 1) {
			dbg_nsec3("Error calculating SHA-1 hash.\n");
			free(data_low);
			free(*digest);
			return -2;
		}
	}

	EVP_MD_CTX_cleanup(&mdctx);

	dbg_nsec3_verb("NSEC3 hashing: calls: %lu, avg time per call: %f."
	               "\n", calls, (double)(total_time) / calls);

	free(data_low);
	return 0;
}

/*----------------------------------------------------------------------------*/
#else

int knot_nsec3_sha1(const knot_nsec3_params_t *params,
                      const uint8_t *data, size_t size, uint8_t **digest,
                      size_t *digest_size)
{
	if (params == NULL || digest == NULL || digest_size == NULL
	    || data == NULL) {
		return KNOT_EBADARG;
	}

	uint8_t *salt = params->salt;
	uint8_t salt_length = params->salt_length;
	uint16_t iterations = params->iterations;

	dbg_nsec3_verb("Hashing: \n");
	dbg_nsec3_verb("  Data: %.*s \n", size, data);
	dbg_nsec3_hex_verb((const char *)data, size);
	dbg_nsec3_verb(" (size %d)\n  Iterations: %u\n", (int)size, iterations);
	dbg_nsec3_verb("  Salt length: %u\n", salt_length);
	dbg_nsec3_verb("  Salt: \n");
	if (salt_length > 0) {
		dbg_nsec3_hex_verb((char *)salt, salt_length);
		dbg_nsec3_verb("\n");
	} else {
		dbg_nsec3_verb("none\n");
	}

	SHA_CTX ctx;

	*digest = (uint8_t *)malloc(SHA_DIGEST_LENGTH);
	if (*digest == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	uint8_t *data_low = knot_nsec3_to_lowercase(data, size);
	if (data_low == NULL) {
		free(*digest);
		return KNOT_ENOMEM;
	}

	const uint8_t *in = data_low;
	unsigned in_size = size;

	int res = 0;

	// other iterations
	for (int i = 0; i <= iterations; ++i) {
		SHA1_Init(&ctx);

		res = SHA1_Update(&ctx, in, in_size);

		if (salt_length > 0) {
			res = SHA1_Update(&ctx, salt, salt_length);
		}

		SHA1_Final(*digest, &ctx);

		in = *digest;
		in_size = SHA_DIGEST_LENGTH;

		if (res != 1) {
			dbg_nsec3("Error calculating SHA-1 hash.\n");
			free(data_low);
			free(*digest);
			return KNOT_ECRYPTO;
		}
	}

	*digest_size = SHA_DIGEST_LENGTH;

	dbg_nsec3_verb("Hash: %.*s\n", *digest_size, *digest);
	dbg_nsec3_hex_verb((const char *)*digest, *digest_size);
	dbg_nsec3_verb("\n");

	free(data_low);
	return KNOT_EOK;
}
#endif

/*----------------------------------------------------------------------------*/

void knot_nsec3_params_free(knot_nsec3_params_t *params)
{
	if (params->salt != NULL) {
		free(params->salt);
	}
}
