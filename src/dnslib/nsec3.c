#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

#include "nsec3.h"
#include "common.h"
#include "descriptor.h"
#include "utils.h"

/*----------------------------------------------------------------------------*/

int dnslib_nsec3_params_from_wire(dnslib_nsec3_params_t *params,
                                  const dnslib_rrset_t *nsec3param)
{
	assert(dnslib_rrset_type(nsec3param) == DNSLIB_RRTYPE_NSEC3PARAM);
	const dnslib_rdata_t *rdata = dnslib_rrset_rdata(nsec3param);

	assert(rdata->count == 4);

	params->algorithm = *(uint8_t *)
	                     (&dnslib_rdata_item(rdata, 0)->raw_data[1]);
	params->flags = *(uint8_t *)
			(&dnslib_rdata_item(rdata, 1)->raw_data[1]);
	params->iterations = dnslib_wire_read_u16(
			(uint8_t *)(dnslib_rdata_item(rdata, 2)->raw_data + 1));
	params->salt_length =
		((uint8_t *)(dnslib_rdata_item(rdata, 3)->raw_data))[1];
	if (params->salt_length > 0) {
		params->salt = (uint8_t *)malloc(params->salt_length);
	}

	CHECK_ALLOC_LOG(params->salt, -1);

	memcpy(params->salt, dnslib_rdata_item(rdata, 3)->raw_data + 1,
	       params->salt_length);

	debug_dnslib_nsec3("Parsed NSEC3PARAM:\n");
	debug_dnslib_nsec3("Algorithm: %hu\n", params->algorithm);
	debug_dnslib_nsec3("Flags: %hu\n", params->flags);
	debug_dnslib_nsec3("Iterations: %hu\n", params->iterations);
	debug_dnslib_nsec3("Salt length: %hu\n", params->salt_length);
	debug_dnslib_nsec3("Salt: ");
	debug_dnslib_nsec3_hex((char *)params->salt, params->salt_length);
	debug_dnslib_nsec3("\n");

	return 0;
}

/*----------------------------------------------------------------------------*/
#if DNSLIB_NSEC3_SHA_USE_EVP
int dnslib_nsec3_sha1(const dnslib_nsec3_params_t *params,
                      const uint8_t *data, size_t size, uint8_t **digest,
                      size_t *digest_size)
{
	assert(digest != NULL);
	assert(digest_size != NULL);

	if (data == NULL) {
		return -3;
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

	const uint8_t *in = data;
	unsigned in_size = size;

	int res = 0;

#ifdef DNSLIB_NSEC3_DEBUG
	unsigned long long total_time = 0;
	unsigned long calls = 0;
	long time = 0;
#endif

	for (int i = 0; i <= iterations; ++i) {
#ifdef DNSLIB_NSEC3_DEBUG
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

#ifdef DNSLIB_NSEC3_DEBUG
		perf_end(time);
		total_time += time;
		++calls;
#endif

		if (res != 1) {
			log_error("Error calculating SHA-1 hash.\n");
			return -2;
		}
	}

	EVP_MD_CTX_cleanup(&mdctx);

	debug_dnslib_nsec3("NSEC3 hashing: calls: %lu, avg time per call: %f."
	                   "\n", calls, (double)(total_time) / calls);

	return 0;
}

/*----------------------------------------------------------------------------*/
#else
int dnslib_nsec3_sha1(const dnslib_nsec3_params_t *params,
                      const uint8_t *data, size_t size, uint8_t **digest,
                      size_t *digest_size)
{
	assert(digest != NULL);
	assert(digest_size != NULL);

	if (data == NULL) {
		return -3;
	}

	uint8_t *salt = params->salt;
	uint8_t salt_length = params->salt_length;
	uint16_t iterations = params->iterations;

	SHA_CTX ctx;

	*digest = (uint8_t *)malloc(SHA_DIGEST_LENGTH);
	if (*digest == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	const uint8_t *in = data;
	unsigned in_size = size;

	int res = 0;

#ifdef DNSLIB_NSEC3_DEBUG
	long time = 0;
	unsigned long long total_time = 0;
	unsigned long calls = 0;
#endif

	// other iterations
	for (int i = 0; i <= iterations; ++i) {
#ifdef DNSLIB_NSEC3_DEBUG
		perf_begin();
#endif

		SHA1_Init(&ctx);

		res = SHA1_Update(&ctx, in, in_size);

		if (salt_length > 0) {
			res = SHA1_Update(&ctx, salt, salt_length);
		}

		SHA1_Final(*digest, &ctx);

		in = *digest;
		in_size = SHA_DIGEST_LENGTH;

#ifdef DNSLIB_NSEC3_DEBUG
		perf_end(time);
		total_time += time;
		++calls;
#endif

		if (res != 1) {
			log_error("Error calculating SHA-1 hash.\n");
			return -2;
		}
	}

	debug_dnslib_nsec3("NSEC3 hashing: calls: %lu, avg time per call: %f."
	                   "\n", calls, (double)(total_time) / calls);

	*digest_size = SHA_DIGEST_LENGTH;

	return 0;
}
#endif

/*----------------------------------------------------------------------------*/

void dnslib_nsec3_params_free(dnslib_nsec3_params_t *params)
{
	if (params->salt != NULL) {
		free(params->salt);
	}
}
