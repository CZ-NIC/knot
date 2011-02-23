#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

#include <sys/time.h>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

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
	params->salt = (uint8_t *)malloc(params->salt_length);

	CHECK_ALLOC_LOG(params->salt, -1);

	memcpy(params->salt, dnslib_rdata_item(rdata, 3)->raw_data + 1,
	       params->salt_length);

	printf("Parsed NSEC3PARAM:\n");
	printf("Algorithm: %hu\n", params->algorithm);
	printf("Flags: %hu\n", params->flags);
	printf("Iterations: %hu\n", params->iterations);
	printf("Salt length: %hu\n", params->salt_length);
	printf("Salt: ");
	hex_print((char *)params->salt, params->salt_length);
	printf("\n");

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_nsec3_sha1(const dnslib_nsec3_params_t *params, const uint8_t *data,
                      size_t size, uint8_t **digest, size_t *digest_size)
{
	assert(digest != NULL);
	assert(digest_size != NULL);

	unsigned long long total_time = 0;
	unsigned long calls = 0;

	if (data == NULL) {
		return -3;
	}

	uint8_t *salt = params->salt;
	uint8_t salt_length = params->salt_length;
	uint16_t iterations = params->iterations;

	int dig_size = gnutls_hash_get_len(GNUTLS_DIG_SHA1);

	void *digest_old = malloc(dig_size);
	CHECK_ALLOC_LOG(digest_old, -1);

	size_t to_hash_size = size + salt_length;

	void *to_hash = malloc(to_hash_size);
	if (to_hash == NULL) {
		ERR_ALLOC_FAILED;
		free(digest_old);
		return -1;
	}

	memcpy(to_hash, data, size);
	memcpy(to_hash + size, salt, salt_length);

	int res = 0;
	long time = 0;
	// first iteration
	perf_begin();
	res = gnutls_hash_fast(GNUTLS_DIG_SHA1, to_hash, to_hash_size,
	                       digest_old);
	perf_end(time);
	total_time += time;
	++calls;

	if (res != GNUTLS_E_SUCCESS) {
		log_error("Error calculating SHA-1 hash.\n");
		free(digest_old);
		free(to_hash);
		return -2;
	}

	void *digest_new = malloc(dig_size);
	if (digest_new == NULL) {
		ERR_ALLOC_FAILED;
		free(digest_old);
		return -1;
	}

	to_hash_size = dig_size + salt_length;
	free(to_hash);
	to_hash = malloc(to_hash_size);
	if (to_hash == NULL) {
		ERR_ALLOC_FAILED;
		free(digest_old);
		free(digest_new);
		return -1;
	}

	//printf("Iterations: %d\n", iterations);

	// other iterations
	for (int i = 0; i < iterations; ++i) {

		memcpy(to_hash, digest_old, dig_size);
		memcpy(to_hash + dig_size, salt, salt_length);

		perf_begin();
		res = gnutls_hash_fast(GNUTLS_DIG_SHA1, to_hash, to_hash_size,
		                       digest_new);
		perf_end(time);

		if (res != GNUTLS_E_SUCCESS) {
			log_error("Error calculating SHA-1 hash.\n");
			free(digest_old);
			free(digest_new);
			free(to_hash);
			return -2;
		}

		// copy the new digest to the old one and repeat
		memcpy(digest_old, digest_new, dig_size);


		total_time += time;
		++calls;
	}

	free(digest_new);
	free(to_hash);

	*digest = digest_old;
	*digest_size = dig_size;

//	gnutls_hash_deinit(context, NULL);

//	printf("NSEC3 hashing: calls: %lu, avg time per call: %f.\n",
//	       calls, (double)(total_time) / calls);

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_nsec3_sha1_2(const dnslib_nsec3_params_t *params,
                        const uint8_t *data, size_t size, uint8_t **digest,
                        size_t *digest_size)
{
	assert(digest != NULL);
	assert(digest_size != NULL);

	unsigned long long total_time = 0;
	unsigned long calls = 0;

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
	long time = 0;

	//printf("Iterations: %d\n", iterations);

	// other iterations
	for (int i = 0; i <= iterations; ++i) {
		perf_begin();

		EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);

		res = EVP_DigestUpdate(&mdctx, in, in_size);

		if (salt_length > 0) {
			res = EVP_DigestUpdate(&mdctx, salt, salt_length);
		}

		EVP_DigestFinal_ex(&mdctx, *digest, digest_size);
		in = *digest;
		in_size = *digest_size;

		perf_end(time);

		if (res != 1) {
			log_error("Error calculating SHA-1 hash.\n");
			return -2;
		}

		total_time += time;
		++calls;
	}

	EVP_MD_CTX_cleanup(&mdctx);

//	printf("NSEC3 hashing: calls: %lu, avg time per call: %f.\n",
//	       calls, (double)(total_time) / calls);

	return 0;
}

/*----------------------------------------------------------------------------*/

int dnslib_nsec3_sha1_3(const dnslib_nsec3_params_t *params,
                        const uint8_t *data, size_t size, uint8_t **digest,
                        size_t *digest_size)
{
	assert(digest != NULL);
	assert(digest_size != NULL);

	unsigned long long total_time = 0;
	unsigned long calls = 0;

	if (data == NULL) {
		return -3;
	}

	uint8_t *salt = params->salt;
	uint8_t salt_length = params->salt_length;
	uint16_t iterations = params->iterations;

	SHA_CTX ctx;
	//EVP_MD_CTX_init(&mdctx);

	*digest = (uint8_t *)malloc(SHA_DIGEST_LENGTH);
	if (*digest == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	const uint8_t *in = data;
	unsigned in_size = size;

	int res = 0;
	long time = 0;

	//printf("Iterations: %d\n", iterations);

	// other iterations
	for (int i = 0; i <= iterations; ++i) {
		perf_begin();

		SHA1_Init(&ctx);

		res = SHA1_Update(&ctx, in, in_size);

		if (salt_length > 0) {
			res = SHA1_Update(&ctx, salt, salt_length);
		}

		SHA1_Final(*digest, &ctx);

		in = *digest;
		in_size = SHA_DIGEST_LENGTH;

		perf_end(time);

		if (res != 1) {
			log_error("Error calculating SHA-1 hash.\n");
			return -2;
		}

		total_time += time;
		++calls;
	}

//	EVP_MD_CTX_cleanup(&mdctx);

//	printf("NSEC3 hashing: calls: %lu, avg time per call: %f.\n",
//	       calls, (double)(total_time) / calls);

	*digest_size = SHA_DIGEST_LENGTH;

	return 0;
}
