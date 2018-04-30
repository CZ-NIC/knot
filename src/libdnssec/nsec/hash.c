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

#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <openssl/evp.h>
#include <string.h>

#include "libdnssec/error.h"
#include "libdnssec/nsec.h"
#include "libdnssec/shared/shared.h"

static int openssl_nsec3_hash(gnutls_digest_algorithm_t algorithm, int iterations,
			      const dnssec_binary_t *salt, const dnssec_binary_t *data,
			      dnssec_binary_t *hash)
{
	assert(salt);
	assert(data);
	assert(hash);

	const EVP_MD *md = EVP_sha1();

	int hash_size = EVP_MD_size(md);
	if (hash_size <= 0) {
		return DNSSEC_NSEC3_HASHING_ERROR;
	}

	int r = dnssec_binary_resize(hash, hash_size);
	if (r != DNSSEC_EOK) {
		return r;
	}

	const uint8_t *in = data->data;
	size_t in_size = data->size;

	for (int i = 0; i <= iterations; i++) {
		EVP_MD_CTX ctx;
		r = EVP_DigestInit(&ctx, md);
		if (r != 1) {
			return DNSSEC_NSEC3_HASHING_ERROR;
		}

		r = EVP_DigestUpdate(&ctx, in, in_size);
		if (r != 1) {
			return DNSSEC_NSEC3_HASHING_ERROR;
		}

		r = EVP_DigestUpdate(&ctx, salt->data, salt->size);
		if (r != 1) {
			return DNSSEC_NSEC3_HASHING_ERROR;
		}

		unsigned int size = hash->size;
		r = EVP_DigestFinal(&ctx, hash->data, &size);
		if (r != 1 || size != hash->size) {
			return DNSSEC_NSEC3_HASHING_ERROR;
		}

		in = hash->data;
		in_size = hash->size;
	}

	return DNSSEC_EOK;
}

/*!
 * Compute NSEC3 hash for given data and algorithm.
 *
 * \see RFC 5155
 *
 * \todo Input data should be converted to lowercase.
 */
__attribute__((unused))
static int nsec3_hash(gnutls_digest_algorithm_t algorithm, int iterations,
		      const dnssec_binary_t *salt, const dnssec_binary_t *data,
		      dnssec_binary_t *hash)
{
	assert(salt);
	assert(data);
	assert(hash);

	int hash_size = gnutls_hash_get_len(algorithm);
	if (hash_size <= 0) {
		return DNSSEC_NSEC3_HASHING_ERROR;
	}

	int result = dnssec_binary_resize(hash, hash_size);
	if (result != DNSSEC_EOK) {
		return result;
	}

	_cleanup_hash_ gnutls_hash_hd_t digest = NULL;
	result = gnutls_hash_init(&digest, algorithm);
	if (result < 0) {
		return DNSSEC_NSEC3_HASHING_ERROR;
	}

	const uint8_t *in = data->data;
	size_t in_size = data->size;

	for (int i = 0; i <= iterations; i++) {
		result = gnutls_hash(digest, in, in_size);
		if (result < 0) {
			return DNSSEC_NSEC3_HASHING_ERROR;
		}

		result = gnutls_hash(digest, salt->data, salt->size);
		if (result < 0) {
			return DNSSEC_NSEC3_HASHING_ERROR;
		}

		gnutls_hash_output(digest, hash->data);

		in = hash->data;
		in_size = hash->size;
	}

	return DNSSEC_EOK;
}

/*!
 * Get GnuTLS digest algorithm from DNSSEC algorithm number.
 */
static gnutls_digest_algorithm_t algorithm_d2g(dnssec_nsec3_algorithm_t dnssec)
{
	switch (dnssec) {
	case DNSSEC_NSEC3_ALGORITHM_SHA1: return GNUTLS_DIG_SHA1;
	default:                          return GNUTLS_DIG_UNKNOWN;
	}
}

/* -- public API ----------------------------------------------------------- */

/*!
 * Compute NSEC3 hash for given data.
 */
_public_
int dnssec_nsec3_hash(const dnssec_binary_t *data,
		      const dnssec_nsec3_params_t *params,
		      dnssec_binary_t *hash)
{
	if (!data || !params || !hash) {
		return DNSSEC_EINVAL;
	}

	gnutls_digest_algorithm_t algorithm = algorithm_d2g(params->algorithm);
	if (algorithm == GNUTLS_DIG_UNKNOWN) {
		return DNSSEC_INVALID_NSEC3_ALGORITHM;
	}

	return openssl_nsec3_hash(algorithm, params->iterations, &params->salt, data, hash);
}

/*!
 * Get length of raw NSEC3 hash for a given algorithm.
 */
_public_
size_t dnssec_nsec3_hash_length(dnssec_nsec3_algorithm_t algorithm)
{
	gnutls_digest_algorithm_t gnutls = algorithm_d2g(algorithm);
	if (gnutls == GNUTLS_DIG_UNKNOWN) {
		return 0;
	}

	return gnutls_hash_get_len(gnutls);
}
