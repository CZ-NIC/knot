/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <string.h>

#include "libknot/dnssec/error.h"
#include "libknot/dnssec/nsec.h"
#include "libknot/dnssec/shared/shared.h"

/*!
 * Compute NSEC3 hash for given data and algorithm.
 *
 * \see RFC 5155
 *
 * \todo Input data should be converted to lowercase.
 */
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
	if (result != KNOT_EOK) {
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

	return KNOT_EOK;
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
		return KNOT_EINVAL;
	}

	gnutls_digest_algorithm_t algorithm = algorithm_d2g(params->algorithm);
	if (algorithm == GNUTLS_DIG_UNKNOWN) {
		return DNSSEC_INVALID_NSEC3_ALGORITHM;
	}

	return nsec3_hash(algorithm, params->iterations, &params->salt, data, hash);
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
