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

#include <assert.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "libknot/rrtype/nsec3.h"
#include "libknot/util/tolower.h"
#include "libknot/errcode.h"
#include "common/macros.h"

/*!
 * \brief Compute NSEC3 SHA1 hash.
 *
 * \param[in]  salt         Salt.
 * \param[in]  salt_length  Salt length.
 * \param[in]  iterations   Interation count of the SHA1 computation.
 * \param[in]  data         Input data to be hashed.
 * \param[in]  data_size    Input data size.
 * \param[out] digest       Result of the computation (will be allocated).
 * \param[out] digest_size  Size of the result.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int nsec3_sha1(const uint8_t *salt, uint8_t salt_length,
                      uint16_t iterations, const uint8_t *data,
                      size_t data_size, uint8_t **digest, size_t *digest_size)
{
	assert(data);
	assert(digest);
	assert(digest_size);

	if (salt_length > 0 && !salt) {
		return KNOT_EINVAL;
	}

	EVP_MD_CTX mdctx;
	EVP_MD_CTX_init(&mdctx);

	unsigned int result_size = 0;
	uint8_t *result = (uint8_t *)malloc(EVP_MD_size(EVP_sha1()));
	if (result == NULL) {
		EVP_MD_CTX_cleanup(&mdctx);
		return KNOT_ENOMEM;
	}

	uint8_t *data_low = knot_strtolower(data, data_size);
	if (data_low == NULL) {
		free(result);
		EVP_MD_CTX_cleanup(&mdctx);
		return KNOT_ENOMEM;
	}

	const uint8_t *in = data_low;
	unsigned int in_size = data_size;

	for (int i = 0; i <= iterations; i++) {
		EVP_DigestInit_ex(&mdctx, EVP_sha1(), NULL);

		int success_ops =
			EVP_DigestUpdate(&mdctx, in, in_size) +
			EVP_DigestUpdate(&mdctx, salt, salt_length) +
			EVP_DigestFinal_ex(&mdctx, result, &result_size);

		if (success_ops != 3) {
			EVP_MD_CTX_cleanup(&mdctx);
			free(result);
			free(data_low);
			return KNOT_NSEC3_ECOMPUTE_HASH;
		}

		in = result;
		in_size = result_size;
	}

	EVP_MD_CTX_cleanup(&mdctx);
	free(data_low);

	*digest = result;
	*digest_size = (size_t)result_size;

	return KNOT_EOK;
}

_public_
void knot_nsec3_bitmap(const knot_rdataset_t *rrs, size_t pos,
                       uint8_t **bitmap, uint16_t *size)
{
	KNOT_RDATASET_CHECK(rrs, pos, return);

	/* Bitmap is last, skip all the items. */
	size_t offset = 6; //hash alg., flags, iterations, salt len., hash len.
	offset += knot_nsec3_salt_length(rrs, pos); //salt

	uint8_t *next_hashed = NULL;
	uint8_t next_hashed_size = 0;
	knot_nsec3_next_hashed(rrs, pos, &next_hashed, &next_hashed_size);
	offset += next_hashed_size; //hash

	*bitmap = knot_rdata_offset(rrs, pos, offset);
	const knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
	*size = knot_rdata_rdlen(rr) - offset;
}

_public_
int knot_nsec3_hash(const knot_nsec3_params_t *params, const uint8_t *data,
                    size_t data_size, uint8_t **digest, size_t *digest_size)
{
	if (!params || !data || !digest || !digest_size) {
		return KNOT_EINVAL;
	}

	if (params->algorithm != 1) {
		return KNOT_DNSSEC_ENOTSUP;
	}

	return nsec3_sha1(params->salt, params->salt_length, params->iterations,
	                  data, data_size, digest, digest_size);
}
