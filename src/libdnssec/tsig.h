/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \file
 *
 * \addtogroup tsig
 *
 * \brief Low-level TSIG signing API.
 *
 * @{
 */

#pragma once

#include <stdint.h>

#include <libdnssec/binary.h>

/*!
 * TSIG algorithms.
 *
 * \note The numeric values are library specific.
 */
typedef enum dnssec_tsig_algorithm {
	DNSSEC_TSIG_UNKNOWN = 0,
	DNSSEC_TSIG_HMAC_MD5,
	DNSSEC_TSIG_HMAC_SHA1,
	DNSSEC_TSIG_HMAC_SHA224,
	DNSSEC_TSIG_HMAC_SHA256,
	DNSSEC_TSIG_HMAC_SHA384,
	DNSSEC_TSIG_HMAC_SHA512
} dnssec_tsig_algorithm_t;

/*!
 * Get TSIG algorithm number from domain name.
 *
 * \see https://www.iana.org/assignments/tsig-algorithm-names/tsig-algorithm-names.xhtml
 *
 * \param dname  Domain name of the algorithm (e.g., 0x0b hmac-sha256).
 *
 * \return TSIG algorithm.
 */
dnssec_tsig_algorithm_t dnssec_tsig_algorithm_from_dname(const uint8_t *dname);

/*!
 * Get a domain name of the TSIG algorithm.
 *
 * \param algorithm  TSIG algorithm.
 *
 * \return Domain name of the TSIG algorithm.
 */
const uint8_t *dnssec_tsig_algorithm_to_dname(dnssec_tsig_algorithm_t algorithm);

/*!
 * Get TSIG algorithm from a MAC name.
 *
 * \param name  MAC name (e.g., hmac-sha256).
 *
 * \return TSIG algorithm.
 */
dnssec_tsig_algorithm_t dnssec_tsig_algorithm_from_name(const char *name);

/*!
 * Get MAC name from a TSIG algorithm.
 *
 * \param algorithm  TSIG algorithm.
 *
 * \return MAC name of the TSIG algorithm.
 */
const char *dnssec_tsig_algorithm_to_name(dnssec_tsig_algorithm_t algorithm);

/*!
 * Get optimal size of a TSIG algorithm.
 */
int dnssec_tsig_optimal_key_size(dnssec_tsig_algorithm_t algorithm);

struct dnssec_tsig_ctx;

/*!
 * TSIG signing context.
 */
typedef struct dnssec_tsig_ctx dnssec_tsig_ctx_t;

/*!
 * Create new TSIG signing context.
 *
 * \param[out] ctx        Resulting TSIG context.
 * \param[in]  algorithm  TSIG algorithm.
 * \param[in]  key        Shared key to be used for signing.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_tsig_new(dnssec_tsig_ctx_t **ctx, dnssec_tsig_algorithm_t algorithm,
		    const dnssec_binary_t *key);

/*!
 * Free the TSIG signing context.
 *
 * \param ctx  TSIG signing context to be freed.
 */
void dnssec_tsig_free(dnssec_tsig_ctx_t *ctx);

/*!
 * Add data to be signed by TSIG.
 *
 * \param ctx   TSIG signing context.
 * \param data  Data to be signed.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_tsig_add(dnssec_tsig_ctx_t *ctx, const dnssec_binary_t *data);

/*!
 * Get size of the TSIG signature for given signing context.
 *
 * \param ctx  TSIG signing context.
 *
 * \return The size of the TSIG signature.
 */
size_t dnssec_tsig_size(dnssec_tsig_ctx_t *ctx);

/*!
 * Get size of the TSIG signature for given algorithm.
 *
 * \param algorithm  TSIG algorithm.
 *
 * \return The size of the TSIG signature.
 */
size_t dnssec_tsig_algorithm_size(dnssec_tsig_algorithm_t algorithm);

/*!
 * Write TSIG signature.
 *
 * \param[in]  ctx  TSIG signing context.
 * \param[out] mac  Resulting TSIG signature.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_tsig_write(dnssec_tsig_ctx_t *ctx, uint8_t *mac);

/*! @} */
