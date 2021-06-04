/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \addtogroup digest
 *
 * \brief Data hashing operations.
 *
 * @{
 */

#pragma once

#include "libdnssec/binary.h"
#include "libdnssec/error.h"

typedef enum {
	DNSSEC_DIGEST_INVALID = 0,
	DNSSEC_DIGEST_SHA384  = 1,
	DNSSEC_DIGEST_SHA512  = 2,
} dnssec_digest_t;

struct dnssec_digest_ctx;
typedef struct dnssec_digest_ctx dnssec_digest_ctx_t;

/*!
 * \brief Initialize digest context.
 *
 * \param algorithm   Hasing algorithm to be used.
 * \param out_ctx     Output: context structure to be initialized.
 *
 * \return DNSSEC_E*
 */
int dnssec_digest_init(dnssec_digest_t algorithm, dnssec_digest_ctx_t **out_ctx);

/*!
 * \brief Digest data.
 *
 * \param ctx    Digest context.
 * \param data   Data to be hashed.
 *
 * \note This function may be invoked repeatedly for single digest context,
 *       hashing all data as concatenated.
 *
 * \return DNSSEC_E*
 *
 * \note If error is returned, the digest context is automatically disposed.
 */
int dnssec_digest(dnssec_digest_ctx_t *ctx, dnssec_binary_t *data);

/*!
 * \brief Finalize digest, dispose digest context and return the hash.
 *
 * \param ctx   Digest context.
 * \param out   Output: computed hash.
 *
 * \return DNSSEC_E*
 */
int dnssec_digest_finish(dnssec_digest_ctx_t *ctx, dnssec_binary_t *out);

/*! @} */
