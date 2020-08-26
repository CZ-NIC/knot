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
 * \addtogroup nsec
 *
 * \brief NSEC bitmap and NSEC3 hash computation API.
 *
 * The module provides interface for computation of NSEC3 hashes and for
 * construction of bit maps used in NSEC and NSEC3 records.
 *
 * @{
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <libdnssec/binary.h>

/*!
 * DNSSEC NSEC3 algorithm numbers.
 */
typedef enum dnssec_nsec_algorithm {
	DNSSEC_NSEC3_ALGORITHM_UNKNOWN = 0,
	DNSSEC_NSEC3_ALGORITHM_SHA1 = 1,
} dnssec_nsec3_algorithm_t;

/*!
 * DNSSEC NSEC3 parameters.
 */
typedef struct dnssec_nsec3_params {
	dnssec_nsec3_algorithm_t algorithm; /*!< NSEC3 algorithm. */
	uint8_t flags;                      /*!< NSEC3 flags. */
	uint16_t iterations;                /*!< NSEC3 iterations count. */
	dnssec_binary_t salt;               /*!< NSEC3 salt. */
} dnssec_nsec3_params_t;

/*!
 * Free NSEC3 parameters.
 */
void dnssec_nsec3_params_free(dnssec_nsec3_params_t *params);

/*!
 * Parse NSEC3 parameters from NSEC3PARAM RDATA.
 *
 * \param params  Output parameters.
 * \param rdata   NSEC3PARAM RDATA.
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_nsec3_params_from_rdata(dnssec_nsec3_params_t *params,
				   const dnssec_binary_t *rdata);

/*!
 * Check if NSEC3 parameters match.
 *
 * \param params1  NSEC3 parameters 1.
 * \param params2  NSEC3 parameters 2.
 *
 * \return True if match or if both NULL.
 */
bool dnssec_nsec3_params_match(const dnssec_nsec3_params_t *params1,
			       const dnssec_nsec3_params_t *params2);

/*!
 * Check whether a given NSEC bitmap contains a given RR type.
 *
 * \param bitmap  Bitmap of an NSEC record.
 * \param size    Size of the bitmap.
 * \param type    RR type to check for.
 *
 * \return true if bitmap contains type, false otherwise.
 */
bool dnssec_nsec_bitmap_contains(const uint8_t *bitmap, uint16_t size, uint16_t type);

/*!
 * Compute NSEC3 hash for given data.
 *
 * \todo Input data must be converted to lowercase!
 *
 * \param[in]  data    Data to be hashed (usually domain name).
 * \param[in]  params  NSEC3 parameters.
 * \param[out] hash    Computed hash (will be allocated or resized).
 *
 * \return Error code, DNSSEC_EOK if successful.
 */
int dnssec_nsec3_hash(const dnssec_binary_t *data,
		      const dnssec_nsec3_params_t *params,
		      dnssec_binary_t *hash);

/*!
 * Get length of raw NSEC3 hash for a given algorithm.
 *
 * \param algorithm  NSEC3 algorithm number.
 *
 * \return Length of raw NSEC3 hash, zero on error.
 */
size_t dnssec_nsec3_hash_length(dnssec_nsec3_algorithm_t algorithm);

struct dnssec_nsec_bitmap;

/*!
 * Context for encoding of RR types bitmap used in NSEC/NSEC3.
 */
typedef struct dnssec_nsec_bitmap dnssec_nsec_bitmap_t;

/*!
 * Allocate new bit map encoding context.
 */
dnssec_nsec_bitmap_t *dnssec_nsec_bitmap_new(void);

/*!
 * Clear existing bit map encoding context.
 */
void dnssec_nsec_bitmap_clear(dnssec_nsec_bitmap_t *bitmap);

/*!
 * Free bit map encoding context.
 */
void dnssec_nsec_bitmap_free(dnssec_nsec_bitmap_t *bitmap);

/*!
 * Add one RR type into the bitmap.
 */
void dnssec_nsec_bitmap_add(dnssec_nsec_bitmap_t *bitmap, uint16_t type);

/*!
 * Compute the size of the encoded bitmap.
 */
size_t dnssec_nsec_bitmap_size(const dnssec_nsec_bitmap_t *bitmap);

/*!
 * Write encoded bitmap into the given buffer.
 */
void dnssec_nsec_bitmap_write(const dnssec_nsec_bitmap_t *bitmap, uint8_t *output);

/*! @} */
