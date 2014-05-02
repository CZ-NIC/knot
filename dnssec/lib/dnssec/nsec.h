/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * NSEC3 bitmap and hash computation API.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <dnssec/binary.h>

/*!
 * DNSSEC NSEC3 algorithm numbers.
 */
typedef enum dnssec_nsec_algorithm {
	DNSSEC_NSEC3_ALGORITHM_UNKNOWN = 0,
	DNSSEC_NSEC3_ALGORITHM_SHA1 = 1,
} dnssec_nsec3_algorithm_t;

/*!
 * DNSSEC NSEC3 parameters.
 *
 * \todo Disclose this and add setters?
 */
typedef struct dnssec_nsec3_params {
	dnssec_nsec3_algorithm_t algorithm;
	uint8_t flags;
	uint16_t iterations;
	dnssec_binary_t salt;
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

/*!
 * Context for encoding of RR types bitmap used in NSEC/NSEC3.
 */
struct dnssec_nsec_bitmap;
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
