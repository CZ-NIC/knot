/*!
 * \file nsec3.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief Functions for computation of NSEC3 hashes.
 *
 * \addtogroup libknot
 * @{
 */
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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "libknot/consts.h"
#include "libknot/rdataset.h"
#include "libknot/rrtype/nsec3param.h"

static inline
uint8_t knot_nsec3_algorithm(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 0);
}

static inline
uint8_t knot_nsec3_flags(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 1);
}

static inline
uint16_t knot_nsec3_iterations(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(knot_rdata_offset(rrs, pos, 2));
}

static inline
uint8_t knot_nsec3_salt_length(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *(knot_rdata_offset(rrs, pos, 0) + 4);
}

static inline
const uint8_t *knot_nsec3_salt(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return NULL);
	return knot_rdata_offset(rrs, pos, 5);
}

static inline
void knot_nsec3_next_hashed(const knot_rdataset_t *rrs, size_t pos,
                            uint8_t **name, uint8_t *name_size)
{
	KNOT_RDATASET_CHECK(rrs, pos, return);
	uint8_t salt_size = knot_nsec3_salt_length(rrs, pos);
	*name_size = *knot_rdata_offset(rrs, pos, 4 + salt_size + 1);
	*name = knot_rdata_offset(rrs, pos, 4 + salt_size + 2);
}

void knot_nsec3_bitmap(const knot_rdataset_t *rrs, size_t pos,
                       uint8_t **bitmap, uint16_t *size);

/*!
 * \brief Get length of the raw NSEC3 hash.
 *
 * \param algorithm  NSEC3 hash algorithm.
 *
 * \return Length of the hash, 0 for unknown hash algorithm.
 */
inline static size_t knot_nsec3_hash_length(uint8_t algorithm)
{
	if (algorithm == KNOT_NSEC3_ALGORITHM_SHA1) {
		return 20;
	} else {
		return 0;
	}
}

/*!
 * \brief Get length of the NSEC3 hash encoded in Base32 encoding.
 *
 * \param algorithm  NSEC3 hash algorithm.
 *
 * \return Length of the hash, 0 for unknown hash algorithm.
 */
inline static size_t knot_nsec3_hash_b32_length(uint8_t algorithm)
{
	if (algorithm == KNOT_NSEC3_ALGORITHM_SHA1) {
		return 32;
	} else {
		return 0;
	}
}

/*!
 * \brief Compute NSEC3 hash for given data.
 *
 * \param[in]  params       NSEC3 parameters.
 * \param[in]  data         Data to compute hash for.
 * \param[in]  size         Size of the data.
 * \param[out] digest       Computed hash.
 * \param[out] digest_size  Size of the computed hash.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec3_hash(const knot_nsec3_params_t *params, const uint8_t *data,
                    size_t size, uint8_t **digest, size_t *digest_size);

/*! @} */
