/*!
 * \file nsec5.h
 *
 * \author Dimitris Papadopoulos
 *
 * \brief Functions for computation of NSEC5 hashes.
 *
 * \see nsec3.h
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

static inline
uint16_t knot_nsec5_key_tag(const knot_rdataset_t *rrs, size_t pos)
{
    KNOT_RDATASET_CHECK(rrs, pos, return 0);
    return knot_wire_read_u16(knot_rdata_offset(rrs, pos, 0));
}

static inline
uint8_t knot_nsec5_flags(const knot_rdataset_t *rrs, size_t pos)
{
    KNOT_RDATASET_CHECK(rrs, pos, return 0);
    return *knot_rdata_offset(rrs, pos, 2);
}

static inline
uint8_t knot_nsec5_next_length(const knot_rdataset_t *rrs, size_t pos)
{
    KNOT_RDATASET_CHECK(rrs, pos, return 0);
    return *(knot_rdata_offset(rrs, pos, 0) + 3);
}

static inline
void knot_nsec5_next_hashed(const knot_rdataset_t *rrs, size_t pos,
                            uint8_t **name)
{
    KNOT_RDATASET_CHECK(rrs, pos, return);
    //uint8_t salt_size = knot_nsec3_salt_length(rrs, pos);
    *name = knot_rdata_offset(rrs, pos, 4);
}

static inline
void knot_nsec5_bitmap(const knot_rdataset_t *rrs, size_t pos,
                       uint8_t **bitmap, uint16_t *size)
{
    KNOT_RDATASET_CHECK(rrs, pos, return);
    
    /* Bitmap is last, skip all the items. */
    size_t offset = 4; //key tag, flags, next len.
    
    uint8_t next_hashed_size = knot_nsec5_next_length(rrs, pos);
    offset += next_hashed_size; //hash
    
    *bitmap = knot_rdata_offset(rrs, pos, offset);
    const knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
    *size = knot_rdata_rdlen(rr) - offset;
}

/*!
 * \brief Get length of the raw NSEC5 hash.
 *
 * \param algorithm  NSEC5 hash algorithm.
 *
 * \return Length of the hash, 0 for unknown hash algorithm.
 */
static inline size_t knot_nsec5_hash_length(uint8_t algorithm)
{
    if (algorithm == KNOT_NSEC5_ALGORITHM_FDH_SHA256_SHA256) {
        return 32;
    } else {
        return 0;
    }
}

/*!
 * \brief Get length of the NSEC5 hash encoded in Base32 encoding.
 *
 * \param algorithm  NSEC5 hash algorithm.
 *
 * \return Length of the hash, 0 for unknown hash algorithm.
 */
static inline size_t knot_nsec5_hash_b32_length(uint8_t algorithm)
{
    if (algorithm == KNOT_NSEC5_ALGORITHM_FDH_SHA256_SHA256) {
        return 52; //SHA256 -> 256 bits -> padded to 280 -> 280/5 = 56. then remove ===== padding --> 52
    } else {
        return 0;
    }
}

/*!
 * \brief Compute NSEC5 hash for given data.
 *
 * \param[in]  params       NSEC5 parameters.
 * \param[in]  data         Data to compute hash for.
 * \param[in]  size         Size of the data.
 * \param[out] digest       Computed hash.
 * \param[out] digest_size  Size of the computed hash.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_nsec5_hash();

/*! @} */
