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
/*!
 * \file
 *
 * \brief Functions for computation of NSEC3 hashes.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "libknot/codes.h"
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

uint16_t knot_nsec3_iterations(const knot_rdataset_t *rrs, size_t pos);

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

/*! @} */
