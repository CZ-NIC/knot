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
/*!
 * \file
 *
 * \addtogroup rrtype
 * @{
 */

#pragma once

#include "libknot/rdataset.h"
#include "libknot/wire.h"

/*!
 * \brief NSEC3 rdata constants.
 */
#define KNOT_NSEC3_ALGORITHM_SHA1	1
#define KNOT_NSEC3_FLAG_OPT_OUT		1

static inline
uint8_t knot_nsec3_algorithm(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos);
	return *knot_rdata_offset(rrs, pos, 0);
}

static inline
uint8_t knot_nsec3_flags(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos);
	return *knot_rdata_offset(rrs, pos, 1);
}

static inline
uint16_t knot_nsec3_iterations(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos);
	return knot_wire_read_u16(knot_rdata_offset(rrs, pos, 2));
}

static inline
uint8_t knot_nsec3_salt_length(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos);
	return *(knot_rdata_offset(rrs, pos, 0) + 4);
}

static inline
const uint8_t *knot_nsec3_salt(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos);
	return knot_rdata_offset(rrs, pos, 5);
}

static inline
void knot_nsec3_next_hashed(const knot_rdataset_t *rrs, size_t pos,
                            uint8_t **name, uint8_t *name_size)
{
	KNOT_RDATASET_CHECK(rrs, pos);
	uint8_t salt_size = knot_nsec3_salt_length(rrs, pos);
	*name_size = *knot_rdata_offset(rrs, pos, 4 + salt_size + 1);
	*name = knot_rdata_offset(rrs, pos, 4 + salt_size + 2);
}

static inline
void knot_nsec3_bitmap(const knot_rdataset_t *rrs, size_t pos,
                       uint8_t **bitmap, uint16_t *size)
{
	KNOT_RDATASET_CHECK(rrs, pos);

	/* Bitmap is last, skip all the items. */
	size_t offset = 6; //hash alg., flags, iterations, salt len., hash len.
	offset += knot_nsec3_salt_length(rrs, pos); //salt

	uint8_t *next_hashed = NULL;
	uint8_t next_hashed_size = 0;
	knot_nsec3_next_hashed(rrs, pos, &next_hashed, &next_hashed_size);
	offset += next_hashed_size; //hash

	*bitmap = knot_rdata_offset(rrs, pos, offset);
	const knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
	*size = rr->len - offset;
}

/*! @} */
