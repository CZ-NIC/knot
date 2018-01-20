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

static inline
uint8_t knot_nsec3param_algorithm(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 0);
}

static inline
uint8_t knot_nsec3param_flags(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 1);
}

static inline
uint16_t knot_nsec3param_iterations(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(knot_rdata_offset(rrs, pos, 2));
}

static inline
uint8_t knot_nsec3param_salt_length(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 4);
}

static inline
const uint8_t *knot_nsec3param_salt(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_rdata_offset(rrs, pos, 5);
}

/*! @} */
