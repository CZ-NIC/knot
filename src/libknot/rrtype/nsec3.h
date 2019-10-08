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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \file
 *
 * \addtogroup rrtype
 * @{
 */

#pragma once

#include "libknot/rdata.h"
#include "libknot/wire.h"

/*!
 * \brief NSEC3 rdata constants.
 */
#define KNOT_NSEC3_ALGORITHM_SHA1	1
#define KNOT_NSEC3_FLAG_OPT_OUT		1

static inline
uint8_t knot_nsec3_alg(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data);
}

static inline
uint8_t knot_nsec3_flags(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 1);
}

static inline
uint16_t knot_nsec3_iters(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u16(rdata->data + 2);
}

static inline
uint8_t knot_nsec3_salt_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 4);
}

static inline
const uint8_t *knot_nsec3_salt(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 5;
}

static inline
uint8_t knot_nsec3_next_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 5 + knot_nsec3_salt_len(rdata));
}

static inline
const uint8_t *knot_nsec3_next(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 6 + knot_nsec3_salt_len(rdata);
}

static inline
uint16_t knot_nsec3_bitmap_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->len - 6 - knot_nsec3_salt_len(rdata) - knot_nsec3_next_len(rdata);
}

static inline
const uint8_t *knot_nsec3_bitmap(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 6 + knot_nsec3_salt_len(rdata) + knot_nsec3_next_len(rdata);
}

/*! @} */
