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

#include "libknot/dname.h"
#include "libknot/rdata.h"

static inline
const knot_dname_t *knot_nsec_next(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
uint16_t knot_nsec_bitmap_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->len - knot_dname_size(knot_nsec_next(rdata));
}

static inline
const uint8_t *knot_nsec_bitmap(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + knot_dname_size(knot_nsec_next(rdata));
}

/*! @} */
