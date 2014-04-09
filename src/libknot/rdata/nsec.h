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

#pragma once

#include "libknot/rr.h"

static inline
const knot_dname_t *knot_nsec_next(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, 0);
}

static inline
void knot_nsec_bitmap(const knot_rrs_t *rrs,
                            uint8_t **bitmap, uint16_t *size)
{
	RRS_CHECK(rrs, 0, return);
	knot_rr_t *rr = knot_rrs_rr(rrs, 0);
	int next_size = knot_dname_size(knot_nsec_next(rrs));

	*bitmap = knot_rr_rdata(rr) + next_size;
	*size = knot_rr_rdata_size(rr) - next_size;
}