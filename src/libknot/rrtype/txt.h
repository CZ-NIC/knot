/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/rdataset.h"

static inline
size_t knot_txt_count(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);

	const knot_rdata_t *rdata = knot_rdataset_at(rrs, pos);
	const uint8_t *start = knot_rdata_data(rdata);
	const uint8_t *end = start + knot_rdata_rdlen(rdata);

	size_t count = 0;

	for (const uint8_t *p = start; p < end; p += 1 + *p) {
		count++;
	}

	return count;
}

static inline
const uint8_t *knot_txt_data(const knot_rdataset_t *rrs, size_t pos, size_t index)
{
	KNOT_RDATASET_CHECK(rrs, pos, return NULL);

	const knot_rdata_t *rdata = knot_rdataset_at(rrs, pos);
	const uint8_t *start = knot_rdata_data(rdata);
	const uint8_t *end = start + knot_rdata_rdlen(rdata);

	const uint8_t *data = start;

	for (size_t i = 0; i < index; i++) {
		data += 1 + *data;
		if (data > end) {
			return NULL;
		}
	}

	return data;
}
