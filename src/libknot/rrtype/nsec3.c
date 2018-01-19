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

#include <assert.h>

#include "libknot/attribute.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/wire.h"

_public_
uint16_t knot_nsec3_iterations(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_wire_read_u16(knot_rdata_offset(rrs, pos, 2));
}

_public_
void knot_nsec3_bitmap(const knot_rdataset_t *rrs, size_t pos,
                       uint8_t **bitmap, uint16_t *size)
{
	KNOT_RDATASET_CHECK(rrs, pos, return);

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
