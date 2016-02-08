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

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "libknot/attribute.h"
#include "libknot/rdata.h"
#include "libknot/errcode.h"
#include "contrib/macros.h"

#ifndef STRICT_ALIGNMENT
#pragma pack(push, 1)
#endif

/*!< \brief Helper structure - offsets in RR array. */
struct rr_offsets {
	uint32_t ttl;
	uint16_t size;
	uint8_t rdata[];
};

#ifndef STRICT_ALIGNMENT
#pragma pack(pop)
#endif

_public_
void knot_rdata_init(knot_rdata_t *rdata,
                     uint16_t rdlen, const uint8_t *data, uint32_t ttl)
{
	knot_rdata_set_ttl(rdata, ttl);
	knot_rdata_set_rdlen(rdata, rdlen);
	memcpy(knot_rdata_data(rdata), data, rdlen);
}

_public_
uint16_t knot_rdata_rdlen(const knot_rdata_t *rr)
{
	return ((struct rr_offsets *)rr)->size;
}

_public_
void knot_rdata_set_rdlen(knot_rdata_t *rr, uint16_t size)
{
	((struct rr_offsets *)rr)->size = size;
}

_public_
uint32_t knot_rdata_ttl(const knot_rdata_t *rr)
{
	return ((struct rr_offsets *)rr)->ttl;
}

_public_
void knot_rdata_set_ttl(knot_rdata_t *rr, uint32_t ttl)
{
	((struct rr_offsets *)rr)->ttl = ttl;
}

_public_
uint8_t *knot_rdata_data(const knot_rdata_t *rr)
{
	return ((struct rr_offsets *)rr)->rdata;
}

_public_
size_t knot_rdata_array_size(uint16_t size)
{
	return size + sizeof(struct rr_offsets);
}

_public_
int knot_rdata_cmp(const knot_rdata_t *rr1, const knot_rdata_t *rr2)
{
	assert(rr1 && rr2);
	const uint8_t *r1 = knot_rdata_data(rr1);
	const uint8_t *r2 = knot_rdata_data(rr2);
	uint16_t l1 = knot_rdata_rdlen(rr1);
	uint16_t l2 = knot_rdata_rdlen(rr2);
	int cmp = memcmp(r1, r2, MIN(l1, l2));
	if (cmp == 0 && l1 != l2) {
		cmp = l1 < l2 ? -1 : 1;
	}
	return cmp;
}
