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

#include "libknot/rdataset.h"

#define KNOT_RDATA_DNSKEY_FLAG_KSK 1

uint16_t knot_dnskey_flags(const knot_rdataset_t *rrs, size_t pos);

static inline
uint8_t knot_dnskey_proto(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);

	return *knot_rdata_offset(rrs, pos, 2);
}

static inline
uint8_t knot_dnskey_alg(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return *knot_rdata_offset(rrs, pos, 3);
}

static inline
void knot_dnskey_key(const knot_rdataset_t *rrs, size_t pos, uint8_t **key,
                           uint16_t *key_size)
{
	KNOT_RDATASET_CHECK(rrs, pos, return);
	*key = knot_rdata_offset(rrs, pos, 4);
	const knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
	*key_size = knot_rdata_rdlen(rr) - 4;
}
