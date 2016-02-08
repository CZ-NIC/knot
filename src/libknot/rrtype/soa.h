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
#include "libknot/dname.h"

static inline
const knot_dname_t *knot_soa_primary_ns(const knot_rdataset_t *rrs)
{
	KNOT_RDATASET_CHECK(rrs, 0, return NULL);
	return knot_rdata_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_soa_mailbox(const knot_rdataset_t *rrs)
{
	KNOT_RDATASET_CHECK(rrs, 0, return NULL);
	return knot_rdata_offset(rrs, 0, knot_dname_size(knot_soa_primary_ns(rrs)));
}

static inline
size_t knot_soa_names_len(const knot_rdataset_t *rrs)
{
	KNOT_RDATASET_CHECK(rrs, 0, return 0);
	return knot_dname_size(knot_soa_primary_ns(rrs))
	       + knot_dname_size(knot_soa_mailbox(rrs));
}

uint32_t knot_soa_serial(const knot_rdataset_t *rrs);

void knot_soa_serial_set(knot_rdataset_t *rrs, uint32_t serial);

uint32_t knot_soa_refresh(const knot_rdataset_t *rrs);

uint32_t knot_soa_retry(const knot_rdataset_t *rrs);

uint32_t knot_soa_expire(const knot_rdataset_t *rrs);

uint32_t knot_soa_minimum(const knot_rdataset_t *rrs);
