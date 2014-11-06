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

#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/rdataset.h"

static inline
const knot_dname_t *knot_cname_name(const knot_rdataset_t *rrs)
{
	KNOT_RDATASET_CHECK(rrs, 0, return NULL);
	return knot_rdata_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_dname_target(const knot_rdataset_t *rrs)
{
	KNOT_RDATASET_CHECK(rrs, 0, return NULL);
	return knot_rdata_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_ns_name(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_rdata_offset(rrs, pos, 0);
}

static inline
const knot_dname_t *knot_mx_name(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_rdata_offset(rrs, pos, 2);
}

static inline
const knot_dname_t *knot_srv_name(const knot_rdataset_t *rrs, size_t pos)
{
	KNOT_RDATASET_CHECK(rrs, pos, return 0);
	return knot_rdata_offset(rrs, pos, 6);
}

static inline
const knot_dname_t *knot_rdata_name(const knot_rdataset_t *rrs, size_t pos, uint16_t type)
{
	switch (type) {
		case KNOT_RRTYPE_NS:
			return knot_ns_name(rrs, pos);
		case KNOT_RRTYPE_MX:
			return knot_mx_name(rrs, pos);
		case KNOT_RRTYPE_SRV:
			return knot_srv_name(rrs, pos);
		case KNOT_RRTYPE_CNAME:
			return knot_cname_name(rrs);
	}

	return NULL;
}
