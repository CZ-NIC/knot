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

#include "common/descriptor.h"
#include "libknot/rr.h"
#include "libknot/dname.h"

static inline
const knot_dname_t *knot_rrs_cname_name(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_rrs_dname_target(const knot_rrs_t *rrs)
{
	RRS_CHECK(rrs, 0, return NULL);
	return data_offset(rrs, 0, 0);
}

static inline
const knot_dname_t *knot_rrs_ns_name(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 0);
}

static inline
const knot_dname_t *knot_rrs_mx_name(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 2);
}

static inline
const knot_dname_t *knot_rrs_srv_name(const knot_rrs_t *rrs, size_t pos)
{
	RRS_CHECK(rrs, pos, return 0);
	return data_offset(rrs, pos, 6);
}

static inline
const knot_dname_t *knot_rrs_name(const knot_rrs_t *rrs, size_t pos,
                                  uint16_t type)
{
	switch (type) {
		case KNOT_RRTYPE_NS:
			return knot_rrs_ns_name(rrs, pos);
		case KNOT_RRTYPE_MX:
			return knot_rrs_mx_name(rrs, pos);
		case KNOT_RRTYPE_SRV:
			return knot_rrs_srv_name(rrs, pos);
		case KNOT_RRTYPE_CNAME:
			return knot_rrs_cname_name(rrs);
	}

	return NULL;
}