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
/*!
 * \file
 *
 * \addtogroup rrtype
 * @{
 */

#pragma once

#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/rdata.h"

static inline
const knot_dname_t *knot_cname_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_dname_target(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_ns_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_mx_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 2;
}

static inline
const knot_dname_t *knot_srv_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 6;
}

static inline
const knot_dname_t *knot_rdata_name(const knot_rdata_t *rdata, uint16_t type)
{
	assert(rdata);
	switch (type) {
		case KNOT_RRTYPE_NS:
			return knot_ns_name(rdata);
		case KNOT_RRTYPE_MX:
			return knot_mx_name(rdata);
		case KNOT_RRTYPE_SRV:
			return knot_srv_name(rdata);
		case KNOT_RRTYPE_CNAME:
			return knot_cname_name(rdata);
		case KNOT_RRTYPE_DNAME:
			return knot_dname_target(rdata);
	}

	return NULL;
}

/*! @} */
