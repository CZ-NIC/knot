/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/rdata.h"
#include "libknot/wire.h"

#define KNOT_ZONEMD_SCHEME_SIMPLE	1
#define KNOT_ZONEMD_ALGORITHM_SHA384	1
#define KNOT_ZONEMD_ALGORITHM_SHA512	2

static inline
uint32_t knot_zonemd_soa_serial(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data);
}

static inline
uint8_t knot_zonemd_scheme(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 4);
}

static inline
uint8_t knot_zonemd_algorithm(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 5);
}

static inline
size_t knot_zonemd_digest_size(const knot_rdata_t *rdata)
{
	switch (knot_zonemd_algorithm(rdata)) {
	case KNOT_ZONEMD_ALGORITHM_SHA384: return 48;
	case KNOT_ZONEMD_ALGORITHM_SHA512: return 64;
	default: return 0;
	}
}

static inline
const uint8_t *knot_zonemd_digest(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 6;
}

/*! @} */
