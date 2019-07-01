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

static inline
uint16_t knot_ds_key_tag(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u16(rdata->data);
}

static inline
uint8_t knot_ds_alg(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 2);
}

static inline
uint8_t knot_ds_digest_type(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 3);
}

static inline
uint16_t knot_ds_digest_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->len - 4;
}

static inline
const uint8_t *knot_ds_digest(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 4;
}

/*! @} */
