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

#include "libknot/dname.h"
#include "libknot/rdata.h"
#include "libknot/wire.h"

static inline
const knot_dname_t *knot_soa_primary(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_soa_mailbox(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + knot_dname_size(knot_soa_primary(rdata));
}

static inline
size_t knot_soa_names_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_dname_size(knot_soa_primary(rdata)) +
	       knot_dname_size(knot_soa_mailbox(rdata));
}

static inline
uint32_t knot_soa_serial(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + knot_soa_names_len(rdata));
}

static inline
void knot_soa_serial_set(knot_rdata_t *rdata, uint32_t serial)
{
	assert(rdata);
	knot_wire_write_u32(rdata->data + knot_soa_names_len(rdata), serial);
}

static inline
uint32_t knot_soa_refresh(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + knot_soa_names_len(rdata) + 4);
}

static inline
uint32_t knot_soa_retry(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + knot_soa_names_len(rdata) + 8);
}

static inline
uint32_t knot_soa_expire(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + knot_soa_names_len(rdata) + 12);
}

static inline
uint32_t knot_soa_minimum(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + knot_soa_names_len(rdata) + 16);
}

/*! @} */
