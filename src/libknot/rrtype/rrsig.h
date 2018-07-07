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

#include "libknot/dname.h"
#include "libknot/rdata.h"
#include "libknot/wire.h"

static inline
uint16_t knot_rrsig_type_covered(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u16(rdata->data);
}

static inline
uint8_t knot_rrsig_alg(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 2);
}

static inline
uint8_t knot_rrsig_labels(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 3);
}

static inline
uint32_t knot_rrsig_original_ttl(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + 4);
}

static inline
uint32_t knot_rrsig_sig_expiration(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + 8);
}

static inline
uint32_t knot_rrsig_sig_inception(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u32(rdata->data + 12);
}

static inline
uint16_t knot_rrsig_key_tag(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u16(rdata->data + 16);
}

static inline
const knot_dname_t *knot_rrsig_signer_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 18;
}

static inline
uint16_t knot_rrsig_signature_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->len - 18 - knot_dname_size(knot_rrsig_signer_name(rdata));
}

static inline
const uint8_t *knot_rrsig_signature(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 18 + knot_dname_size(knot_rrsig_signer_name(rdata));
}

/*! @} */
