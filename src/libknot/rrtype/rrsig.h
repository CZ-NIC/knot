/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
