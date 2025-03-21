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
