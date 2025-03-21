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
