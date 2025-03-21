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

/*!
 * \brief NSEC3 rdata constants.
 */
#define KNOT_NSEC3_ALGORITHM_SHA1	1
#define KNOT_NSEC3_FLAG_OPT_OUT		1

static inline
uint8_t knot_nsec3_alg(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data);
}

static inline
uint8_t knot_nsec3_flags(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 1);
}

static inline
uint16_t knot_nsec3_iters(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u16(rdata->data + 2);
}

static inline
uint8_t knot_nsec3_salt_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 4);
}

static inline
const uint8_t *knot_nsec3_salt(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 5;
}

static inline
uint8_t knot_nsec3_next_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 5 + knot_nsec3_salt_len(rdata));
}

static inline
const uint8_t *knot_nsec3_next(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 6 + knot_nsec3_salt_len(rdata);
}

static inline
uint16_t knot_nsec3_bitmap_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->len - 6 - knot_nsec3_salt_len(rdata) - knot_nsec3_next_len(rdata);
}

static inline
const uint8_t *knot_nsec3_bitmap(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 6 + knot_nsec3_salt_len(rdata) + knot_nsec3_next_len(rdata);
}

/*! @} */
