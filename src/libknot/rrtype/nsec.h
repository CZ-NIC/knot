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

static inline
const knot_dname_t *knot_nsec_next(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
uint16_t knot_nsec_bitmap_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->len - knot_dname_size(knot_nsec_next(rdata));
}

static inline
const uint8_t *knot_nsec_bitmap(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + knot_dname_size(knot_nsec_next(rdata));
}

/*! @} */
