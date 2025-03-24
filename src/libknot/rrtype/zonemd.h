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
