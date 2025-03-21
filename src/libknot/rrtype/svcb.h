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
uint32_t knot_svcb_priority(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u16(rdata->data);
}

static inline
const knot_dname_t *knot_svcb_target(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 2;
}

/*! @} */
