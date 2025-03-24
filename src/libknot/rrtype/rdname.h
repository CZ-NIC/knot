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

#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/rdata.h"
#include "libknot/rrtype/svcb.h"

static inline
const knot_dname_t *knot_cname_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_dname_target(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_ns_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_ptr_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data;
}

static inline
const knot_dname_t *knot_mx_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 2;
}

static inline
const knot_dname_t *knot_srv_name(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 6;
}

static inline
const knot_dname_t *knot_rdata_name(const knot_rdata_t *rdata, uint16_t type)
{
	assert(rdata);
	switch (type) {
		case KNOT_RRTYPE_NS:
			return knot_ns_name(rdata);
		case KNOT_RRTYPE_PTR:
			return knot_ptr_name(rdata);
		case KNOT_RRTYPE_MX:
			return knot_mx_name(rdata);
		case KNOT_RRTYPE_SRV:
			return knot_srv_name(rdata);
		case KNOT_RRTYPE_CNAME:
			return knot_cname_name(rdata);
		case KNOT_RRTYPE_DNAME:
			return knot_dname_target(rdata);
		case KNOT_RRTYPE_SVCB:
		case KNOT_RRTYPE_HTTPS:
			return knot_svcb_target(rdata);
	}

	return NULL;
}

/*! @} */
