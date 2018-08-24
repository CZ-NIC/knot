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

#include "libknot/rdata.h"
#include "libknot/wire.h"

/*! See https://www.iana.org/assignments/dnskey-flags */
/*! /brief "Secure entry point" marks KSK and CSK in practice. */
#define KNOT_DNSKEY_FLAG_SEP	1
/*! /brief The key is ALLOWED to be used for zone contents signing. */
#define KNOT_DNSKEY_FLAG_ZONE	256
/*! /brief The key MUST NOT be used for validation. */
#define KNOT_DNSKEY_FLAG_REVOKE	128

static inline
uint16_t knot_dnskey_flags(const knot_rdata_t *rdata)
{
	assert(rdata);
	return knot_wire_read_u16(rdata->data);
}

static inline
uint8_t knot_dnskey_proto(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 2);
}

static inline
uint8_t knot_dnskey_alg(const knot_rdata_t *rdata)
{
	assert(rdata);
	return *(rdata->data + 3);
}

static inline
uint16_t knot_dnskey_key_len(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->len - 4;
}

static inline
const uint8_t *knot_dnskey_key(const knot_rdata_t *rdata)
{
	assert(rdata);
	return rdata->data + 4;
}

/*! @} */
