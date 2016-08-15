/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

#include "dnssec/tsig.h"
#include "libknot/attribute.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/consts.h"
#include "libknot/dname.h"
#include "libknot/errcode.h"
#include "libknot/rrset.h"
#include "contrib/wire.h"
#include "contrib/wire_ctx.h"

/*! \brief TSIG field offsets. */
typedef enum tsig_off_t {
	TSIG_ALGNAME_O = 0,
	TSIG_TSIGNED_O,
	TSIG_FUDGE_O,
	TSIG_MACLEN_O,
	TSIG_MAC_O,
	TSIG_ORIGID_O,
	TSIG_ERROR_O,
	TSIG_OLEN_O,
	TSIG_OTHER_O
} tsig_off_t;

/* Helpers for RDATA offset calculation. */
#define TSIG_OTHER_MAXLEN (3 * sizeof(uint16_t))
#define TSIG_OFF_MACLEN (4 * sizeof(uint16_t))
#define TSIG_FIXED_RDLEN (11 * sizeof(uint16_t))

/*!
 * \brief Seek offset of a TSIG RR field.
 *
 * \param rr TSIG RR.
 * \param id Field index.
 * \param nb Required number of bytes after the offset (for boundaries check).
 * \return pointer to field on wire or NULL.
 */
static uint8_t* rdata_seek(const knot_rrset_t *rr, tsig_off_t id, size_t nb)
{
	const knot_rdata_t *rr_data = knot_rdataset_at(&rr->rrs, 0);
	if (!rr_data || knot_rdata_rdlen(rr_data) == 0) {
		return NULL;
	}

	wire_ctx_t wire = wire_ctx_init_const(knot_rdata_data(rr_data),
	                                      knot_rdata_rdlen(rr_data));

	/* TSIG RR names should be already sanitized on parse. */
	int alg_len = knot_dname_size(wire.wire);

	/* Not pretty, but fast. */
	switch(id) {
	case TSIG_ALGNAME_O: break;
	case TSIG_TSIGNED_O:
		wire_ctx_skip(&wire, alg_len); break;
	case TSIG_FUDGE_O:
		wire_ctx_skip(&wire, alg_len + 3 * sizeof(uint16_t));
		break;
	case TSIG_MACLEN_O:
		wire_ctx_skip(&wire, alg_len + 4 * sizeof(uint16_t));
		break;
	case TSIG_MAC_O:
		wire_ctx_skip(&wire, alg_len + 5 * sizeof(uint16_t));
		break;
	case TSIG_ORIGID_O:
		wire_ctx_skip(&wire, alg_len + 4 * sizeof(uint16_t));
		wire_ctx_skip(&wire, wire_ctx_read_u16(&wire));
		break;

	case TSIG_ERROR_O:
		wire_ctx_skip(&wire, alg_len + 4 * sizeof(uint16_t));
		wire_ctx_skip(&wire, wire_ctx_read_u16(&wire));
		wire_ctx_skip(&wire, sizeof(uint16_t));
		break;
	case TSIG_OLEN_O:
		wire_ctx_skip(&wire, alg_len + 4 * sizeof(uint16_t));
		wire_ctx_skip(&wire, wire_ctx_read_u16(&wire));
		wire_ctx_skip(&wire, 2 * sizeof(uint16_t));
		break;
	case TSIG_OTHER_O:
		wire_ctx_skip(&wire, alg_len + 4 * sizeof(uint16_t));
		wire_ctx_skip(&wire, wire_ctx_read_u16(&wire));
		wire_ctx_skip(&wire, 3 * sizeof(uint16_t));
		break;
	}

	if (wire.error != KNOT_EOK) {
		return NULL;
	}

	/* Check remaining bytes. */

	if (wire_ctx_available(&wire) < nb){
		return NULL;
	}

	return wire.position;
}

static int rdata_set_tsig_error(knot_rrset_t *tsig, uint16_t tsig_error)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_ERROR_O, sizeof(uint16_t));
	if (!rd) {
		return KNOT_ERROR;
	}

	wire_write_u16(rd, tsig_error);
	return KNOT_EOK;
}

_public_
int knot_tsig_create_rdata(knot_rrset_t *rr, const knot_dname_t *alg,
                           uint16_t maclen, uint16_t tsig_err)
{
	if (rr == NULL || alg == NULL) {
		return KNOT_EINVAL;
	}

	/* We already checked rr and know rdlen > 0, no need to check rest. */
	int alg_len = knot_dname_size(alg);
	size_t rdlen = alg_len + TSIG_FIXED_RDLEN + maclen;
	if (tsig_err != KNOT_TSIG_ERR_BADTIME) {
		rdlen -= TSIG_OTHER_MAXLEN;
	}
	uint8_t rd[rdlen];
	memset(rd, 0, rdlen);

	/* Copy alg name. */
	knot_dname_to_wire(rd, alg, rdlen);

	/* Set MAC variable length in advance. */
	size_t offset = alg_len + TSIG_OFF_MACLEN;
	wire_write_u16(rd + offset, maclen);

	int ret = knot_rrset_add_rdata(rr, rd, rdlen, 0, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Set error. */
	rdata_set_tsig_error(rr, tsig_err);

	return KNOT_EOK;
}

_public_
int knot_tsig_rdata_set_time_signed(knot_rrset_t *tsig, uint64_t time)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_TSIGNED_O, 3*sizeof(uint16_t));
	if (!rd) {
		return KNOT_ERROR;
	}

	wire_write_u48(rd, time);
	return KNOT_EOK;
}

_public_
int knot_tsig_rdata_set_fudge(knot_rrset_t *tsig, uint16_t fudge)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_FUDGE_O, sizeof(uint16_t));
	if (!rd) {
		return KNOT_ERROR;
	}

	wire_write_u16(rd, fudge);
	return KNOT_EOK;
}

_public_
int knot_tsig_rdata_set_mac(knot_rrset_t *tsig, uint16_t length, const uint8_t *mac)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_MAC_O, length);
	if (!rd) {
		return KNOT_ERROR;
	}

	/*! \note Cannot change length, as rdata is already preallocd. */

	/* Copy the actual MAC. */
	memcpy(rd, mac, length);
	return KNOT_EOK;
}

_public_
int knot_tsig_rdata_set_orig_id(knot_rrset_t *tsig, uint16_t id)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_ORIGID_O, sizeof(uint16_t));
	if (!rd) {
		return KNOT_ERROR;
	}

	/* Write the length - 2. */
	wire_write_u16(rd, id);
	return KNOT_EOK;
}

_public_
int knot_tsig_rdata_set_other_data(knot_rrset_t *tsig, uint16_t len,
                                   const uint8_t *other_data)
{
	if (len > TSIG_OTHER_MAXLEN) {
		return KNOT_EINVAL;
	}

	uint8_t *rd = rdata_seek(tsig, TSIG_OLEN_O, len+sizeof(uint16_t));
	if (!rd) {
		return KNOT_ERROR;
	}

	/* Write the length. */
	wire_write_u16(rd, len);

	/* Copy the actual data. */
	memcpy(rd + sizeof(uint16_t), other_data, len);
	return KNOT_EOK;
}

_public_
const knot_dname_t *knot_tsig_rdata_alg_name(const knot_rrset_t *tsig)
{
	const knot_rdata_t *rr_data = knot_rdataset_at(&tsig->rrs, 0);
	return knot_rdata_data(rr_data);
}

_public_
dnssec_tsig_algorithm_t knot_tsig_rdata_alg(const knot_rrset_t *tsig)
{
	/* Get the algorithm name. */
	const knot_dname_t *alg_name = knot_tsig_rdata_alg_name(tsig);
	if (!alg_name) {
		return DNSSEC_TSIG_UNKNOWN;
	}

	return dnssec_tsig_algorithm_from_dname(alg_name);
}

_public_
uint64_t knot_tsig_rdata_time_signed(const knot_rrset_t *tsig)
{
	/*! \todo How to return invalid value? */
	uint8_t *rd = rdata_seek(tsig, TSIG_TSIGNED_O, 3*sizeof(uint16_t));
	if (!rd) {
		return 0;
	}
	return wire_read_u48(rd);
}

_public_
uint16_t knot_tsig_rdata_fudge(const knot_rrset_t *tsig)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_FUDGE_O, sizeof(uint16_t));
	if (!rd) {
		return 0;
	}
	return wire_read_u16(rd);
}

_public_
const uint8_t *knot_tsig_rdata_mac(const knot_rrset_t *tsig)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_MAC_O, 0);
	if (!rd) {
		return NULL;
	}
	return rd;
}

_public_
size_t knot_tsig_rdata_mac_length(const knot_rrset_t *tsig)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_MACLEN_O, sizeof(uint16_t));
	if (!rd) {
		return 0;
	}
	return wire_read_u16(rd);
}

_public_
uint16_t knot_tsig_rdata_orig_id(const knot_rrset_t *tsig)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_ORIGID_O, sizeof(uint16_t));
	if (!rd) {
		return 0;
	}
	return wire_read_u16(rd);
}

_public_
uint16_t knot_tsig_rdata_error(const knot_rrset_t *tsig)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_ERROR_O, sizeof(uint16_t));
	if (!rd) {
		return 0;
	}
	return wire_read_u16(rd);
}

_public_
const uint8_t *knot_tsig_rdata_other_data(const knot_rrset_t *tsig)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_OTHER_O, 0);
	if (!rd) {
		return NULL;
	}
	return rd;
}

_public_
uint16_t knot_tsig_rdata_other_data_length(const knot_rrset_t *tsig)
{
	uint8_t *rd = rdata_seek(tsig, TSIG_OLEN_O, sizeof(uint16_t));
	if (!rd) {
		return 0;
	}
	return wire_read_u16(rd);
}

_public_
size_t knot_tsig_rdata_tsig_variables_length(const knot_rrset_t *tsig)
{
	if (tsig == NULL) {
		return 0;
	}
	/* Key name, Algorithm name and Other data have variable lengths. */
	const knot_dname_t *key_name = tsig->owner;
	if (!key_name) {
		return 0;
	}

	const knot_dname_t *alg_name = knot_tsig_rdata_alg_name(tsig);
	if (!alg_name) {
		return 0;
	}

	uint16_t other_data_length = knot_tsig_rdata_other_data_length(tsig);

	return knot_dname_size(key_name) + knot_dname_size(alg_name) +
	       other_data_length + KNOT_TSIG_VARIABLES_LENGTH;
}

_public_
size_t knot_tsig_rdata_tsig_timers_length()
{
	/*! \todo Cleanup */
	return KNOT_TSIG_TIMERS_LENGTH;
}

_public_
size_t knot_tsig_wire_maxsize(const knot_tsig_key_t *key)
{
	if (key == NULL || key->name == NULL) {
		return 0;
	}

	const uint8_t *alg_dname = dnssec_tsig_algorithm_to_dname(key->algorithm);

	/*! \todo Used fixed size as a base. */
	return knot_dname_size(key->name) +
	sizeof(uint16_t) + /* TYPE */
	sizeof(uint16_t) + /* CLASS */
	sizeof(uint32_t) + /* TTL */
	sizeof(uint16_t) + /* RDLENGTH */
	knot_dname_size(alg_dname) + /* Alg. name */
	6 * sizeof(uint8_t) + /* Time signed */
	sizeof(uint16_t) + /* Fudge */
	sizeof(uint16_t) + /* MAC size */
	dnssec_tsig_algorithm_size(key->algorithm) + /* MAC */
	sizeof(uint16_t) + /* Original ID */
	sizeof(uint16_t) + /* Error */
	sizeof(uint16_t) + /* Other len */
	6* sizeof(uint8_t); /* uint48_t in case of BADTIME RCODE */
}

_public_
int knot_tsig_rdata_is_ok(const knot_rrset_t *tsig)
{
	/*! \todo Check size, needs to check variable-length fields. */
	const knot_rdata_t *rr_data = knot_rdataset_at(&tsig->rrs, 0);
	return (tsig
	        && knot_rdata_data(rr_data) != NULL
	        && rdata_seek(tsig, TSIG_OTHER_O, 0) != NULL
	        && knot_tsig_rdata_alg_name(tsig) != NULL
	        && knot_tsig_rdata_time_signed(tsig) != 0);
}
