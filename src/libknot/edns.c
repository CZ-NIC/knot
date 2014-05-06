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

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>

#include "libknot/edns.h"
#include "libknot/common.h"
#include "common/descriptor.h"
#include "common/debug.h"

/*! \brief Some implementation-related constants. */
enum knot_edns_private_consts {
	/*! \brief Mask for the DO bit in TTL in wire byte order. */
	KNOT_EDNS_DO_MASK = (uint32_t)1 << 15,
	/*! \brief Offset of Extended RCODE field in TTL in wire byte order. */
	KNOT_EDNS_OFFSET_RCODE = 0,
	/*! \brief Offset of the Version field in TTL in wire byte order. */
	KNOT_EDNS_OFFSET_VERSION = 1
};

#define DUMMY_RDATA_SIZE 1

/*----------------------------------------------------------------------------*/
/* EDNS server parameters handling functions                                  */
/*----------------------------------------------------------------------------*/

knot_edns_params_t *knot_edns_new_params(uint16_t max_payload, uint8_t ver,
                                         uint16_t flags, uint16_t nsid_len,
                                         uint8_t *nsid)
{
	knot_edns_params_t *edns =
	               (knot_edns_params_t *)malloc(sizeof(knot_edns_params_t));
	CHECK_ALLOC_LOG(edns, NULL);

	edns->version = ver;
	edns->payload = max_payload;
	edns->nsid_len = nsid_len;
	edns->flags = flags;

	if (nsid_len > 0) {
		edns->nsid = (uint8_t *)malloc(edns->nsid_len);
		if (edns->nsid == NULL) {
			free(edns);
			return NULL;
		}
		memcpy(edns->nsid, nsid, nsid_len);
	}

	return edns;
}

/*----------------------------------------------------------------------------*/

void knot_edns_free_params(knot_edns_params_t **edns)
{
	if (edns == NULL || *edns == NULL) {
		return;
	}

	free((*edns)->nsid);
	free(*edns);
	*edns = NULL;
}

/*----------------------------------------------------------------------------*/
/* EDNS OPT RR handling functions.                                            */
/*----------------------------------------------------------------------------*/

static int init_opt(knot_rrset_t *opt_rr, uint8_t ext_rcode,
                    uint8_t ver, uint16_t flags, mm_ctx_t *mm)
{
	assert(opt_rr != NULL);

	uint8_t *rdata = (uint8_t *)mm_alloc(mm, DUMMY_RDATA_SIZE);
	if (rdata == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* For easier manipulation, use wire order to assemble the TTL, then
	 * convert it to machine byte order.
	 */
	uint32_t ttl = 0;
	memcpy(&ttl + KNOT_EDNS_OFFSET_RCODE, &ext_rcode, 1);
	memcpy(&ttl + KNOT_EDNS_OFFSET_VERSION, &ver, 1);
	/* Flags are in wire order, so just copy them. */
	memcpy(&ttl, &flags, 2);

	/* Now convert the TTL to machine byte order. */
	uint32_t ttl_local = knot_wire_read_u32((uint8_t *)&ttl);

	int ret = knot_rrset_add_rdata(opt_rr, rdata, 0, ttl_local, mm);
	if (ret != KNOT_EOK) {
		mm_free(mm, rdata);
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_edns_init_from_params(knot_rrset_t *opt_rr,
                               const knot_edns_params_t *params, bool add_nsid,
                               mm_ctx_t *mm)
{
	if (opt_rr == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	opt_rr->rclass = params->payload;
	init_opt(opt_rr, 0, params->version, 0, mm);

	int ret = KNOT_EOK;
	if (add_nsid) {
		ret = knot_edns_add_option(opt_rr, KNOT_EDNS_OPTION_NSID,
		                           params->nsid_len, params->nsid, mm);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_edns_get_payload(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);
	return opt_rr->rclass;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_payload(knot_rrset_t *opt_rr, uint16_t payload)
{
	assert(opt_rr != NULL);
	opt_rr->rclass = payload;
}

/*----------------------------------------------------------------------------*/

uint8_t knot_edns_get_ext_rcode(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32((uint8_t *)&ttl, knot_rrset_ttl(opt_rr));

	uint8_t rcode;
	memcpy(&rcode, ((uint8_t *)&ttl) + KNOT_EDNS_OFFSET_RCODE, 1);

	return rcode;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_ext_rcode(knot_rrset_t *opt_rr, uint8_t ext_rcode)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32((uint8_t *)&ttl, knot_rrset_ttl(opt_rr));
	// Set the Extended RCODE in the converted TTL
	memcpy(&ttl + KNOT_EDNS_OFFSET_RCODE, &ext_rcode, 1);
	// Convert it back to machine byte order
	uint32_t ttl_local = knot_wire_read_u32((uint8_t *)&ttl);
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl_local);
}

/*----------------------------------------------------------------------------*/

uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32((uint8_t *)&ttl, knot_rrset_ttl(opt_rr));

	uint8_t version;
	memcpy(&version, ((uint8_t *)&ttl) + KNOT_EDNS_OFFSET_VERSION, 1);

	return version;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32((uint8_t *)&ttl, knot_rrset_ttl(opt_rr));
	// Set the version in the converted TTL
	memcpy(&ttl + KNOT_EDNS_OFFSET_VERSION, &version, 1);
	// Convert it back to machine byte order
	uint32_t ttl_local = knot_wire_read_u32((uint8_t *)&ttl);
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl_local);
}

/*----------------------------------------------------------------------------*/

bool knot_edns_do(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32((uint8_t *)&ttl, knot_rrset_ttl(opt_rr));

	return ttl & KNOT_EDNS_DO_MASK;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_do(knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32((uint8_t *)&ttl, knot_rrset_ttl(opt_rr));
	// Set the DO bit in the converted TTL
	ttl |= KNOT_EDNS_DO_MASK;
	// Convert it back to machine byte order
	uint32_t ttl_local = knot_wire_read_u32((uint8_t *)&ttl);
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl_local);
}

/*----------------------------------------------------------------------------*/

int knot_edns_add_option(knot_rrset_t *opt_rr, uint16_t code,
                         uint16_t length, const uint8_t *data, mm_ctx_t *mm)
{
	if (opt_rr == NULL || (length != 0 && data == NULL)) {
		return KNOT_EINVAL;
	}

	/* We need to replace the RDATA currently in the OPT RR */

	/* 1) create new RDATA by appending the new option after the current
	 *    RDATA.
	 */
	assert(opt_rr->rrs.rr_count == 1);
	knot_rdata_t *old_rdata = knot_rdataset_at(&opt_rr->rrs, 0);

	uint8_t *old_data = knot_rdata_data(old_rdata);
	uint16_t old_data_len = knot_rdata_rdlen(old_rdata);
	uint16_t new_data_len = old_data_len + 4 + length;

	uint8_t *new_data = (uint8_t *)mm_alloc(mm, new_data_len);
	CHECK_ALLOC_LOG(new_data, KNOT_ENOMEM);

	dbg_edns_verb("EDNS: Adding option. Code: %u, length: %u, data:\n",
	              code, length);
	dbg_edns_hex_verb(data, length);

	memcpy(new_data, old_data, old_data_len);
	// write length and code in wireformat (convert endian)
	knot_wire_write_u16(new_data + old_data_len, code);
	knot_wire_write_u16(new_data + old_data_len + 2, length);
	// write the option data
	memcpy(new_data + old_data_len + 4, data, length);

	/* 2) Create new RDATA structure (we need to preserve the TTL).
	 */
	size_t new_rdata_size = knot_rdata_array_size(new_data_len);
	knot_rdata_t *new_rdata = (knot_rdata_t *)mm_alloc(mm, new_rdata_size);
	if (new_rdata == NULL) {
		mm_free(mm, new_data);
		return KNOT_ENOMEM;
	}
	knot_rdata_set_ttl(new_rdata, knot_rdata_ttl(old_rdata));
	knot_rdata_set_rdlen(new_rdata, new_data_len);
	memcpy(knot_rdata_data(new_rdata), new_data, new_data_len);

	/* 3) Replace the RDATA in the rdataset. This is an ugly hack, but
	 *    there is no better way around the current API.
	 */
	opt_rr->rrs.data = new_rdata;

	/* 4) Delete the old RDATA.
	 * WARNING: This assumes the data isn't shared.
	 */
	mm_free(mm, old_rdata);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

bool knot_edns_has_option(const knot_rrset_t *opt_rr, uint16_t code)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	assert(opt_rr->rrs.rr_count == 1);

	// Get the actual RDATA
	uint8_t *data = knot_rdata_data(knot_rdataset_at(&opt_rr->rrs, 0));
	uint16_t data_len = knot_rdata_rdlen(knot_rdataset_at(&opt_rr->rrs, 0));

	int pos = 0;
	while (data_len - pos > 4) {
		uint16_t opt_code = knot_wire_read_u16(data + pos);
		if (opt_code == code) {
			return true;
		}
		uint16_t opt_len = knot_wire_read_u16(data + pos + 2);
		pos += (4 + opt_len);
	}

	return false;
}

/*----------------------------------------------------------------------------*/

size_t knot_edns_size(knot_rrset_t *opt_rr)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	size_t size = KNOT_EDNS_MIN_SIZE;
	// Only one RDATA in OPT RRSet
	size += knot_rdata_rdlen(knot_rdataset_at(&opt_rr->rrs, 0));

	return size;
}
