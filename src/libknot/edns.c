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

/*! \brief Various EDNS constatns. */
enum knot_edns_consts {
	/*! \brief Mask for the DO bit in little endian. */
	KNOT_EDNS_DO_MASK = (uint32_t)0x800000,
	/*! \brief Step for allocation of space for option entries. */
	KNOT_EDNS_OPTION_STEP = 1,

	KNOT_EDNS_OFFSET_RCODE = 3,
	KNOT_EDNS_OFFSET_VERSION = 2
};

#define DUMMY_RDATA_SIZE 1

/*----------------------------------------------------------------------------*/
/*! \todo [OPT] Done */
knot_rrset_t *knot_edns_new(uint16_t max_pld, uint8_t ext_rcode, uint8_t ver,
                            uint16_t flags, mm_ctx_t *mm)
{
	knot_dname_t *owner = knot_dname_from_str(".");
	CHECK_ALLOC_LOG(owner, NULL);
	knot_rrset_t *opt = knot_rrset_new(owner, KNOT_RRTYPE_OPT, max_pld, mm);
	if (opt == NULL) {
		ERR_ALLOC_FAILED;
		free(owner);
		return NULL;
	}
	uint8_t *rdata = (uint8_t *)malloc(DUMMY_RDATA_SIZE);
	if (rdata == NULL) {
		ERR_ALLOC_FAILED;
		knot_rrset_free(&opt, mm);
		return NULL;
	}

	uint32_t ttl = 0;
	memcpy(&ttl + KNOT_EDNS_OFFSET_RCODE, &ext_rcode, 1);
	memcpy(&ttl + KNOT_EDNS_OFFSET_VERSION, &ver, 1);
	// Flags must be in inverse order than on wire (i.e. DO is 9th bit)
	memcpy(&ttl, &flags, 2);

	int ret = knot_rrset_add_rdata(opt, rdata, 0, ttl, mm);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&opt, mm);
		return NULL;
	}

	return opt;
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
uint16_t knot_edns_get_payload(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);
	return opt_rr->rclass;
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
void knot_edns_set_payload(knot_rrset_t *opt_rr, uint16_t payload)
{
	assert(opt_rr != NULL);
	opt_rr->rclass = payload;
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
uint8_t knot_edns_get_ext_rcode(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	// TTL has bytes in an inverse order
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	uint8_t rcode;
	memcpy(&rcode, &ttl + KNOT_EDNS_OFFSET_RCODE, 1);

	return rcode;
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
void knot_edns_set_ext_rcode(knot_rrset_t *opt_rr, uint8_t ext_rcode)
{
	assert(opt_rr != NULL);

	// TTL has bytes in an inverse order
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	memcpy(&ttl + KNOT_EDNS_OFFSET_RCODE, &ext_rcode, 1);
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl);
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	// TTL has bytes in an inverse order
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	uint8_t version;
	memcpy(&version, &ttl + KNOT_EDNS_OFFSET_VERSION, 1);

	return version;
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version)
{
	assert(opt_rr != NULL);

	// TTL has bytes in an inverse order
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	memcpy(&ttl + KNOT_EDNS_OFFSET_VERSION, &version, 1);
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl);
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
bool knot_edns_do(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	// TTL has bytes in an inverse order
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	return ttl & KNOT_EDNS_DO_MASK;
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
void knot_edns_set_do(knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	// TTL has bytes in an inverse order
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	ttl |= KNOT_EDNS_DO_MASK;
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl);
}

/*----------------------------------------------------------------------------*/
/* [OPT] Done */
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
/* [OPT] Done */
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
/* [OPT] Done */
size_t knot_edns_size(knot_rrset_t *opt_rr)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	size_t size = EDNS_MIN_SIZE;
	// Only one RDATA in OPT RRSet
	size += knot_rdata_rdlen(knot_rdataset_at(&opt_rr->rrs, 0));

	return size;
}

/*----------------------------------------------------------------------------*/
/* NEW API                                                                    */
/*----------------------------------------------------------------------------*/

knot_edns_params_t *knot_edns_new_params()
{
	knot_edns_params_t *opt =
	               (knot_edns_params_t *)malloc(sizeof(knot_edns_params_t));
	CHECK_ALLOC_LOG(opt, NULL);

	memset(opt, 0, sizeof(knot_edns_params_t));
	return opt;
}

void knot_edns_free_params(knot_edns_params_t **opt)
{
	if (opt == NULL || *opt == NULL) {
		return;
	}

	free((*opt)->nsid);
	free(*opt);
	*opt = NULL;
}

/*! \todo Rewrite and remove the edns_params_t type. */
knot_rrset_t *knot_edns_new_from_params(const knot_edns_params_t *params,
                                        bool add_nsid)
{
	if (params == NULL) {
		return NULL;
	}

	knot_rrset_t *rrset = (knot_rrset_t *)malloc(sizeof(knot_rrset_t *));
	rrset->owner = knot_dname_from_str(".");
	rrset->type = KNOT_RRTYPE_OPT;

	knot_edns_set_payload(rrset, params->payload);
	knot_edns_set_ext_rcode(rrset, 0);
	knot_edns_set_version(rrset, params->version);

	if (add_nsid) {
		/*! \todo */
	}

	return rrset;
}
