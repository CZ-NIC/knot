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

#include <string.h>
#include "libknot/edns.h"
#include "libknot/common.h"
#include "common/descriptor.h"
#include "common/debug.h"

/*! \brief Some implementation-related constants. */
enum knot_edns_private_consts {
	/*! \brief Mask for the DO bit (machine byte order) */
	KNOT_EDNS_DO_MASK = (uint32_t)(1 << 15),
	/*! \brief Offset of Extended RCODE field in TTL (network byte order). */
	KNOT_EDNS_OFFSET_RCODE = 0,
	/*! \brief Offset of the Version field in TTL (network byte order). */
	KNOT_EDNS_OFFSET_VERSION = 1,
	/*! \brief Offset of the Flags field in TTL (network byte order). */
	KNOT_EDNS_OFFSET_FLAGS = 2
};

/*----------------------------------------------------------------------------*/

int knot_edns_init(knot_rrset_t *opt_rr, uint16_t max_pld,
                  uint8_t ext_rcode, uint8_t ver, mm_ctx_t *mm)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	/* Initialiye RRSet. */
	knot_dname_t *owner = knot_dname_copy((const uint8_t*)"", mm);
	if (owner == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rrset_init(opt_rr, owner, KNOT_RRTYPE_OPT, max_pld);

	/* Create empty RDATA */
	int ret = knot_rrset_add_rdata(opt_rr, NULL, 0, 0, mm);
	if (ret == KNOT_EOK) {
		knot_edns_set_ext_rcode(opt_rr, ext_rcode);
		knot_edns_set_version(opt_rr, ver);
	}

	return ret;
}


/*----------------------------------------------------------------------------*/

size_t knot_edns_wire_size(knot_rrset_t *opt_rr)
{
	if (opt_rr == NULL) {
		return 0;
	}

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	assert(rdata != NULL);

	return KNOT_EDNS_MIN_SIZE + knot_rdata_rdlen(rdata);
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
	uint8_t *ttl_ptr = (uint8_t *)&ttl;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32(ttl_ptr, knot_rrset_ttl(opt_rr));

	uint8_t rcode;
	memcpy(&rcode, ttl_ptr + KNOT_EDNS_OFFSET_RCODE, 1);

	return rcode;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_ext_rcode(knot_rrset_t *opt_rr, uint8_t ext_rcode)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	uint8_t *ttl_ptr = (uint8_t *)&ttl;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32(ttl_ptr, knot_rrset_ttl(opt_rr));
	// Set the Extended RCODE in the converted TTL
	memcpy(ttl_ptr + KNOT_EDNS_OFFSET_RCODE, &ext_rcode, 1);
	// Convert it back to machine byte order
	uint32_t ttl_local = knot_wire_read_u32(ttl_ptr);
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl_local);
}

/*----------------------------------------------------------------------------*/

uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	uint8_t *ttl_ptr = (uint8_t *)&ttl;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32(ttl_ptr, knot_rrset_ttl(opt_rr));

	uint8_t version;
	memcpy(&version, ttl_ptr + KNOT_EDNS_OFFSET_VERSION, 1);

	return version;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version)
{
	assert(opt_rr != NULL);

	uint32_t ttl = 0;
	uint8_t *ttl_ptr = (uint8_t *)&ttl;
	// TTL is stored in machine byte order. Convert it to wire order first.
	knot_wire_write_u32(ttl_ptr, knot_rrset_ttl(opt_rr));
	// Set the version in the converted TTL
	memcpy(ttl_ptr + KNOT_EDNS_OFFSET_VERSION, &version, 1);
	// Convert it back to machine byte order
	uint32_t ttl_local = knot_wire_read_u32(ttl_ptr);
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl_local);
}

/*----------------------------------------------------------------------------*/

bool knot_edns_do(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	return knot_rrset_ttl(opt_rr) & KNOT_EDNS_DO_MASK;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_do(knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	// Read the TTL
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	// Set the DO bit
	ttl |= KNOT_EDNS_DO_MASK;
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Find OPTION with the given code in the OPT RDATA.
 *
 * \param rdata     RDATA to search in.
 * \param opt_code  Code of the OPTION to find.
 * \param[out] pos  Position of the OPTION or NULL if not found.
 */
static void find_option(knot_rdata_t *rdata, uint16_t opt_code, uint8_t **pos)
{
	uint8_t *data = knot_rdata_data(rdata);
	uint16_t rdlength = knot_rdata_rdlen(rdata);

	*pos = NULL;

	int i = 0;
	while (i + 4 <= rdlength) {
		uint16_t code = knot_wire_read_u16(data + i);
		if (opt_code == code) {
			*pos = data + i;
			return;
		}
		uint16_t opt_len = knot_wire_read_u16(data + i + 2);
		i += (4 + opt_len);
	}
}

/*----------------------------------------------------------------------------*/

int knot_edns_clear_options(knot_rrset_t *opt_rr, bool retain_nsid)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);

	if (retain_nsid) {
		/* Search for NSID and move it to the beginning. Then crop. */
		uint8_t *pos = NULL;
		find_option(rdata, KNOT_EDNS_OPTION_NSID, &pos);

		uint16_t nsid_len = knot_wire_read_u16(pos + 2);
		uint16_t total_len = nsid_len + 4;

		memmove(knot_rdata_data(rdata), pos, total_len);
		knot_rdata_set_rdlen(rdata, total_len);
	} else {
		/* Clear the whole RDATA. No other OPTIONS supported now. */
		knot_rdata_set_rdlen(rdata, 0);
	}

	return KNOT_EOK;
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
	dbg_edns_hex_verb((char *)data, length);

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
	assert(opt_rr != NULL);

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	assert(rdata != NULL);

	uint8_t *pos = NULL;
	find_option(rdata, code, &pos);

	return pos != NULL;
}

/*----------------------------------------------------------------------------*/

bool knot_edns_has_nsid(const knot_rrset_t *opt_rr)
{
	return knot_edns_has_option(opt_rr, KNOT_EDNS_OPTION_NSID);
}

/*----------------------------------------------------------------------------*/

bool knot_edns_check_record(knot_rrset_t *opt_rr)
{
	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	if (rdata == NULL) {
		return false;
	}

	uint8_t *data = knot_rdata_data(rdata);
	uint16_t rdlength = knot_rdata_rdlen(rdata);
	uint32_t pos = 0;

	/* RFC2671 4.4: {uint16_t code, uint16_t len, data} */
	while (pos + KNOT_EDNS_OPTION_HDRLEN <= rdlength) {
		uint16_t opt_len = knot_wire_read_u16(data + pos + sizeof(uint16_t));
		pos += KNOT_EDNS_OPTION_HDRLEN + opt_len;
	}

	/* If not at the end of the RDATA, there are either some redundant data
	 * (pos < rdlength) or the last OPTION is too long (pos > rdlength).
	 */
	return pos == rdlength;
}
