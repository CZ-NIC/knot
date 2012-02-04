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

#include "edns.h"
#include "common.h"
#include "util/descriptor.h"
#include "util/debug.h"
#include "util/error.h"

/*! \brief Various EDNS constatns. */
enum knot_edns_consts {
	/*! \brief Mask for the DO bit. */
	KNOT_EDNS_DO_MASK = (uint16_t)0x8000,
	/*! \brief Step for allocation of space for option entries. */
	KNOT_EDNS_OPTION_STEP = 1
};

/*----------------------------------------------------------------------------*/

knot_opt_rr_t *knot_edns_new()
{
	knot_opt_rr_t *opt_rr = (knot_opt_rr_t *)malloc(
	                                               sizeof(knot_opt_rr_t));
	CHECK_ALLOC_LOG(opt_rr, NULL);
	memset(opt_rr, 0, sizeof(knot_opt_rr_t));
	opt_rr->size = KNOT_EDNS_MIN_SIZE;
	opt_rr->option_count = 0;
	opt_rr->options_max = 0;

	opt_rr->ext_rcode = 0;
	opt_rr->flags = 0;
	opt_rr->version = 0;

	return opt_rr;
}

/*----------------------------------------------------------------------------*/

int knot_edns_new_from_wire(knot_opt_rr_t *opt_rr, const uint8_t *wire,
                              size_t max_size)
{
	const uint8_t *pos = wire;
	int parsed = 0;

	if (pos == NULL || max_size == 0 || opt_rr == NULL) {
		return KNOT_EBADARG;
	}

	if (max_size < KNOT_EDNS_MIN_SIZE) {
		dbg_edns("Not enough data to parse OPT RR header.\n");
		return KNOT_EFEWDATA;
	}

	// owner of EDNS OPT RR must be root (0)
	if (*pos != 0) {
		dbg_edns("EDNS packet malformed (expected root "
		                  "domain as owner).\n");
		return KNOT_EMALF;
	}
	pos += 1;

	// check the type of the record (must be OPT)
	if (knot_wire_read_u16(pos) != KNOT_RRTYPE_OPT) {
		dbg_edns("EDNS packet malformed (expected OPT type"
		                  ".\n");
		return KNOT_EMALF;
	}
	pos += 2;

	opt_rr->payload = knot_wire_read_u16(pos);
	dbg_edns("Parsed payload: %u\n", opt_rr->payload);

	pos += 2;
	opt_rr->ext_rcode = *(pos++);
	opt_rr->version = *(pos++);
	opt_rr->flags = knot_wire_read_u16(pos);
	pos += 2;

	parsed = KNOT_EDNS_MIN_SIZE;

	// ignore RDATA, but move pos behind them
	uint16_t rdlength = knot_wire_read_u16(pos);
	pos += 2;

	if (max_size - parsed < rdlength) {
		dbg_edns("Not enough data to parse OPT RR.\n");
		return KNOT_EFEWDATA;
	}

	while (parsed < rdlength + KNOT_EDNS_MIN_SIZE) {
		if (max_size - parsed < 4) {
			dbg_edns("Not enough data to parse OPT RR"
			                  " OPTION header.\n");
			return KNOT_EFEWDATA;
		}
		uint16_t code = knot_wire_read_u16(pos);
		pos += 2;
		uint16_t length = knot_wire_read_u16(pos);
		pos += 2;
		dbg_edns("EDNS OPTION: Code: %u, Length: %u\n",
		                  code, length);
		if (max_size - parsed - 4 < length) {
			dbg_edns("Not enough data to parse OPT RR"
			                  " OPTION data.\n");
			return KNOT_EFEWDATA;
		}
		int ret;
		if ((ret =
		     knot_edns_add_option(opt_rr, code, length, pos)) != 0) {
			dbg_edns("Error parsing OPT option field.\n");
			return ret;
		}
		pos += length;
		parsed += length + 4;
	}

	return parsed;
}

/*----------------------------------------------------------------------------*/

int knot_edns_new_from_rr(knot_opt_rr_t *opt_rr,
                            const knot_rrset_t *rrset)
{
	if (opt_rr == NULL || rrset == NULL
	    || knot_rrset_type(rrset) != KNOT_RRTYPE_OPT) {
		return KNOT_EBADARG;
	}

	dbg_edns("Parsing payload.\n");
	opt_rr->payload = knot_rrset_class(rrset);

	// the TTL has switched bytes
	uint32_t ttl;
	dbg_edns("TTL: %u\n", knot_rrset_ttl(rrset));
	knot_wire_write_u32((uint8_t *)&ttl, knot_rrset_ttl(rrset));
	// first byte of TTL is extended RCODE
	dbg_edns("TTL: %u\n", ttl);
	memcpy(&opt_rr->ext_rcode, &ttl, 1);
	dbg_edns("Parsed extended RCODE: %u.\n", opt_rr->ext_rcode);
	// second is the version
	memcpy(&opt_rr->version, (const uint8_t *)(&ttl) + 1, 1);
	dbg_edns("Parsed version: %u.\n", opt_rr->version);
	// third and fourth are flags
	opt_rr->flags = knot_wire_read_u16((const uint8_t *)(&ttl) + 2);
	dbg_edns("Parsed flags: %u.\n", opt_rr->flags);
	// size of the header, options are counted elsewhere
	opt_rr->size = 11;

	int rc = 0;
	dbg_edns("Parsing options.\n");
	const knot_rdata_t *rdata = knot_rrset_rdata(rrset);

	// in OPT RR, all RDATA are in one RDATA item stored as BINARY data,
	// i.e. preceded by their length
	if (rdata != NULL) {
		assert(knot_rdata_item_count(rdata) == 1);
		uint16_t size = knot_rdata_item(rdata, 0)->raw_data[0];
		const uint8_t *raw = (const uint8_t *)
		                      knot_rdata_item(rdata, 0)->raw_data;
		int pos = 2;
		assert(size > 0);
		while (pos - 2 < size) {
			// ensure there is enough data to parse the OPTION CODE
			// and OPTION LENGTH
			if (size - pos + 2 < 4) {
				dbg_edns("Not enough data to parse.\n");
				return KNOT_EMALF;
			}
			uint16_t opt_code = knot_wire_read_u16(raw + pos);
			uint16_t opt_size = knot_wire_read_u16(raw + pos + 2);

			// there should be enough data for parsing the OPTION
			// data
			if (size - pos - 2 < opt_size) {
				dbg_edns("Not enough data to parse options: "
				         "size - pos - 2=%d, opt_size=%d\n",
				         size - pos - 2, opt_size);
				return KNOT_EMALF;
			}
			rc = knot_edns_add_option(opt_rr, opt_code, opt_size,
			                          raw + pos + 4);
			if (rc != KNOT_EOK) {
				dbg_edns("Could not add option.\n");
				return rc;
			}
			pos += 4 + opt_size;
		}
	}
	
	
	dbg_edns("EDNS created.\n");

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_edns_get_payload(const knot_opt_rr_t *opt_rr)
{
	assert(opt_rr != NULL);
	return opt_rr->payload;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_payload(knot_opt_rr_t *opt_rr,
                             uint16_t payload)
{
	assert(opt_rr != NULL);
	opt_rr->payload = payload;
}

/*----------------------------------------------------------------------------*/

uint8_t knot_edns_get_ext_rcode(const knot_opt_rr_t *opt_rr)
{
	return opt_rr->ext_rcode;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_ext_rcode(knot_opt_rr_t *opt_rr,
                               uint8_t ext_rcode)
{
	assert(opt_rr != NULL);
	opt_rr->ext_rcode = ext_rcode;
}

/*----------------------------------------------------------------------------*/

uint8_t knot_edns_get_version(const knot_opt_rr_t *opt_rr)
{
	assert(opt_rr != NULL);
	return opt_rr->version;
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_version(knot_opt_rr_t *opt_rr,
                                           uint8_t version)
{
	assert(opt_rr != NULL);
	opt_rr->version = version;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_edns_get_flags(const knot_opt_rr_t *opt_rr)
{
	assert(opt_rr != NULL);
	return opt_rr->flags;
}

/*----------------------------------------------------------------------------*/

int knot_edns_do(const knot_opt_rr_t *opt_rr)
{
	if (opt_rr == NULL) {
		return KNOT_EBADARG;
	}

	dbg_edns("Flags: %u\n", opt_rr->flags);
	return (opt_rr->flags & KNOT_EDNS_DO_MASK);
}

/*----------------------------------------------------------------------------*/

void knot_edns_set_do(knot_opt_rr_t *opt_rr)
{
	if (opt_rr == NULL) {
		return;
	}

	opt_rr->flags |= KNOT_EDNS_DO_MASK;
}

/*----------------------------------------------------------------------------*/

int knot_edns_add_option(knot_opt_rr_t *opt_rr, uint16_t code,
                           uint16_t length, const uint8_t *data)
{
	if (opt_rr == NULL) {
		return KNOT_EBADARG;
	}

	if (opt_rr->option_count == opt_rr->options_max) {
		knot_opt_option_t *options_new =
			(knot_opt_option_t *)calloc(
				(opt_rr->options_max + KNOT_EDNS_OPTION_STEP),
				sizeof(knot_opt_option_t));
		CHECK_ALLOC_LOG(options_new, KNOT_ENOMEM);
		memcpy(options_new, opt_rr->options, opt_rr->option_count);

		knot_opt_option_t *old_options = opt_rr->options;
		opt_rr->options = options_new;
		opt_rr->options_max += KNOT_EDNS_OPTION_STEP;
		free(old_options);
	}

	dbg_edns("Adding option.\n");
	dbg_edns("Code: %u.\n", code);
	dbg_edns("Length: %u.\n", length);
	dbg_edns("Data: %p.\n", data);

	opt_rr->options[opt_rr->option_count].data = (uint8_t *)malloc(length);
	CHECK_ALLOC_LOG(opt_rr->options[opt_rr->option_count].data, KNOT_ENOMEM);
	memcpy(opt_rr->options[opt_rr->option_count].data, data, length);

	opt_rr->options[opt_rr->option_count].code = code;
	opt_rr->options[opt_rr->option_count].length = length;

	++opt_rr->option_count;
	opt_rr->size += 4 + length;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_edns_has_option(const knot_opt_rr_t *opt_rr, uint16_t code)
{
	if (opt_rr == NULL) {
		return KNOT_EBADARG;
	}

	int i = 0;
	while (i < opt_rr->option_count && opt_rr->options[i].code != code) {
		++i;
	}

	assert(i >= opt_rr->option_count || opt_rr->options[i].code == code);

	return (i < opt_rr->option_count);
}

/*----------------------------------------------------------------------------*/

short knot_edns_to_wire(const knot_opt_rr_t *opt_rr, uint8_t *wire,
                          size_t max_size)
{
	if (opt_rr == NULL) {
		return KNOT_EBADARG;
	}

	assert(KNOT_EDNS_MIN_SIZE <= max_size);

	if (max_size < opt_rr->size) {
		dbg_edns("Not enough place for OPT RR wire format.\n");
		return KNOT_ESPACE;
	}

	uint8_t *pos = wire;

	dbg_edns_detail("Putting OPT RR to the wire format. Size: %zu, "
	                "position: %zu\n",
	                opt_rr->size, (size_t)(pos - wire));

	*(pos++) = 0;
	knot_wire_write_u16(pos, KNOT_RRTYPE_OPT);
	pos += 2;
	knot_wire_write_u16(pos, opt_rr->payload);
	pos += 2;
	*(pos++) = opt_rr->ext_rcode;
	*(pos++) = opt_rr->version;
	knot_wire_write_u16(pos, opt_rr->flags);
	pos += 2;

	dbg_edns_detail("Leaving space for RDLENGTH at pos %zu\n",
	                (size_t)(pos - wire));

	uint8_t *rdlen = pos;
	uint16_t len = 0;
	pos += 2;

	// OPTIONs
	for (int i = 0; i < opt_rr->option_count; ++i) {
		dbg_edns_detail("Inserting option #%d at pos %zu\n",
		                i, (size_t)(pos - wire));
		knot_wire_write_u16(pos, opt_rr->options[i].code);
		pos += 2;
		knot_wire_write_u16(pos, opt_rr->options[i].length);
		pos += 2;
		memcpy(pos, opt_rr->options[i].data, opt_rr->options[i].length);
		pos += opt_rr->options[i].length;
		len += 4 + opt_rr->options[i].length;
	}

	dbg_edns_detail("Final pos %zu\n", (size_t)(pos - wire));

	knot_wire_write_u16(rdlen, len);

	return opt_rr->size;
}

/*----------------------------------------------------------------------------*/

short knot_edns_size(knot_opt_rr_t *opt_rr)
{
	if (opt_rr == NULL) {
		return KNOT_EBADARG;
	}

	return opt_rr->size;
}

/*----------------------------------------------------------------------------*/

void knot_edns_free_options(knot_opt_rr_t *opt_rr)
{
	if (opt_rr->option_count > 0) {
		/* Free the option data, if any. */
		for (int i = 0; i < opt_rr->option_count; i++) {
			struct knot_opt_option option = opt_rr->options[i];
			if (option.data != NULL) {
				free(option.data);
			}
		}
		free(opt_rr->options);
	}
}

/*----------------------------------------------------------------------------*/

void knot_edns_free(knot_opt_rr_t **opt_rr)
{
	if (opt_rr == NULL || *opt_rr == NULL) {
		return;
	}

	knot_edns_free_options(*opt_rr);

	free(*opt_rr);
	*opt_rr = NULL;
}
