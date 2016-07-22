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
#include <sys/socket.h>

#include "libknot/attribute.h"
#include "libknot/consts.h"
#include "libknot/rrtype/opt.h"
#include "libknot/descriptor.h"
#include "contrib/wire_ctx.h"
#include "contrib/wire.h"

/*! \brief Some implementation-related constants. */
enum knot_edns_private_consts {
	/*! \brief Bit mask for DO bit. */
	EDNS_DO_MASK = (uint32_t)(1 << 15),

	/*! \brief Byte offset of the extended RCODE field in TTL. */
	EDNS_OFFSET_RCODE   = 0,
	/*! \brief Byte offset of the version field in TTL. */
	EDNS_OFFSET_VERSION = 1,

	/*! \brief Byte offset of the family field in option data. */
	EDNS_OFFSET_CLIENT_SUBNET_FAMILY   = 0,
	/*! \brief Byte offset of the source mask field in option data. */
	EDNS_OFFSET_CLIENT_SUBNET_SRC_MASK = 2,
	/*! \brief Byte offset of the destination mask field in option data. */
	EDNS_OFFSET_CLIENT_SUBNET_DST_MASK = 3,
	/*! \brief Byte offset of the address field in option data. */
	EDNS_OFFSET_CLIENT_SUBNET_ADDR     = 4,
};

/*----------------------------------------------------------------------------*/
_public_
int knot_edns_init(knot_rrset_t *opt_rr, uint16_t max_pld,
                  uint8_t ext_rcode, uint8_t ver, knot_mm_t *mm)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	/* Initialize RRSet. */
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
_public_
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
_public_
uint16_t knot_edns_get_payload(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);
	return opt_rr->rclass;
}

/*----------------------------------------------------------------------------*/
_public_
void knot_edns_set_payload(knot_rrset_t *opt_rr, uint16_t payload)
{
	assert(opt_rr != NULL);
	opt_rr->rclass = payload;
}

/*----------------------------------------------------------------------------*/
_public_
uint8_t knot_edns_get_ext_rcode(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);
	uint32_t ttl = 0;
	wire_ctx_t w = wire_ctx_init((uint8_t *) &ttl, sizeof(ttl));
	// TTL is stored in machine byte order. Convert it to wire order first.
	wire_ctx_write_u32(&w, knot_rrset_ttl(opt_rr));
	wire_ctx_set_offset(&w, EDNS_OFFSET_RCODE);
	return wire_ctx_read_u8(&w);
}

/*----------------------------------------------------------------------------*/

static void set_value_to_ttl(knot_rrset_t *opt_rr, size_t offset, uint8_t value)
{
	uint32_t ttl = 0;
	wire_ctx_t w = wire_ctx_init((uint8_t*) &ttl, sizeof(ttl));
	// TTL is stored in machine byte order. Convert it to wire order first.
	wire_ctx_write_u32(&w, knot_rrset_ttl(opt_rr));
	// Set the Extended RCODE in the converted TTL
	wire_ctx_set_offset(&w, offset);
	wire_ctx_write_u8(&w, value);
	// Convert it back to machine byte order
	wire_ctx_set_offset(&w, 0);
	uint32_t ttl_local = wire_ctx_read_u32(&w);
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl_local);
}

/*----------------------------------------------------------------------------*/
_public_
void knot_edns_set_ext_rcode(knot_rrset_t *opt_rr, uint8_t ext_rcode)
{
	assert(opt_rr != NULL);
	set_value_to_ttl(opt_rr, EDNS_OFFSET_RCODE, ext_rcode);
}

/*----------------------------------------------------------------------------*/
_public_
uint8_t knot_edns_get_version(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);
	uint32_t ttl = 0;
	wire_ctx_t w = wire_ctx_init((uint8_t*) &ttl, sizeof(ttl));
	// TTL is stored in machine byte order. Convert it to wire order first.
	wire_ctx_write_u32(&w, knot_rrset_ttl(opt_rr));
	wire_ctx_set_offset(&w, EDNS_OFFSET_VERSION);
	return wire_ctx_read_u8(&w);
}

/*----------------------------------------------------------------------------*/
_public_
void knot_edns_set_version(knot_rrset_t *opt_rr, uint8_t version)
{
	assert(opt_rr != NULL);
	set_value_to_ttl(opt_rr, EDNS_OFFSET_VERSION, version);
}

/*----------------------------------------------------------------------------*/
_public_
bool knot_edns_do(const knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);
	return knot_rrset_ttl(opt_rr) & EDNS_DO_MASK;
}

/*----------------------------------------------------------------------------*/
_public_
void knot_edns_set_do(knot_rrset_t *opt_rr)
{
	assert(opt_rr != NULL);

	// Read the TTL
	uint32_t ttl = knot_rrset_ttl(opt_rr);
	// Set the DO bit
	ttl |= EDNS_DO_MASK;
	// Store the TTL to the RDATA
	knot_rdata_set_ttl(knot_rdataset_at(&opt_rr->rrs, 0), ttl);
}

/*----------------------------------------------------------------------------*/
/*!
 * \brief Skips an option from the supplied \a wire data.
 *
 * \param      wire      Wire data containing sequence of OPT RDATA.
 * \param[out] code      Code of the option that is at hand.
 * \param[out] full_len  Length of the entire skipped option with its header.
 *
 * \return Pointer to the first byte of the entire skipped option,
 *         NULL when none or incomplete option data left.
 */
static uint8_t *skip_option(wire_ctx_t *wire,
                            uint16_t *code, uint16_t *full_len)
{
	assert(wire && code && full_len);

	uint8_t *position = NULL;

	if (wire_ctx_available(wire) > 0) {
		position = wire->position;
		uint16_t opt_code = wire_ctx_read_u16(wire);
		if (wire->error != KNOT_EOK) {
			return NULL;
		}

		uint16_t opt_len = wire_ctx_read_u16(wire);
		wire_ctx_skip(wire, opt_len);
		/*
		 * Return position only when the entire option fits
		 * in the RDATA.
		 */
		if (wire->error == KNOT_EOK) {
			*code = opt_code;
			*full_len = KNOT_EDNS_OPTION_HDRLEN + opt_len;
			return position;
		}
	}

	return NULL;
}

/*!
 * \brief Find OPTION with the given code in the OPT RDATA.
 *
 * \note It is ensured that the full option, as declared in option length,
 *       is encompassed in the RDATA when found.
 *
 * \param rdata     RDATA to search in.
 * \param opt_code  Code of the OPTION to find.
 *
 * \return Pointer to the first byte of the first option that matches
 *         \a opt_code, NULL if no option found or error occurred.
 */
static uint8_t *find_option(knot_rdata_t *rdata, uint16_t opt_code)
{
	wire_ctx_t wire = wire_ctx_init_const(knot_rdata_data(rdata),
	                                      knot_rdata_rdlen(rdata));
	uint8_t *position = NULL;
	uint16_t code, full_len;

	while ((position = skip_option(&wire, &code, &full_len)) != NULL) {
		if (code == opt_code) {
			return position;
		}
	}

	return NULL;
}

/*!
 * \brief Removes all occurrences of options with given \a code. Shoves all
 *        remaining options toward beginning. Takes first opportunity to use
 *        freed space to reserve option, if reservation required.
 *
 * \note When adding an option then it may be placed into first suitable place
 *       i.e. not necessary at the end.
 *
 * \param[in]  opt_rr    OPT RR in the packet.
 * \param[in]  code      Option code.
 * \param[in]  reserve   False when options should only be deleted.
 * \param[in]  size      Desired option size.
 * \param[out] wire_ptr  Pointer to reserved option data (can be NULL).
 * \param[in]  mm        Memory context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int delete_and_reserve_option(knot_rrset_t *opt_rr, uint16_t code,
                                     bool reserve, uint16_t size,
                                     uint8_t **wire_ptr, knot_mm_t *mm)
{
	assert(opt_rr != NULL);

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	assert(rdata != NULL);
	wire_ctx_t rd_wire = wire_ctx_init_const(knot_rdata_data(rdata),
	                                         knot_rdata_rdlen(rdata));
	wire_ctx_t wr_wire = wire_ctx_init(knot_rdata_data(rdata),
	                                   knot_rdata_rdlen(rdata));

	uint16_t deleted_len = 0; // Total area length acquired by deleting.

	uint8_t *rd_pos = NULL;
	uint8_t *wr_pos = NULL; // Set non-null if enough freed space found.
	uint16_t opt_code, full_len;

	// Removes, shove and reserve if have enough place.
	while ((rd_pos = skip_option(&rd_wire, &opt_code, &full_len)) != NULL) {
		if (opt_code != code) {
			if (deleted_len == 0) {
				// No data must be shoved towards front.
				wire_ctx_skip(&wr_wire, full_len);
				assert(wr_wire.error == KNOT_EOK);
			} else if (deleted_len >= full_len) {
				// There is enough space for a copy.
				wire_ctx_write(&wr_wire, rd_pos, full_len);
				assert(wr_wire.error == KNOT_EOK);
			} else {
				// There isn't enough space for a copy.
				memmove(knot_rdata_data(rdata) + wire_ctx_offset(&wr_wire),
				        rd_pos, full_len);
				wire_ctx_skip(&wr_wire, full_len);
				assert(wr_wire.error == KNOT_EOK);
			}
		} else {
			deleted_len += full_len;
			if (reserve && !wr_pos &&
			    deleted_len >= (KNOT_EDNS_OPTION_HDRLEN + size)) {
				// Reserve this freed space.
				wr_pos = knot_rdata_data(rdata) + wire_ctx_offset(&wr_wire);
				deleted_len -= KNOT_EDNS_OPTION_HDRLEN + size;
				wire_ctx_skip(&wr_wire, KNOT_EDNS_OPTION_HDRLEN + size);
			}
		}
	}

	if (deleted_len > 0) {
		// Adjust data length.
		assert(knot_rdata_rdlen(rdata) >= deleted_len);
		knot_rdata_set_rdlen(rdata, knot_rdata_rdlen(rdata) - deleted_len);
	}

	if (reserve && wr_pos) {
		// Found enough space when deleting entries.
		wire_ctx_t wire = wire_ctx_init(wr_pos, KNOT_EDNS_OPTION_HDRLEN + size);
		wire_ctx_write_u16(&wire, code);
		wire_ctx_write_u16(&wire, size);
		size_t offset = wire_ctx_offset(&wire);
		wire_ctx_clear(&wire, size);
		if (wire_ptr) {
			*wire_ptr = wr_pos + offset;
		}
	} else if (reserve) {
		return knot_edns_reserve_option(opt_rr, code, size, wire_ptr, mm);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

/*!
 * \brief Add new EDNS option by replacing RDATA of OPT RR.
 *
 * \param opt   OPT RR structure to add the Option to.
 * \param code  Option code.
 * \param size  Option data length in bytes.
 * \param mm    Memory context.
 *
 * \return Pointer to uninitialized option data.
 */
static uint8_t *edns_add(knot_rrset_t *opt, uint16_t code, uint16_t size,
                         knot_mm_t *mm)
{
	assert(opt->rrs.rr_count == 1);

	// extract old RDATA

	knot_rdata_t *old_rdata = knot_rdataset_at(&opt->rrs, 0);
	uint8_t *old_data = knot_rdata_data(old_rdata);
	uint16_t old_data_len = knot_rdata_rdlen(old_rdata);

	// construct new RDATA

	uint16_t new_data_len = old_data_len + KNOT_EDNS_OPTION_HDRLEN + size;
	uint8_t new_data[new_data_len];

	wire_ctx_t wire = wire_ctx_init(new_data, new_data_len);
	wire_ctx_write(&wire, old_data, old_data_len);
	wire_ctx_write_u16(&wire, code);
	wire_ctx_write_u16(&wire, size);

	// prepare EDNS option data

	size_t offset = wire_ctx_offset(&wire);
	wire_ctx_clear(&wire, size);

	assert(wire_ctx_available(&wire) == 0);
	assert(wire.error == KNOT_EOK);

	// replace RDATA

	uint32_t ttl = knot_rdata_ttl(old_rdata);
	knot_rdataset_clear(&opt->rrs, mm);
	if (knot_rrset_add_rdata(opt, new_data, new_data_len, ttl, mm) != KNOT_EOK) {
		return NULL;
	}

	return knot_rdata_data(knot_rdataset_at(&opt->rrs, 0)) + offset;
}

_public_
int knot_edns_remove_options(knot_rrset_t *opt_rr, uint16_t code)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	return delete_and_reserve_option(opt_rr, code, false, 0, NULL, NULL);
}

_public_
int knot_edns_reserve_unique_option(knot_rrset_t *opt_rr, uint16_t code,
                                    uint16_t size, uint8_t **wire_ptr,
                                    knot_mm_t *mm)
{
	if (opt_rr == NULL) {
		return KNOT_EINVAL;
	}

	return delete_and_reserve_option(opt_rr, code, true, size, wire_ptr, mm);
}

_public_
int knot_edns_reserve_option(knot_rrset_t *opt_rr, uint16_t code,
                             uint16_t size, uint8_t **wire_ptr, knot_mm_t *mm)
{
	if (!opt_rr) {
		return KNOT_EINVAL;
	}

	uint8_t *wire = edns_add(opt_rr, code, size, mm);
	if (!wire) {
		return KNOT_ENOMEM;
	}

	if (wire_ptr) {
		*wire_ptr = wire;
	}

	return KNOT_EOK;
}

_public_
int knot_edns_add_option(knot_rrset_t *opt_rr, uint16_t code,
                         uint16_t size, const uint8_t *data, knot_mm_t *mm)
{
	if (!opt_rr || (size > 0 && !data)) {
		return KNOT_EINVAL;
	}

	uint8_t *wire = edns_add(opt_rr, code, size, mm);
	if (!wire) {
		return KNOT_ENOMEM;
	}

	memcpy(wire, data, size);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
_public_
bool knot_edns_has_option(const knot_rrset_t *opt_rr, uint16_t code)
{
	assert(opt_rr != NULL);

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	assert(rdata != NULL);

	uint8_t *pos = find_option(rdata, code);

	return pos != NULL;
}

_public_
uint8_t *knot_edns_get_option(const knot_rrset_t *opt_rr, uint16_t code)
{
	assert(opt_rr != NULL);

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	assert(rdata != NULL);

	return find_option(rdata, code);
}

_public_
uint16_t knot_edns_opt_get_code(const uint8_t *opt)
{
	assert(opt != NULL);

	return wire_read_u16(opt);
}

_public_
uint16_t knot_edns_opt_get_length(const uint8_t *opt)
{
	assert(opt != NULL);

	return wire_read_u16(opt + sizeof(uint16_t));
}

/*----------------------------------------------------------------------------*/
_public_
bool knot_edns_check_record(knot_rrset_t *opt_rr)
{
	if (opt_rr->rrs.rr_count != 1) {
		return false;
	}

	knot_rdata_t *rdata = knot_rdataset_at(&opt_rr->rrs, 0);
	if (rdata == NULL) {
		return false;
	}

	wire_ctx_t wire = wire_ctx_init_const(knot_rdata_data(rdata),
	                                      knot_rdata_rdlen(rdata));

	/* RFC2671 4.4: {uint16_t code, uint16_t len, data} */
	// read data to the end or error
	while (wire_ctx_available(&wire) > 0 && wire.error == KNOT_EOK) {
		wire_ctx_read_u16(&wire); 			// code
		uint16_t opt_len = wire_ctx_read_u16(&wire);	// length
		wire_ctx_skip(&wire, opt_len);			// data
	}

	return wire.error == KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
_public_
int knot_edns_client_subnet_create(const knot_addr_family_t family,
                                   const uint8_t *addr,
                                   const uint16_t addr_len,
                                   uint8_t src_mask,
                                   uint8_t dst_mask,
                                   uint8_t *data,
                                   uint16_t *data_len)
{
	if (addr == NULL || data == NULL || data_len == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t addr_prefix_len = (src_mask + 7) / 8; // Ceiling operation.
	uint8_t modulo = src_mask % 8;

	if (addr_prefix_len > addr_len) {
		return KNOT_EINVAL;
	}

	wire_ctx_t wire = wire_ctx_init(data, *data_len);
	wire_ctx_write_u16(&wire, family);
	wire_ctx_write_u8(&wire, src_mask);
	wire_ctx_write_u8(&wire, dst_mask);
	wire_ctx_write(&wire, addr, addr_prefix_len);

	if (wire.error != KNOT_EOK) {
		return wire.error;
	}

	// Zeroize trailing bits in the last byte.
	if (modulo > 0 && addr_prefix_len > 0) {
		wire.position[-1] &= 0xFF << (8 - modulo);
	}

	*data_len = wire_ctx_offset(&wire);

	return KNOT_EOK;
}

_public_
int knot_edns_client_subnet_parse(const uint8_t *data,
                                  const uint16_t data_len,
                                  knot_addr_family_t *family,
                                  uint8_t *addr,
                                  uint16_t *addr_len,
                                  uint8_t *src_mask,
                                  uint8_t *dst_mask)
{
	if (data == NULL || family == NULL || addr == NULL ||
	    addr_len == NULL || src_mask == NULL || dst_mask == NULL) {
		return KNOT_EINVAL;
	}

	wire_ctx_t wire = wire_ctx_init_const(data, data_len);

	*family = wire_ctx_read_u16(&wire);
	*src_mask = wire_ctx_read_u8(&wire);
	*dst_mask = wire_ctx_read_u8(&wire);
	*addr_len = wire_ctx_available(&wire);
	wire_ctx_read(&wire, addr, *addr_len);

	if (wire.error != KNOT_EOK) {
		return wire.error;
	}

	return KNOT_EOK;
}
