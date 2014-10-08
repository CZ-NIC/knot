/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libknot/common.h"
#include "libknot/consts.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/packet/pkt.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/packet/wire.h"
#include "libknot/rrset.h"

/*!
 * \brief Get maximal size of a domain name in a wire with given capacity.
 */
static uint16_t dname_max(size_t wire_avail)
{
	return MIN(wire_avail, KNOT_DNAME_MAXLEN);
}

/*!
 * \brief Get compression pointer for a given hint.
 */
static uint16_t compr_get_ptr(knot_compr_t *compr, uint16_t hint)
{
	if (compr == NULL) {
		return 0;
	}

	return knot_pkt_compr_hint(compr->rrinfo, hint);
}

/*!
 * \brief Set compression pointer for a given hint.
 */
static void compr_set_ptr(knot_compr_t *compr, uint16_t hint,
                          const uint8_t *written_at, uint16_t written_size)
{
	if (compr == NULL) {
		return;
	}

	assert(written_at >= compr->wire);

	uint16_t offset = written_at - compr->wire;

	knot_pkt_compr_hint_set(compr->rrinfo, hint, offset, written_size);
}

/*!
 * \brief Write fixed-size RDATA field.
 */
static int write_rdata_fixed(const uint8_t **src, size_t *src_avail,
                             uint8_t **dst, size_t *dst_avail, size_t size)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);

	/* Check input/output buffer boundaries */

	if (size > *src_avail) {
		return KNOT_EMALF;
	}

	if (size > *dst_avail) {
		return KNOT_ESPACE;
	}

	/* Data binary copy */

	memcpy(*dst, *src, size);

	/* Update buffers */

	*src += size;
	*src_avail -= size;

	*dst += size;
	*dst_avail -= size;

	return KNOT_EOK;
}

/*!
 * \brief Write NAPTR RDATA header.
 */
static int write_rdata_naptr_header(const uint8_t **src, size_t *src_avail,
                                    uint8_t **dst, size_t *dst_avail)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);

	size_t size = 0;

	/* Fixed fields size (order, preference) */

	size += 2 * sizeof(uint16_t);

	/* Variable fields size (flags, services, regexp) */

	for (int i = 0; i < 3; i++) {
		const uint8_t *len_ptr = *src + size;
		if (len_ptr >= *src + *src_avail) {
			return KNOT_EMALF;
		}

		size += 1 + *len_ptr;
	}

	/* Copy the data */

	return write_rdata_fixed(src, src_avail, dst, dst_avail, size);
}

/*!
 * \brief DNAME RDATA processing config.
 */
struct dname_config {
	int (*write_cb)(const uint8_t **src, size_t *src_avail,
	                uint8_t **dst, size_t *dst_avail,
	                int dname_type, struct dname_config *dname_cfg,
	                knot_rrset_wire_flags_t flags);
	knot_compr_t *compr;
	uint16_t hint;
	const uint8_t *pkt_wire;
};

typedef struct dname_config dname_config_t;

/*!
 * \brief Write one RDATA block to wire.
 */
static int write_rdata_block(const uint8_t **src, size_t *src_avail,
                             uint8_t **dst, size_t *dst_avail,
                             int type, dname_config_t *dname_cfg,
                             knot_rrset_wire_flags_t flags)
{
	switch (type) {
	case KNOT_RDATA_WF_COMPRESSIBLE_DNAME:
	case KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME:
	case KNOT_RDATA_WF_FIXED_DNAME:
		return dname_cfg->write_cb(src, src_avail, dst, dst_avail,
		                           type, dname_cfg, flags);
	case KNOT_RDATA_WF_NAPTR_HEADER:
		return write_rdata_naptr_header(src, src_avail, dst, dst_avail);
	case KNOT_RDATA_WF_REMAINDER:
		return write_rdata_fixed(src, src_avail, dst, dst_avail, *src_avail);
	default:
		/* Fixed size block */
		assert(type > 0);
		return write_rdata_fixed(src, src_avail, dst, dst_avail, type);
	}
}

/*!
 * \brief Iterate over RDATA blocks.
 */
static int rdata_traverse(const uint8_t **src, size_t *src_avail,
                          uint8_t **dst, size_t *dst_avail,
                          const rdata_descriptor_t *desc,
                          dname_config_t *dname_cfg, knot_rrset_wire_flags_t flags)
{
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int block_type = desc->block_types[i];
		int ret = write_rdata_block(src, src_avail, dst, dst_avail,
		                            block_type, dname_cfg, flags);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*- RRSet to wire -----------------------------------------------------------*/

/*!
 * \brief Write RR owner to wire.
 */
static int write_owner(const knot_rrset_t *rrset, uint8_t **dst, size_t *dst_avail,
                       knot_compr_t *compr, knot_rrset_wire_flags_t flags)
{
	assert(rrset);
	assert(dst && *dst);
	assert(dst_avail);

	uint16_t owner_pointer = compr_get_ptr(compr, COMPR_HINT_OWNER);

	/* Check size */

	size_t owner_size = 0;
	if (owner_pointer > 0) {
		owner_size = sizeof(uint16_t);
	} else {
		owner_size = knot_dname_size(rrset->owner);
	}

	if (owner_size > *dst_avail) {
		return KNOT_ESPACE;
	}

	/* Write result */

	if (owner_pointer > 0) {
		knot_wire_put_pointer(*dst, owner_pointer);
	} else {
		int written = knot_compr_put_dname(rrset->owner, *dst,
		                                   dname_max(*dst_avail), compr);
		if (written < 0) {
			return written;
		}

		if (flags & KNOT_RRSET_WIRE_CANONICAL) {
			assert(compr == NULL);
			knot_dname_to_lower(*dst);
		}

		compr_set_ptr(compr, COMPR_HINT_OWNER, *dst, written);
		owner_size = written;
	}

	/* Update buffer */

	*dst += owner_size;
	*dst_avail -= owner_size;

	return KNOT_EOK;
}

/*!
 * \brief Write RR type, class, and TTL to wire.
 */
static int write_fixed_header(const knot_rrset_t *rrset, uint16_t rrset_index,
                              uint8_t **dst, size_t *dst_avail)
{
	assert(rrset);
	assert(rrset_index < rrset->rrs.rr_count);
	assert(dst && *dst);
	assert(dst_avail);

	/* Check capacity */

	size_t size = sizeof(uint16_t)  // type
	            + sizeof(uint16_t)  // class
	            + sizeof(uint32_t); // ttl

	if (size > *dst_avail) {
		return KNOT_ESPACE;
	}

	/* Write result */

	uint32_t ttl = knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, rrset_index));
	uint8_t *write = *dst;

	knot_wire_write_u16(write, rrset->type);
	write += sizeof(uint16_t);
	knot_wire_write_u16(write, rrset->rclass);
	write += sizeof(uint16_t);
	knot_wire_write_u32(write, ttl);
	write += sizeof(uint32_t);

	assert(write == *dst + size);

	/* Update buffer */

	*dst = write;
	*dst_avail -= size;

	return KNOT_EOK;
}

/*!
 * \brief Write RDATA DNAME to wire.
 */
static int compress_rdata_dname(const uint8_t **src, size_t *src_avail,
                                uint8_t **dst, size_t *dst_avail,
                                int dname_type, dname_config_t *dname_cfg,
                                knot_rrset_wire_flags_t flags)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);
	assert(dname_cfg);

	/* Source domain name */

	const knot_dname_t *dname = *src;
	size_t dname_size = knot_dname_size(dname);

	/* Output domain name */

	knot_compr_t *put_compr = NULL;
	if (dname_type == KNOT_RDATA_WF_COMPRESSIBLE_DNAME) {
		put_compr = dname_cfg->compr;
	}

	int written = knot_compr_put_dname(dname, *dst, dname_max(*dst_avail),
	                                   put_compr);
	if (written < 0) {
		assert(written == KNOT_ESPACE);
		return written;
	}

	/* Post-processing */

	if (flags & KNOT_RRSET_WIRE_CANONICAL) {
		assert(dname_cfg->compr == NULL);
		knot_dname_to_lower(*dst);
	}

	/* Update compression hints */

	if (compr_get_ptr(dname_cfg->compr, dname_cfg->hint) == 0) {
		compr_set_ptr(dname_cfg->compr, dname_cfg->hint, *dst, written);
	}

	/* Update buffers */

	*dst += written;
	*dst_avail -= written;

	*src += dname_size;
	*src_avail -= dname_size;

	return KNOT_EOK;
}

/*!
 * \brief Write RDLENGTH and RDATA fields of a RR in a wire.
 */
static int write_rdata(const knot_rrset_t *rrset, uint16_t rrset_index,
                       uint8_t **dst, size_t *dst_avail,
                       knot_compr_t *compr, knot_rrset_wire_flags_t flags)
{
	assert(rrset);
	assert(rrset_index < rrset->rrs.rr_count);
	assert(dst && *dst);
	assert(dst_avail);

	const knot_rdata_t *rdata = knot_rdataset_at(&rrset->rrs, rrset_index);

	/* Reserve space for RDLENGTH */

	if (sizeof(uint16_t) > *dst_avail) {
		return KNOT_ESPACE;
	}

	uint8_t *wire_rdlength = *dst;
	*dst += sizeof(uint16_t);
	*dst_avail -= sizeof(uint16_t);

	/* Write RDATA */

	uint8_t *wire_rdata_begin = *dst;
	dname_config_t dname_cfg = {
		.write_cb = compress_rdata_dname,
		.compr = compr,
		.hint = COMPR_HINT_RDATA + rrset_index
	};

	const uint8_t *src = knot_rdata_data(rdata);
	size_t src_avail = knot_rdata_rdlen(rdata);
	if (src_avail > 0) {
		/* Only write non-empty data. */
		const rdata_descriptor_t *desc =
			knot_get_rdata_descriptor(rrset->type);
		int ret = rdata_traverse(&src, &src_avail, dst, dst_avail,
		                         desc, &dname_cfg, flags);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (src_avail > 0) {
		/* Trailing data in the message. */
		return KNOT_EMALF;
	}

	/* Write final RDLENGTH */

	size_t rdlength = *dst - wire_rdata_begin;
	knot_wire_write_u16(wire_rdlength, rdlength);

	return KNOT_EOK;
}

/*!
 * \brief Write one RR from a RR Set to wire.
 */
static int write_rr(const knot_rrset_t *rrset, uint16_t rrset_index,
                    uint8_t **dst, size_t *dst_avail, knot_compr_t *compr,
                    knot_rrset_wire_flags_t flags)
{
	int ret;

	ret = write_owner(rrset, dst, dst_avail, compr, flags);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = write_fixed_header(rrset, rrset_index, dst, dst_avail);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return write_rdata(rrset, rrset_index, dst, dst_avail, compr, flags);
}

/*!
 * \brief Write RR Set content to a wire.
 */
int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, uint16_t max_size,
                       knot_compr_t *compr, knot_rrset_wire_flags_t flags)
{
	if (!rrset || !wire) {
		return KNOT_EINVAL;
	}

	if (flags & KNOT_RRSET_WIRE_CANONICAL) {
		compr = NULL;
	}

	uint8_t *write = wire;
	size_t capacity = max_size;

	for (uint16_t i = 0; i < rrset->rrs.rr_count; i++) {
		int ret = write_rr(rrset, i, &write, &capacity, compr, flags);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	size_t written = write - wire;

	return written;
}

/*- RRSet from wire ---------------------------------------------------------*/

#define RR_HEADER_SIZE 10
#define MAX_RDLENGTH 65535

/*!
 * \brief Parse header of one RR from packet wireformat.
 */
static int parse_header(const uint8_t *pkt_wire, size_t *pos, size_t pkt_size,
                        mm_ctx_t *mm, knot_rrset_t *rrset, uint32_t *ttl,
                        uint16_t *rdlen)
{
	assert(pkt_wire);
	assert(pos);
	assert(rrset);
	assert(ttl);
	assert(rdlen);

	knot_dname_t *owner = knot_dname_parse(pkt_wire, pos, pkt_size, mm);
	if (owner == NULL) {
		return KNOT_EMALF;
	}
	knot_dname_to_lower(owner);

	if (pkt_size - *pos < RR_HEADER_SIZE) {
		knot_dname_free(&owner, mm);
		return KNOT_EMALF;
	}

	uint16_t type = knot_wire_read_u16(pkt_wire + *pos);
	*pos += sizeof(uint16_t);
	uint16_t rclass = knot_wire_read_u16(pkt_wire + *pos);
	*pos += sizeof(uint16_t);
	*ttl = knot_wire_read_u32(pkt_wire + *pos);
	*pos += sizeof(uint32_t);
	*rdlen = knot_wire_read_u16(pkt_wire + *pos);
	*pos += sizeof(uint16_t);

	if (pkt_size - *pos < *rdlen) {
		knot_dname_free(&owner, mm);
		return KNOT_EMALF;
	}

	knot_rrset_init(rrset, owner, type, rclass);

	return KNOT_EOK;
}

/*!
 * \brief Parse and decompress RDATA.
 */
static int decompress_rdata_dname(const uint8_t **src, size_t *src_avail,
                                  uint8_t **dst, size_t *dst_avail,
                                  int dname_type, dname_config_t *dname_cfg,
                                  knot_rrset_wire_flags_t flags)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);
	assert(dname_cfg);
	UNUSED(flags);

	int compr_size = knot_dname_wire_check(*src, *src + *src_avail, dname_cfg->pkt_wire);
	if (compr_size <= 0) {
		return compr_size;
	}
	
	int decompr_size = knot_dname_unpack(*dst, *src, *dst_avail, dname_cfg->pkt_wire);
	if (decompr_size <= 0) {
		return decompr_size;
	}
	
	/* Update buffers */
	*dst += decompr_size;
	*dst_avail -= decompr_size;

	*src += compr_size;
	*src_avail -= compr_size;

	return KNOT_EOK;
}

static bool allow_zero_rdata(const knot_rrset_t *rr, const rdata_descriptor_t *desc)
{
	return rr->rclass != KNOT_CLASS_IN ||  // NONE and ANY for DDNS
	       rr->type == KNOT_RRTYPE_APL ||  // APL RR type
	       desc->type_name == NULL;        // Unknown RR type
}

/*!
 * \brief Parse RDATA part of one RR from packet wireformat.
 */
static int parse_rdata(const uint8_t *pkt_wire, size_t *pos, size_t pkt_size,
                       mm_ctx_t *mm, uint32_t ttl, uint16_t rdlength,
                       knot_rrset_t *rrset)
{
	assert(pkt_wire);
	assert(pos);
	assert(rrset);

	if (pkt_size - *pos < rdlength) {
		return KNOT_EMALF;
	}

	const rdata_descriptor_t *desc = knot_get_rdata_descriptor(rrset->type);
	if (desc->type_name == NULL) {
		desc = knot_get_obsolete_rdata_descriptor(rrset->type);
	}

	if (rdlength == 0) {
		if (allow_zero_rdata(rrset, desc)) {
			return knot_rrset_add_rdata(rrset, NULL, 0, ttl, mm);
		} else {
			return KNOT_EMALF;
		}
	}

	/* Source and destination buffer */

	const uint8_t *src = pkt_wire + *pos;
	size_t src_avail = rdlength;

	const size_t buffer_size = rdlength + KNOT_MAX_RDATA_DNAMES * KNOT_DNAME_MAXLEN;
	uint8_t rdata_buffer[buffer_size];
	uint8_t *dst = rdata_buffer;
	size_t dst_avail = buffer_size;

	/* Parse RDATA */

	dname_config_t dname_cfg = {
		.write_cb = decompress_rdata_dname,
		.pkt_wire = pkt_wire
	};

	int ret = rdata_traverse(&src, &src_avail, &dst, &dst_avail,
	                         desc, &dname_cfg, KNOT_RRSET_WIRE_NONE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (src_avail > 0) {
		/* Trailing data in message. */
		return KNOT_EMALF;
	}

	const size_t written = buffer_size - dst_avail;
	if (written > MAX_RDLENGTH) {
		/* DNAME compression caused RDATA overflow. */
		return KNOT_EMALF;
	}
	
	ret = knot_rrset_add_rdata(rrset, rdata_buffer, written, ttl, mm);
	if (ret == KNOT_EOK) {
		/* Update position pointer. */
		*pos += rdlength;
	}
	
	return ret;
}

/*!
* \brief Creates one RR from a wire.
 */
int knot_rrset_rr_from_wire(const uint8_t *pkt_wire, size_t *pos,
                            size_t pkt_size, mm_ctx_t *mm, knot_rrset_t *rrset)
{
	if (!pkt_wire || !pos || !rrset || *pos > pkt_size) {
		return KNOT_EINVAL;
	}

	uint32_t ttl = 0;
	uint16_t rdlen = 0;
	int ret = parse_header(pkt_wire, pos, pkt_size, mm, rrset, &ttl, &rdlen);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = parse_rdata(pkt_wire, pos, pkt_size, mm, ttl, rdlen, rrset);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(rrset, mm);
	}

	return ret;
}
