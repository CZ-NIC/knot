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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libknot/attribute.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/consts.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/packet/pkt.h"
#include "libknot/packet/wire.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/naptr.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/wire.h"
#include "contrib/macros.h"
#include "contrib/wire_ctx.h"

#define RR_HEADER_SIZE 10

/*!
 * \brief Get maximal size of a domain name in a wire with given capacity.
 */
static uint16_t dname_max(size_t wire_avail)
{
	return MIN(wire_avail, KNOT_DNAME_MAXLEN);
}

/*!
 * Case insensitive comparison of two dnames in wire format.
 * The second name may be compressed in a supplied wire.
 */
static bool dname_equal_wire(const knot_dname_t *d1, const knot_dname_t *d2,
                             const uint8_t *wire)
{
	assert(d1);
	assert(d2);

	d2 = knot_wire_seek_label(d2, wire);

	while (*d1 != '\0' || *d2 != '\0') {
		if (!knot_dname_label_is_equal(d1, d2)) {
			return false;
		}
		d1 = knot_wire_next_label(d1, NULL);
		d2 = knot_wire_next_label(d2, wire);
	}

	return true;
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

	int ret = knot_naptr_header_size(*src, *src + *src_avail);

	if (ret < 0) {
		return ret;
	}

	/* Copy the data */
	return write_rdata_fixed(src, src_avail, dst, dst_avail, ret);
}

/*!
 * \brief DNAME RDATA processing config.
 */
struct dname_config {
	int (*write_cb)(const uint8_t **src, size_t *src_avail,
	                uint8_t **dst, size_t *dst_avail,
	                int dname_type, struct dname_config *dname_cfg);
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
                             int type, dname_config_t *dname_cfg)
{
	switch (type) {
	case KNOT_RDATA_WF_COMPRESSIBLE_DNAME:
	case KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME:
	case KNOT_RDATA_WF_FIXED_DNAME:
		return dname_cfg->write_cb(src, src_avail, dst, dst_avail,
		                           type, dname_cfg);
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
                          const knot_rdata_descriptor_t *desc,
                          dname_config_t *dname_cfg)
{
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int block_type = desc->block_types[i];
		int ret = write_rdata_block(src, src_avail, dst, dst_avail,
		                            block_type, dname_cfg);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Compute total length of RDATA blocks.
 */
static int rdata_len_block(const uint8_t **src, size_t *src_avail,
                           const uint8_t *pkt_wire, int block_type)
{
	int ret, compr_size;

	switch (block_type) {
	case KNOT_RDATA_WF_COMPRESSIBLE_DNAME:
	case KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME:
	case KNOT_RDATA_WF_FIXED_DNAME:
		compr_size = knot_dname_wire_check(*src, *src + *src_avail,
		                                   pkt_wire);
		if (compr_size <= 0) {
			return KNOT_EMALF;
		}

		ret = knot_dname_realsize(*src, pkt_wire);
		*src += compr_size;
		*src_avail -= compr_size;
		break;
	case KNOT_RDATA_WF_NAPTR_HEADER:
		ret = knot_naptr_header_size(*src, *src + *src_avail);
		if (ret < 0) {
			return ret;
		}

		*src += ret;
		*src_avail -= ret;
		break;
	case KNOT_RDATA_WF_REMAINDER:
		ret = *src_avail;
		*src += ret;
		*src_avail -= ret;
		break;
	default:
		/* Fixed size block */
		assert(block_type > 0);
		ret = block_type;
		if (*src_avail < ret) {
			return KNOT_EMALF;
		}

		*src += ret;
		*src_avail -= ret;
		break;
	}

	return ret;
}

/*!
 * \brief Compute total length of RDATA blocks.
 */
static int rdata_len(const uint8_t **src, size_t *src_avail,
                     const uint8_t *pkt_wire,
                     const knot_rdata_descriptor_t *desc)
{
	int _len = 0;
	const uint8_t *_src = *src;
	size_t _src_avail = *src_avail;

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int block_type = desc->block_types[i];
		int ret = rdata_len_block(&_src, &_src_avail, pkt_wire, block_type);
		if (ret < 0) {
			return ret;
		}
		_len += ret;
	}

	if (_src_avail > 0) {
		/* Trailing data in message. */
		return KNOT_EMALF;
	}

	return _len;
}

/*- RRSet to wire -----------------------------------------------------------*/

/*!
 * \brief Write RR owner to wire.
 */
static int write_owner(const knot_rrset_t *rrset, uint8_t **dst, size_t *dst_avail,
                       knot_compr_t *compr)
{
	assert(rrset);
	assert(dst && *dst);
	assert(dst_avail);

	/* Check for zero label owner (don't compress). */

	uint16_t owner_pointer = 0;
	if (*rrset->owner != '\0') {
		owner_pointer = compr_get_ptr(compr, KNOT_COMPR_HINT_OWNER);
	}

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
		/* Check for coincidence with previous RR set */
		if (compr != NULL &&
		    compr->suffix.pos != 0 &&
		    *rrset->owner != '\0' &&
		    dname_equal_wire(rrset->owner,
		                     compr->wire + compr->suffix.pos, compr->wire)) {

			knot_wire_put_pointer(*dst, compr->suffix.pos);
			compr_set_ptr(compr, KNOT_COMPR_HINT_OWNER,
			              compr->wire + compr->suffix.pos, owner_size);
			owner_size = sizeof(uint16_t);
		} else {
			if (compr != NULL) {
				compr->suffix.pos = KNOT_WIRE_HEADER_SIZE;
				compr->suffix.labels = knot_dname_labels(compr->wire + compr->suffix.pos,
				                                         compr->wire);
			}
			int written = knot_compr_put_dname(rrset->owner, *dst,
			                                   dname_max(*dst_avail), compr);
			if (written < 0) {
				return written;
			}

			compr_set_ptr(compr, KNOT_COMPR_HINT_OWNER, *dst, written);
			owner_size = written;
		}
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

	/* Write result */

	wire_ctx_t write = wire_ctx_init(*dst, *dst_avail);

	wire_ctx_write_u16(&write, rrset->type);
	wire_ctx_write_u16(&write, rrset->rclass);

	if (rrset->type == KNOT_RRTYPE_RRSIG) {
		wire_ctx_write_u32(&write, knot_rrsig_original_ttl(&rrset->rrs, rrset_index));
	} else {
		wire_ctx_write_u32(&write, rrset->ttl);
	}

	/* Check write */
	if (write.error != KNOT_EOK) {
		return write.error;
	}

	/* Update buffer */

	*dst = write.position;
	*dst_avail = wire_ctx_available(&write);

	return KNOT_EOK;
}

/*!
 * \brief Write RDATA DNAME to wire.
 */
static int compress_rdata_dname(const uint8_t **src, size_t *src_avail,
                                uint8_t **dst, size_t *dst_avail,
                                int dname_type, dname_config_t *dname_cfg)
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
		return written;
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
                       uint8_t **dst, size_t *dst_avail, knot_compr_t *compr)
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
		.hint = KNOT_COMPR_HINT_RDATA + rrset_index
	};

	const uint8_t *src = rdata->data;
	size_t src_avail = rdata->len;
	if (src_avail > 0) {
		/* Only write non-empty data. */
		const knot_rdata_descriptor_t *desc =
			knot_get_rdata_descriptor(rrset->type);
		int ret = rdata_traverse(&src, &src_avail, dst, dst_avail,
		                         desc, &dname_cfg);
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
                    uint8_t **dst, size_t *dst_avail, knot_compr_t *compr)
{
	int ret;

	ret = write_owner(rrset, dst, dst_avail, compr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = write_fixed_header(rrset, rrset_index, dst, dst_avail);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return write_rdata(rrset, rrset_index, dst, dst_avail, compr);
}

/*!
 * \brief Write RR Set content to a wire.
 */
_public_
int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, uint16_t max_size,
                       knot_compr_t *compr)
{
	if (!rrset || !wire) {
		return KNOT_EINVAL;
	}

	uint8_t *write = wire;
	size_t capacity = max_size;

	for (uint16_t i = 0; i < rrset->rrs.rr_count; i++) {
		int ret = write_rr(rrset, i, &write, &capacity, compr);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return write - wire;
}

/*- RRSet from wire ---------------------------------------------------------*/

/*!
 * \brief Parse header of one RR from packet wireformat.
 */
static int parse_header(const uint8_t *pkt_wire, size_t *pos, size_t pkt_size,
                        knot_mm_t *mm, knot_rrset_t *rrset, uint16_t *rdlen)
{
	assert(pkt_wire);
	assert(pos);
	assert(rrset);
	assert(rdlen);

	knot_dname_t *owner = knot_dname_parse(pkt_wire, pos, pkt_size, mm);
	if (owner == NULL) {
		return KNOT_EMALF;
	}

	if (pkt_size - *pos < RR_HEADER_SIZE) {
		knot_dname_free(&owner, mm);
		return KNOT_EMALF;
	}

	wire_ctx_t wire = wire_ctx_init_const(pkt_wire, pkt_size);
	wire_ctx_set_offset(&wire, *pos);

	uint16_t type = wire_ctx_read_u16(&wire);
	uint16_t rclass = wire_ctx_read_u16(&wire);
	uint32_t ttl = wire_ctx_read_u32(&wire);
	*rdlen = wire_ctx_read_u16(&wire);

	*pos = wire_ctx_offset(&wire);

	if (wire.error != KNOT_EOK) {
		knot_dname_free(&owner, mm);
		return wire.error;
	}

	if (wire_ctx_available(&wire) < *rdlen) {
		knot_dname_free(&owner, mm);
		return KNOT_EMALF;
	}

	knot_rrset_init(rrset, owner, type, rclass, ttl);

	return KNOT_EOK;
}

/*!
 * \brief Parse and decompress RDATA.
 */
static int decompress_rdata_dname(const uint8_t **src, size_t *src_avail,
                                  uint8_t **dst, size_t *dst_avail,
                                  int dname_type, dname_config_t *dname_cfg)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);
	assert(dname_cfg);
	UNUSED(dname_type);

	int compr_size = knot_dname_wire_check(*src, *src + *src_avail,
	                                       dname_cfg->pkt_wire);
	if (compr_size <= 0) {
		return compr_size;
	}

	int decompr_size = knot_dname_unpack(*dst, *src, *dst_avail,
	                                     dname_cfg->pkt_wire);
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

static bool allow_zero_rdata(const knot_rrset_t *rr,
                             const knot_rdata_descriptor_t *desc)
{
	return rr->rclass != KNOT_CLASS_IN ||  // NONE and ANY for DDNS
	       rr->type == KNOT_RRTYPE_APL ||  // APL RR type
	       desc->type_name == NULL;        // Unknown RR type
}

/*!
 * \brief Parse RDATA part of one RR from packet wireformat.
 */
static int parse_rdata(const uint8_t *pkt_wire, size_t *pos, size_t pkt_size,
                       knot_mm_t *mm, uint16_t rdlength, knot_rrset_t *rrset)
{
	assert(pkt_wire);
	assert(pos);
	assert(rrset);

	if (pkt_size - *pos < rdlength) {
		return KNOT_EMALF;
	}

	const knot_rdata_descriptor_t *desc = knot_get_rdata_descriptor(rrset->type);
	if (desc->type_name == NULL) {
		desc = knot_get_obsolete_rdata_descriptor(rrset->type);
	}

	if (rdlength == 0) {
		if (allow_zero_rdata(rrset, desc)) {
			return knot_rrset_add_rdata(rrset, NULL, 0, mm);
		} else {
			return KNOT_EMALF;
		}
	}

	/* Source and destination buffer */

	const uint8_t *src = pkt_wire + *pos;
	size_t src_avail = rdlength;

	int buffer_size = rdata_len(&src, &src_avail, pkt_wire, desc);
	if (buffer_size < 0) {
		return buffer_size;
	}

	if (buffer_size > KNOT_RDATA_MAXLEN) {
		/* DNAME compression caused RDATA overflow. */
		return KNOT_EMALF;
	}

	knot_rdataset_t *rrs = &rrset->rrs;
	int ret = knot_rdataset_reserve(rrs, buffer_size, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rdata_t *rr = knot_rdataset_at(rrs, rrs->rr_count - 1);
	assert(rr);
	uint8_t *dst = rr->data;
	size_t dst_avail = buffer_size;

	/* Parse RDATA */

	dname_config_t dname_cfg = {
		.write_cb = decompress_rdata_dname,
		.pkt_wire = pkt_wire
	};

	ret = rdata_traverse(&src, &src_avail, &dst, &dst_avail, desc, &dname_cfg);
	if (ret != KNOT_EOK) {
		knot_rdataset_unreserve(rrs, mm);
		return ret;
	}

	ret = knot_rdataset_sort_at(rrs, rrs->rr_count - 1, mm);
	if (ret != KNOT_EOK) {
		knot_rdataset_unreserve(rrs, mm);
		return ret;
	}

	/* Update position pointer. */
	*pos += rdlength;

	return KNOT_EOK;
}

_public_
int knot_rrset_rr_from_wire(const uint8_t *pkt_wire, size_t *pos, size_t pkt_size,
                            knot_mm_t *mm, knot_rrset_t *rrset, bool canonical)
{
	if (!pkt_wire || !pos || !rrset || *pos > pkt_size) {
		return KNOT_EINVAL;
	}

	uint16_t rdlen = 0;
	int ret = parse_header(pkt_wire, pos, pkt_size, mm, rrset, &rdlen);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = parse_rdata(pkt_wire, pos, pkt_size, mm, rdlen, rrset);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(rrset, mm);
		return ret;
	}

	/* Convert RR to canonical format. */
	if (canonical) {
		ret = knot_rrset_rr_to_canonical(rrset);
		if (ret != KNOT_EOK) {
			knot_rrset_clear(rrset, mm);
		}
	}

	return KNOT_EOK;
}
