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

#include "libknot/attribute.h"
#include "libknot/consts.h"
#include "libknot/descriptor.h"
#include "libknot/packet/pkt.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/rrtype/naptr.h"
#include "libknot/rrtype/rrsig.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"
#include "contrib/tolower.h"
#include "contrib/wire_ctx.h"

/*!
 * \brief Get maximal size of a domain name in a wire with given capacity.
 */
static uint16_t dname_max(size_t wire_avail)
{
	return MIN(wire_avail, KNOT_DNAME_MAXLEN);
}

/*!
 * \brief Compares two domain name labels.
 *
 * \param label1  First label.
 * \param label2  Second label (may be in upper-case).
 *
 * \retval true if the labels are identical
 * \retval false if the labels are NOT identical
 */
static bool label_is_equal(const uint8_t *label1, const uint8_t *label2)
{
	assert(label1 && label2);

	if (*label1 != *label2) {
		return false;
	}

	uint8_t len = *label1;
	for (uint8_t i = 1; i <= len; i++) {
		if (label1[i] != knot_tolower(label2[i])) {
			return false;
		}
	}

	return true;
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
		if (!label_is_equal(d1, d2)) {
			return false;
		}
		d1 = knot_wire_next_label(d1, NULL);
		d2 = knot_wire_next_label(d2, wire);
	}

	return true;
}

static uint16_t compr_get_ptr(knot_compr_t *compr, uint16_t hint)
{
	if (compr == NULL) {
		return 0;
	}

	return knot_compr_hint(compr->rrinfo, hint);
}

static void compr_set_ptr(knot_compr_t *compr, uint16_t hint,
                          const uint8_t *written_at, uint16_t written_size)
{
	if (compr == NULL) {
		return;
	}

	assert(written_at >= compr->wire);

	uint16_t offset = written_at - compr->wire;

	knot_compr_hint_set(compr->rrinfo, hint, offset, written_size);
}

static int write_rdata_fixed(const uint8_t **src, size_t *src_avail,
                             uint8_t **dst, size_t *dst_avail, size_t size)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);

	// Check input/output buffer boundaries.
	if (size > *src_avail) {
		return KNOT_EMALF;
	}

	if (size > *dst_avail) {
		return KNOT_ESPACE;
	}

	// Data binary copy.
	memcpy(*dst, *src, size);

	// Update buffers.
	*src += size;
	*src_avail -= size;

	*dst += size;
	*dst_avail -= size;

	return KNOT_EOK;
}

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

	// Copy the data.
	return write_rdata_fixed(src, src_avail, dst, dst_avail, ret);
}

/*! \brief Helper for \ref compr_put_dname, writes label(s) with size checks. */
#define WRITE_LABEL(dst, written, label, max, len) \
	if ((written) + (len) > (max)) { \
		return KNOT_ESPACE; \
	} else { \
		memcpy((dst) + (written), (label), (len)); \
		written += (len); \
	}

/*!
 * \brief Write compressed domain name to the destination wire.
 *
 * \param dname  Name to be written.
 * \param dst    Destination wire.
 * \param max    Maximum number of bytes available.
 * \param compr  Compression context (NULL for no compression)
 * \return Number of written bytes or an error.
 */
static int compr_put_dname(const knot_dname_t *dname, uint8_t *dst, uint16_t max,
                           knot_compr_t *compr)
{
	assert(dname && dst);

	// Write uncompressible names directly (zero label dname).
	if (compr == NULL || *dname == '\0') {
		return knot_dname_to_wire(dst, dname, max);
	}

	// Get number of labels (should not be a zero label dname).
	size_t name_labels = knot_dname_labels(dname, NULL);
	assert(name_labels > 0);

	// Suffix must not be longer than whole name.
	const knot_dname_t *suffix = compr->wire + compr->suffix.pos;
	int suffix_labels = compr->suffix.labels;
	while (suffix_labels > name_labels) {
		suffix = knot_wire_next_label(suffix, compr->wire);
		--suffix_labels;
	}

	// Suffix is shorter than name, write labels until aligned.
	uint8_t orig_labels = name_labels;
	uint16_t written = 0;
	while (name_labels > suffix_labels) {
		WRITE_LABEL(dst, written, dname, max, (*dname + 1));
		dname = knot_wire_next_label(dname, NULL);
		--name_labels;
	}

	// Label count is now equal.
	assert(name_labels == suffix_labels);
	const knot_dname_t *match_begin = dname;
	const knot_dname_t *compr_ptr = suffix;
	while (dname[0] != '\0') {
		// Next labels.
		const knot_dname_t *next_dname = knot_wire_next_label(dname, NULL);
		const knot_dname_t *next_suffix = knot_wire_next_label(suffix, compr->wire);

		// Two labels match, extend suffix length.
		if (!label_is_equal(dname, suffix)) {
			// If they don't match, write unmatched labels.
			uint16_t mismatch_len = (dname - match_begin) + (*dname + 1);
			WRITE_LABEL(dst, written, match_begin, max, mismatch_len);
			// Start new potential match.
			match_begin = next_dname;
			compr_ptr = next_suffix;
		}

		// Jump to next labels.
		dname = next_dname;
		suffix = next_suffix;
	}

	// If match begins at the end of the name, write '\0' label.
	if (match_begin == dname) {
		WRITE_LABEL(dst, written, dname, max, 1);
	} else {
		// Match covers >0 labels, write out compression pointer.
		if (written + sizeof(uint16_t) > max) {
			return KNOT_ESPACE;
		}
		knot_wire_put_pointer(dst + written, compr_ptr - compr->wire);
		written += sizeof(uint16_t);
	}

	assert(dst >= compr->wire);
	size_t wire_pos = dst - compr->wire;
	assert(wire_pos < KNOT_WIRE_MAX_PKTSIZE);

	// Heuristics - expect similar names are grouped together.
	if (written > sizeof(uint16_t) && wire_pos + written < KNOT_WIRE_PTR_MAX) {
		compr->suffix.pos = wire_pos;
		compr->suffix.labels = orig_labels;
	}

	return written;
}

#define WRITE_OWNER_CHECK(size, dst_avail) \
	if ((size) > *(dst_avail)) { \
		return KNOT_ESPACE; \
	}

#define WRITE_OWNER_INCR(dst, dst_avail, size) \
	*(dst) += (size); \
	*(dst_avail) -= (size);

static int write_owner(const knot_rrset_t *rrset, uint8_t **dst, size_t *dst_avail,
                       knot_compr_t *compr)
{
	assert(rrset);
	assert(dst && *dst);
	assert(dst_avail);

	// Check for zero label owner (don't compress).
	uint16_t owner_pointer = 0;
	if (*rrset->owner != '\0') {
		owner_pointer = compr_get_ptr(compr, KNOT_COMPR_HINT_OWNER);
	}

	// Write result.
	if (owner_pointer > 0) {
		WRITE_OWNER_CHECK(sizeof(uint16_t), dst_avail);
		knot_wire_put_pointer(*dst, owner_pointer);
		WRITE_OWNER_INCR(dst, dst_avail, sizeof(uint16_t));
	// Check for coincidence with previous RR set.
	} else if (compr != NULL && compr->suffix.pos != 0 && *rrset->owner != '\0' &&
	           dname_equal_wire(rrset->owner, compr->wire + compr->suffix.pos,
	                            compr->wire)) {
		WRITE_OWNER_CHECK(sizeof(uint16_t), dst_avail);
		knot_wire_put_pointer(*dst, compr->suffix.pos);
		compr_set_ptr(compr, KNOT_COMPR_HINT_OWNER,
		              compr->wire + compr->suffix.pos,
		              knot_dname_size(rrset->owner));
		WRITE_OWNER_INCR(dst, dst_avail, sizeof(uint16_t));
	} else {
		if (compr != NULL) {
			compr->suffix.pos = KNOT_WIRE_HEADER_SIZE;
			compr->suffix.labels =
				knot_dname_labels(compr->wire + compr->suffix.pos,
				                  compr->wire);
		}
		// WRITE_OWNER_CHECK not needed, compr_put_dname has a check.
		int written = compr_put_dname(rrset->owner, *dst,
		                              dname_max(*dst_avail), compr);
		if (written < 0) {
			return written;
		}

		compr_set_ptr(compr, KNOT_COMPR_HINT_OWNER, *dst, written);
		WRITE_OWNER_INCR(dst, dst_avail, written);
	}

	return KNOT_EOK;
}

static int write_fixed_header(const knot_rrset_t *rrset, uint16_t rrset_index,
                              uint8_t **dst, size_t *dst_avail, uint16_t flags)
{
	assert(rrset);
	assert(rrset_index < rrset->rrs.count);
	assert(dst && *dst);
	assert(dst_avail);

	// Write header.
	wire_ctx_t write = wire_ctx_init(*dst, *dst_avail);

	wire_ctx_write_u16(&write, rrset->type);
	wire_ctx_write_u16(&write, rrset->rclass);

	if ((flags & KNOT_PF_ORIGTTL) && rrset->type == KNOT_RRTYPE_RRSIG) {
		const knot_rdata_t *rdata = knot_rdataset_at(&rrset->rrs, rrset_index);
		wire_ctx_write_u32(&write, knot_rrsig_original_ttl(rdata));
	} else {
		wire_ctx_write_u32(&write, rrset->ttl);
	}

	// Check write.
	if (write.error != KNOT_EOK) {
		return write.error;
	}

	// Update buffer.
	*dst = write.position;
	*dst_avail = wire_ctx_available(&write);

	return KNOT_EOK;
}

static int compress_rdata_dname(const uint8_t **src, size_t *src_avail,
                                uint8_t **dst, size_t *dst_avail,
                                knot_compr_t *put_compr, knot_compr_t *compr,
                                uint16_t hint)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);

	// Source domain name.
	const knot_dname_t *dname = *src;
	size_t dname_size = knot_dname_size(dname);

	// Output domain name.
	int written = compr_put_dname(dname, *dst, dname_max(*dst_avail), put_compr);
	if (written < 0) {
		return written;
	}

	// Update compression hints.
	if (compr_get_ptr(compr, hint) == 0) {
		compr_set_ptr(compr, hint, *dst, written);
	}

	// Update buffers.
	*dst += written;
	*dst_avail -= written;

	*src += dname_size;
	*src_avail -= dname_size;

	return KNOT_EOK;
}

static int rdata_traverse_write(const uint8_t **src, size_t *src_avail,
                                uint8_t **dst, size_t *dst_avail,
                                const knot_rdata_descriptor_t *desc,
                                knot_compr_t *compr, uint16_t hint)
{
	for (const int *type = desc->block_types; *type != KNOT_RDATA_WF_END; type++) {
		int ret;
		knot_compr_t *put_compr = NULL;
		switch (*type) {
		case KNOT_RDATA_WF_COMPRESSIBLE_DNAME:
			put_compr = compr;
			// FALLTHROUGH
		case KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME:
		case KNOT_RDATA_WF_FIXED_DNAME:
			ret = compress_rdata_dname(src, src_avail, dst, dst_avail,
			                           put_compr, compr, hint);
			break;
		case KNOT_RDATA_WF_NAPTR_HEADER:
			ret = write_rdata_naptr_header(src, src_avail, dst, dst_avail);
			break;
		case KNOT_RDATA_WF_REMAINDER:
			ret = write_rdata_fixed(src, src_avail, dst, dst_avail, *src_avail);
			break;
		default:
			// Fixed size block.
			assert(*type > 0);
			ret = write_rdata_fixed(src, src_avail, dst, dst_avail, *type);
			break;
		}
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int write_rdata(const knot_rrset_t *rrset, uint16_t rrset_index,
                       uint8_t **dst, size_t *dst_avail, knot_compr_t *compr)
{
	assert(rrset);
	assert(rrset_index < rrset->rrs.count);
	assert(dst && *dst);
	assert(dst_avail);

	const knot_rdata_t *rdata = knot_rdataset_at(&rrset->rrs, rrset_index);

	// Reserve space for RDLENGTH.
	if (sizeof(uint16_t) > *dst_avail) {
		return KNOT_ESPACE;
	}

	uint8_t *wire_rdlength = *dst;
	*dst += sizeof(uint16_t);
	*dst_avail -= sizeof(uint16_t);
	uint8_t *wire_rdata_begin = *dst;

	// Write RDATA.
	const uint8_t *src = rdata->data;
	size_t src_avail = rdata->len;
	if (src_avail > 0) {
		// Only write non-empty data.
		const knot_rdata_descriptor_t *desc =
			knot_get_rdata_descriptor(rrset->type);
		int ret = rdata_traverse_write(&src, &src_avail, dst, dst_avail,
		                         desc, compr, KNOT_COMPR_HINT_RDATA + rrset_index);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Check for trailing data in the message.
	if (src_avail > 0) {
		return KNOT_EMALF;
	}

	// Write final RDLENGTH.
	size_t rdlength = *dst - wire_rdata_begin;
	knot_wire_write_u16(wire_rdlength, rdlength);

	return KNOT_EOK;
}

static int write_rr(const knot_rrset_t *rrset, uint16_t rrset_index, uint8_t **dst,
                    size_t *dst_avail, knot_compr_t *compr, uint16_t flags)
{
	int ret = write_owner(rrset, dst, dst_avail, compr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = write_fixed_header(rrset, rrset_index, dst, dst_avail, flags);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return write_rdata(rrset, rrset_index, dst, dst_avail, compr);
}

_public_
int knot_rrset_to_wire_extra(const knot_rrset_t *rrset, uint8_t *wire,
                             uint16_t max_size, uint16_t rotate,
                             knot_compr_t *compr, uint16_t flags)
{
	if (rrset == NULL || wire == NULL) {
		return KNOT_EINVAL;
	}
	if (rrset->rrs.count == 0) {
		return 0;
	}
	if (rotate != 0) {
		rotate %= rrset->rrs.count;
	}

	uint8_t *write = wire;
	size_t capacity = max_size;

	uint16_t count = rrset->rrs.count;
	for (uint16_t i = rotate; i < count + rotate; i++) {
		uint16_t pos = (i < count) ? i : (i - count);
		int ret = write_rr(rrset, pos, &write, &capacity, compr, flags);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return write - wire;
}

_public_
int knot_rrset_to_wire_rotate(const knot_rrset_t *rrset, uint8_t *wire,
                              uint16_t max_size, uint16_t rotate,
                              knot_compr_t *compr)
{
	return knot_rrset_to_wire_extra(rrset, wire, max_size, rotate, compr, 0);
}

static int parse_header(const uint8_t *wire, size_t *pos, size_t pkt_size,
                        knot_mm_t *mm, knot_rrset_t *rrset, uint16_t *rdlen)
{
	assert(wire);
	assert(pos);
	assert(rrset);
	assert(rdlen);

	wire_ctx_t src = wire_ctx_init_const(wire, pkt_size);
	wire_ctx_set_offset(&src, *pos);

	int compr_size = knot_dname_wire_check(src.position, wire + pkt_size, wire);
	if (compr_size <= 0) {
		return KNOT_EMALF;
	}

	uint8_t buff[KNOT_DNAME_MAXLEN];
	int decompr_size = knot_dname_unpack(buff, src.position, sizeof(buff), wire);
	if (decompr_size <= 0) {
		return KNOT_EMALF;
	}

	knot_dname_t *owner = mm_alloc(mm, decompr_size);
	if (owner == NULL) {
		return KNOT_ENOMEM;
	}
	memcpy(owner, buff, decompr_size);
	wire_ctx_skip(&src, compr_size);

	uint16_t type = wire_ctx_read_u16(&src);
	uint16_t rclass = wire_ctx_read_u16(&src);
	uint32_t ttl = wire_ctx_read_u32(&src);
	*rdlen = wire_ctx_read_u16(&src);

	if (src.error != KNOT_EOK) {
		knot_dname_free(owner, mm);
		return KNOT_EMALF;
	}

	if (wire_ctx_available(&src) < *rdlen) {
		knot_dname_free(owner, mm);
		return KNOT_EMALF;
	}

	*pos = wire_ctx_offset(&src);

	knot_rrset_init(rrset, owner, type, rclass, ttl);

	return KNOT_EOK;
}

static int decompress_rdata_dname(const uint8_t **src, size_t *src_avail,
                                  uint8_t **dst, size_t *dst_avail,
                                  const uint8_t *pkt_wire)
{
	assert(src && *src);
	assert(src_avail);
	assert(dst && *dst);
	assert(dst_avail);

	int compr_size = knot_dname_wire_check(*src, *src + *src_avail, pkt_wire);
	if (compr_size <= 0) {
		return compr_size;
	}

	int decompr_size = knot_dname_unpack(*dst, *src, *dst_avail, pkt_wire);
	if (decompr_size <= 0) {
		return decompr_size;
	}

	// Update buffers.
	*dst += decompr_size;
	*dst_avail -= decompr_size;

	*src += compr_size;
	*src_avail -= compr_size;

	return KNOT_EOK;
}

static int rdata_traverse_parse(const uint8_t **src, size_t *src_avail,
                                uint8_t **dst, size_t *dst_avail,
                                const knot_rdata_descriptor_t *desc,
                                const uint8_t *pkt_wire)
{
	for (const int *type = desc->block_types; *type != KNOT_RDATA_WF_END; type++) {
		int ret;
		switch (*type) {
		case KNOT_RDATA_WF_COMPRESSIBLE_DNAME:
		case KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME:
		case KNOT_RDATA_WF_FIXED_DNAME:
			ret = decompress_rdata_dname(src, src_avail, dst, dst_avail,
			                             pkt_wire);
			break;
		case KNOT_RDATA_WF_NAPTR_HEADER:
			ret = write_rdata_naptr_header(src, src_avail, dst, dst_avail);
			break;
		case KNOT_RDATA_WF_REMAINDER:
			ret = write_rdata_fixed(src, src_avail, dst, dst_avail, *src_avail);
			break;
		default:
			/* Fixed size block */
			assert(*type > 0);
			ret = write_rdata_fixed(src, src_avail, dst, dst_avail, *type);
			break;
		}
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static bool allow_zero_rdata(const knot_rrset_t *rr,
                             const knot_rdata_descriptor_t *desc)
{
	return rr->rclass != KNOT_CLASS_IN ||  // NONE and ANY for DDNS
	       rr->type == KNOT_RRTYPE_APL ||  // APL RR type
	       desc->type_name == NULL;        // Unknown RR type
}

static int parse_rdata(const uint8_t *pkt_wire, size_t *pos, size_t pkt_size,
                       knot_mm_t *mm, uint16_t rdlength, knot_rrset_t *rrset)
{
	assert(pkt_wire);
	assert(pos);
	assert(rrset);

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
	} else if (pkt_size - *pos < rdlength) {
		return KNOT_EMALF;
	}

	// Buffer for parsed rdata (decompression extends rdata length).
	const size_t max_rdata_len = UINT16_MAX;
	uint8_t buf[knot_rdata_size(max_rdata_len)];
	knot_rdata_t *rdata = (knot_rdata_t *)buf;

	const uint8_t *src = pkt_wire + *pos;
	size_t src_avail = rdlength;
	uint8_t *dst = rdata->data;
	size_t dst_avail = max_rdata_len;

	// Parse RDATA.
	int ret = rdata_traverse_parse(&src, &src_avail, &dst, &dst_avail, desc, pkt_wire);
	if (ret != KNOT_EOK) {
		return KNOT_EMALF;
	}

	// Check for trailing data.
	size_t real_len = max_rdata_len - dst_avail;
	if (real_len < rdlength) {
		return KNOT_EMALF;
	}
	rdata->len = real_len;

	ret = knot_rdataset_add(&rrset->rrs, rdata, mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update position pointer.
	*pos += rdlength;

	return KNOT_EOK;
}

_public_
int knot_rrset_rr_from_wire(const uint8_t *wire, size_t *pos, size_t max_size,
                            knot_rrset_t *rrset, knot_mm_t *mm, bool canonical)
{
	if (wire == NULL || pos == NULL || *pos > max_size || rrset == NULL) {
		return KNOT_EINVAL;
	}

	uint16_t rdlen = 0;
	int ret = parse_header(wire, pos, max_size, mm, rrset, &rdlen);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = parse_rdata(wire, pos, max_size, mm, rdlen, rrset);
	if (ret != KNOT_EOK) {
		knot_rrset_clear(rrset, mm);
		return ret;
	}

	// Convert RR to the canonical format.
	if (canonical) {
		ret = knot_rrset_rr_to_canonical(rrset);
		if (ret != KNOT_EOK) {
			knot_rrset_clear(rrset, mm);
		}
	}

	return KNOT_EOK;
}
