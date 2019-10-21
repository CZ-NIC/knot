/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "contrib/qp-trie/trie.h"
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

// FIXME: cleanup
#if 0
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
#endif

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

#include <stdio.h> // FIXME: debug

/*!
 * \brief Write compressed domain name to the destination wire.
 *
 * \param dname  Name to be written (assumed lower-cased if is_compressible).
 * \param dst    Destination wire.
 * \param max    Maximum number of bytes available.
 * \param compr  Compression context (NULL for no compression)
 * FIXME: docs
 * \return Number of written bytes or an error.
 */
static int compr_put_dname(const knot_dname_t *dname, uint8_t * const dst, uint16_t max,
                           knot_compr_t *compr, bool is_compressible, bool do_write)
{
	if (*dname == '\0' || !compr || !compr->wire) { // FIXME: !compr
		return knot_dname_to_wire(dst, dname, max);
	}
	assert(dname && dst && compr);
	compr->suffix.labels = 0; // FIXME: really do use hints?

	// Initialize ptr_map if required - with just the QNAME.
	if (!compr->ptr_map) {
		compr->ptr_map = trie_create(NULL);
		if (knot_wire_get_qdcount(compr->wire)) {
			knot_dname_t *qname = compr->wire + KNOT_WIRE_HEADER_SIZE;
			int ret = compr_put_dname(qname, qname, KNOT_DNAME_MAXLEN,
						  compr, false, false);
			if (ret) return ret;
		}
	}


	/* Get offsets of all labels within the name. */
	uint8_t label_offs[128];
	int i = 0;
	for (int off = 0; dname[off]; ++i) {
		label_offs[i] = off;
		off += 1 + dname[off];
	}
	const int name_labels = i;

	/* Get *wire* offsets of all labels in the hint. */
	const int hint_labels = is_compressible ? compr->suffix.labels : 0;
	uint16_t hint_offs[hint_labels + 1 /*zero isn't allowed*/];
	i = 0;
	for (const knot_dname_t *suffix = compr->wire + compr->suffix.pos;
			i < hint_labels;
			++i, suffix = knot_wire_next_label(suffix, compr->wire)) {
		hint_offs[i] = suffix - compr->wire;
	}
	assert(hint_labels == 0
		|| knot_wire_next_label(compr->wire + hint_offs[i - 1], NULL)[0] == 0);

	// Match hint and name from root as long as possible.
	for (i = 1; i <= hint_labels && i <= name_labels; ++i) {
		if (!label_is_equal(dname + label_offs[name_labels - i],
					compr->wire + hint_offs[hint_labels - i])) {
			break;
		}
	}

	uint16_t ptr_last = i == 1 ? 0 : hint_offs[hint_labels - (i - 1)];
	int compr_i = name_labels;
	uint16_t compr_ptr = 0;
	// We've used hint as much as possible; now continue with the DB.
	for (i = name_labels - i; i >= 0; --i) {
		/* Find dname from this label in the DB. */
		uint8_t key[2 + 63];
		memcpy(key, &ptr_last, 2);
		const int label_len = dname[label_offs[i]];
		if (is_compressible) { // we can avoid tolower
			memcpy(key + 2, dname + label_offs[i] + 1, label_len);
			#ifndef NDEBUG
			for (int j = 0; j < label_len; ++j) {
				assert(key[2 + j] == knot_tolower(key[2 + j]));
			}
			#endif
		} else {
			for (int j = 0; j < label_len; ++j) {
				key[2 + j] = knot_tolower(dname[label_offs[i] + 1 + j]);
			}
		}
		uintptr_t *pval = (uintptr_t *)
			trie_get_ins(compr->ptr_map, key, 2 + label_len);
		if (unlikely(!pval)) {
			return KNOT_ENOMEM;
		}
		/* Update the DB, preferring the old value. */
		const bool found = *pval;
		if (!found) {
			*pval = dst - compr->wire + label_offs[i];
			// In case we've overshoot with the pointer value,
			// we roll back this iteration - can't improve compression anymore.
			if (unlikely(*pval & KNOT_WIRE_PTR)) {
				trie_del(compr->ptr_map, key, 2 + label_len, NULL);
				break;
			}
		}
		ptr_last = *pval;
		assert(!(ptr_last & KNOT_WIRE_PTR));
		if (found) {
			compr_i = i;
			compr_ptr = ptr_last;
		}
	}
	assert((compr_i == name_labels) == (compr_ptr == 0));
	if (!is_compressible) {
		compr_i = name_labels;
		compr_ptr = 0;
	}

	if (!do_write) {
		return 0;
	}
	// Put the uncompressed parts to the wire.
	uint16_t written = 0;
	for (i = 0; i < compr_i; ++i) {
		const knot_dname_t *label = dname + label_offs[i];
		const int len = *label + 1;
		if (unlikely(written + len > max)) {
			return KNOT_ESPACE;
		} else {
			memcpy(dst + written, label, len);
			written += len;
		}
	}
	// Put the final step: either pointer or root label.
	if (compr_ptr) {
		if (written + sizeof(uint16_t) > max) {
			return KNOT_ESPACE;
		}
		knot_wire_put_pointer(dst + written, compr_ptr);
		written += sizeof(uint16_t);
	} else {
		if (written + 1 > max) {
			return KNOT_ESPACE;
		}
		dst[written++] = 0;
	}

	return written;
}

int knot_compr_init(struct knot_pkt *pkt, const knot_dname_t *qname, uint16_t max)
{
	pkt->compr.wire = pkt->wire;
	if (pkt->compr.ptr_map) {
		trie_clear(pkt->compr.ptr_map);
	} else {
		pkt->compr.ptr_map = trie_create(&pkt->mm);
		if (!pkt->compr.ptr_map) {
			return KNOT_ENOMEM;
		}
	}
	return compr_put_dname(qname, pkt->wire + KNOT_WIRE_HEADER_SIZE, max,
				&pkt->compr, false, true);
}

static int write_owner(const knot_rrset_t *rrset, uint8_t **dst, size_t *dst_avail,
                       knot_compr_t *compr)
{
	assert(rrset && dst && *dst && dst_avail);

	int ret = compr_put_dname(rrset->owner, *dst, *dst_avail, compr, true, true);
	if (ret < 0) {
		return ret;
	}
	*dst_avail -= ret;
	*dst += ret;
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

// TODO: put_compr -> bool is_compressible
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
	int written = compr_put_dname(dname, *dst, dname_max(*dst_avail), compr, !!put_compr, true);
	if (written < 0) {
		return written;
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

	knot_dname_storage_t buff;
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
