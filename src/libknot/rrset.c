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
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "libknot/consts.h"
#include "libknot/common.h"
#include "common/mempattern.h"
#include "libknot/rrset.h"
#include "libknot/rrset-dump.h"
#include "common/descriptor.h"
#include "common/debug.h"
#include "libknot/util/utils.h"
#include "libknot/packet/wire.h"
#include "libknot/packet/pkt.h"
#include "libknot/dname.h"

static uint16_t rrset_rdata_naptr_bin_chunk_size(const knot_rrset_t *rrset,
                                               size_t pos)
{
	if (rrset == NULL || pos >= rrset->rrs.rr_count) {
		return 0;
	}

	size_t size = 0;
	const knot_rdata_t *rr_data = knot_rdataset_at(&rrset->rrs, pos);
	uint8_t *rdata = knot_rdata_data(rr_data);
	assert(rdata);

	/* Two shorts at the beginning. */
	size += 4;
	/* 3 binary TXTs with length in the first byte. */
	for (int i = 0; i < 3; i++) {
		size += *(rdata + size) + 1;
	}

	/*
	 * Dname remaning, but we usually want to get to the DNAME, so
	 * there's no need to include it in the returned size.
	 */

	return size;
}

static size_t rrset_rdata_remainder_size(const knot_rrset_t *rrset,
                                         uint16_t offset, size_t pos)
{
	const knot_rdata_t *rr_data = knot_rdataset_at(&rrset->rrs, pos);
	return knot_rdata_rdlen(rr_data) - offset;
}

static int knot_rrset_header_to_wire(const knot_rrset_t *rrset, uint32_t ttl,
                                     uint8_t **pos, size_t max_size,
                                     knot_compr_t *compr, size_t *size)
{
	// Common size of items: type, class and ttl.
	const size_t type_cls_ttl_len = 2 * sizeof(uint16_t) + sizeof(uint32_t);
	// Rdata length item size.
	const size_t rrlen_len = sizeof(uint16_t);

	if (rrset->owner == NULL) {
		return KNOT_EMALF;
	}

	const uint8_t *owner = NULL;
	uint8_t owner_len = 0;
	uint16_t *rr_compress = NULL;
	if (compr && compr->rrinfo->compress_ptr[0] > 0) {
		rr_compress = compr->rrinfo->compress_ptr;
		owner_len = sizeof(uint16_t);
	} else {
		owner = rrset->owner;
		owner_len = knot_dname_size(owner);
	}

	dbg_packet("%s: max size: %zu, compressed owner: %s, owner size: %u\n",
	           __func__, max_size, rr_compress ? "yes" : "no", owner_len);

	// Check wire space for header.
	if (*size + owner_len + type_cls_ttl_len + rrlen_len > max_size) {
		dbg_rrset_detail("Header does not fit into wire.\n");
		return KNOT_ESPACE;
	}

	if (rr_compress && rr_compress[COMPR_HINT_OWNER] != 0) {
		/* Put compression pointer. */
		knot_wire_put_pointer(*pos, rr_compress[COMPR_HINT_OWNER]);
		*pos += owner_len;
	} else {
		/* Write owner, type, class and ttl to wire. */
		int ret =  knot_compr_put_dname(owner, *pos, KNOT_DNAME_MAXLEN, compr);
		if (ret < 0) {
			return ret;
		} else {
			owner_len = ret;
			*pos += owner_len;
		}
		/* Store first dname compression hint. */
		if (compr) {
			knot_pkt_compr_hint_set(compr->rrinfo, COMPR_HINT_OWNER,
						compr->wire_pos, ret);
		}
	}

	dbg_rrset_detail("  Type: %u\n", rrset->type);
	knot_wire_write_u16(*pos, rrset->type);
	*pos += sizeof(uint16_t);

	dbg_rrset_detail("  Class: %u\n", rrset->rclass);
	knot_wire_write_u16(*pos, rrset->rclass);
	*pos += sizeof(uint16_t);

	dbg_rrset_detail("  TTL: %u\n", ttl);
	knot_wire_write_u32(*pos, ttl);
	*pos += sizeof(uint32_t);

	assert(owner_len != 0);
	*size += owner_len + type_cls_ttl_len;

	return KNOT_EOK;
}

/* [code-review] Split to more functions, this one's too long. */
static int knot_rrset_rdata_to_wire_one(const knot_rrset_t *rrset,
                                        uint16_t rdata_pos, uint8_t **pos,
                                        size_t max_size, size_t *knot_rr_size,
                                        knot_compr_t *compr)
{
	assert(rrset);
	assert(pos);

	/* Put RR header to wire. */
	size_t size = 0;
	int ret = knot_rrset_header_to_wire(rrset,
	                                    knot_rdata_ttl(knot_rdataset_at(&rrset->rrs, rdata_pos)),
	                                    pos, max_size,
	                                    compr, &size);
	if (ret != KNOT_EOK) {
		dbg_response("Failed to convert RR header to wire (%s).\n",
		             knot_strerror(ret));
		return ret;
	}

	// save space for RDLENGTH
	uint8_t *rdlength_pos = *pos;
	*pos += 2;
	size += 2;

	if (compr) {
		compr->wire_pos += size;
	}

	/* Get pointer into RDATA array. */
	const knot_rdata_t *rr_data = knot_rdataset_at(&rrset->rrs, rdata_pos);
	uint8_t *rdata = knot_rdata_data(rr_data);
	assert(rdata);
	/* Offset into one RDATA array. */
	size_t offset = 0;
	/* Actual RDLENGTH. */
	uint16_t rdlength = 0;

	/* Compression pointer hint. */
	uint16_t hint_id = COMPR_HINT_RDATA + rdata_pos;

	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		if (compr && descriptor_item_is_compr_dname(item)) {
			const knot_dname_t *dname = rdata + offset;
			int ret = knot_compr_put_dname(dname, *pos,
			                             max_size - size - rdlength,
			                             compr);
			if (ret < 0) {
				return KNOT_ESPACE;
			}
			/* Store first dname compression hint. */
			if (!knot_pkt_compr_hint(compr->rrinfo, hint_id)) {
				knot_pkt_compr_hint_set(compr->rrinfo, hint_id, compr->wire_pos, ret);
			}
			*pos += ret;
			rdlength += ret;
			offset += knot_dname_size(dname);
			compr->wire_pos += ret;
		} else if (descriptor_item_is_dname(item)) {
			const knot_dname_t *dname = rdata + offset;
			// save whole domain name
			size_t maxb = max_size - size - rdlength;
			int dname_size = knot_dname_to_wire(*pos, dname, maxb);
			if (dname_size < 0)
				return KNOT_ESPACE;
			/* Store first dname compression hint. */
			if (compr && !knot_pkt_compr_hint(compr->rrinfo, hint_id)) {
				knot_pkt_compr_hint_set(compr->rrinfo, hint_id, compr->wire_pos, dname_size);
			}
			*pos += dname_size;
			rdlength += dname_size;
			offset += dname_size;
			if (compr) {
				compr->wire_pos += dname_size;
			}
		} else if (descriptor_item_is_fixed(item)) {
			/* Fixed length chunk. */
			if (size + rdlength + item > max_size) {
				return KNOT_ESPACE;
			}
			memcpy(*pos, rdata + offset, item);
			*pos += item;
			rdlength += item;
			offset += item;
			if (compr) {
				compr->wire_pos += item;
			}
		} else if (descriptor_item_is_remainder(item)) {
			/* Check that the remainder fits to stream. */
			size_t remainder_size =
				rrset_rdata_remainder_size(rrset, offset,
			                                   rdata_pos);
			if (size + rdlength + remainder_size > max_size) {
				return KNOT_ESPACE;
			}
			memcpy(*pos, rdata + offset, remainder_size);
			*pos += remainder_size;
			rdlength += remainder_size;
			offset += remainder_size;
			if (compr) {
				compr->wire_pos += remainder_size;
			}
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			/* Store the binary chunk. */
			uint16_t chunk_size =
			    rrset_rdata_naptr_bin_chunk_size(rrset, rdata_pos);
			if (size + rdlength + chunk_size > max_size) {
				return KNOT_ESPACE;
			}
			memcpy(*pos, rdata + offset, chunk_size);
			*pos += chunk_size;
			rdlength += chunk_size;
			offset += chunk_size;
			if (compr) {
				compr->wire_pos += chunk_size;
			}
		}
	}

	knot_wire_write_u16(rdlength_pos, rdlength);
	size += rdlength;

	*knot_rr_size = size;
	assert(size <= max_size);
	return KNOT_EOK;
}

static int knot_rrset_to_wire_aux(const knot_rrset_t *rrset, uint8_t **pos,
                                  size_t max_size, knot_compr_t *comp)
{
	size_t size = 0;
	assert(rrset != NULL);
	assert(rrset->owner != NULL);
	assert(pos != NULL);
	assert(*pos != NULL);

	// No RDATA, just save header and 0 RDLENGTH.
	if (rrset->rrs.rr_count == 0) {
		size_t header_size = 0;
		int ret = knot_rrset_header_to_wire(rrset, 0, pos, max_size, comp,
		                                    &header_size);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Save zero rdata length.
		knot_wire_write_u16(*pos, 0);
		*pos += sizeof(uint16_t);
		header_size += sizeof(uint16_t);

		return header_size;
	}

	// Save rrset records.
	for (uint16_t i = 0; i < rrset->rrs.rr_count; ++i) {
		dbg_rrset_detail("rrset: to_wire: Current max_size=%zu\n",
			         max_size);
		size_t knot_rr_size = 0;
		int ret = knot_rrset_rdata_to_wire_one(rrset, i, pos, max_size,
		                                       &knot_rr_size, comp);
		if (ret != KNOT_EOK) {
			dbg_rrset("rrset: to_wire: Cannot convert RR. "
			          "Reason: %s.\n", knot_strerror(ret));
			return ret;
		}
		dbg_rrset_detail("Converted RR nr=%d, size=%zu\n", i, knot_rr_size);
		/* Change size of whole RRSet. */
		size += knot_rr_size;
		/* Change max size. */
		max_size -= knot_rr_size;
	}

	dbg_rrset_detail("Max size: %zu, size: %zu\n", max_size, size);

	return size;
}

static int binary_store(uint8_t *rdata, size_t *offset, size_t packet_offset,
                        const uint8_t *wire, size_t *pos, size_t rdlength,
                        size_t size)
{
	assert(rdata);
	assert(wire);

	/* Check that size is OK. */
	if ((*pos - packet_offset) + size > rdlength) {
		dbg_rrset("rrset: rdata_store_binary: Read of size=%zu on "
		          "position %zu exceeded RDLENGTH by %zu octets.\n", size,
		          *pos, ((*pos - packet_offset) + size) - rdlength);
		return KNOT_ESPACE;
	}

	/* Store actual data. */
	memcpy(rdata + *offset, wire + *pos, size);
	*offset += size;
	*pos += size;

	return KNOT_EOK;
}

knot_rrset_t *knot_rrset_new(const knot_dname_t *owner, uint16_t type,
                             uint16_t rclass, mm_ctx_t *mm)
{
	knot_dname_t *owner_cpy = knot_dname_copy(owner, mm);
	if (owner_cpy == NULL) {
		return NULL;
	}

	knot_rrset_t *ret = mm_alloc(mm, sizeof(knot_rrset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&owner_cpy, mm);
		return NULL;
	}

	knot_rrset_init(ret, owner_cpy, type, rclass);

	return ret;
}

void knot_rrset_init(knot_rrset_t *rrset, knot_dname_t *owner, uint16_t type,
                     uint16_t rclass)
{
	rrset->owner = owner;
	rrset->type = type;
	rrset->rclass = rclass;
	knot_rdataset_init(&rrset->rrs);
	rrset->additional = NULL;
}

void knot_rrset_init_empty(knot_rrset_t *rrset)
{
	knot_rrset_init(rrset, NULL, 0, KNOT_CLASS_IN);
}

knot_rrset_t *knot_rrset_copy(const knot_rrset_t *src, mm_ctx_t *mm)
{
	if (src == NULL) {
		return NULL;
	}

	knot_rrset_t *rrset = knot_rrset_new(src->owner, src->type,
	                                     src->rclass, mm);
	if (rrset == NULL) {
		return NULL;
	}

	int ret = knot_rdataset_copy(&rrset->rrs, &src->rrs, mm);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&rrset, mm);
		return NULL;
	}

	return rrset;
}

void knot_rrset_free(knot_rrset_t **rrset, mm_ctx_t *mm)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	knot_rrset_clear(*rrset, mm);

	mm_free(mm, *rrset);
	*rrset = NULL;
}

void knot_rrset_clear(knot_rrset_t *rrset, mm_ctx_t *mm)
{
	if (rrset) {
		knot_rdataset_clear(&rrset->rrs, mm);
		knot_dname_free(&rrset->owner, mm);
	}
}

int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, size_t *size,
                       size_t max_size, uint16_t *rr_count, knot_compr_t *compr)
{
	if (rrset == NULL || wire == NULL || size == NULL || rr_count == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t *pos = wire;

	int ret = knot_rrset_to_wire_aux(rrset, &pos, max_size, compr);
	if (ret < 0) {
		// some RR didn't fit in, so no RRs should be used
		dbg_rrset_verb("Some RR didn't fit in.\n");
		return KNOT_ESPACE;
	}

	// Check if the whole RRSet fit into packet.
	assert(ret <= max_size);
	assert(pos - wire == ret);

	*size = ret;

	dbg_rrset_detail("Size after: %zu\n", *size);

	// If the rrset is empty set record counter to 1.
	*rr_count = rrset->rrs.rr_count > 0 ? rrset->rrs.rr_count : 1;

	return KNOT_EOK;
}

int knot_rrset_rdata_from_wire_one(knot_rrset_t *rrset,
                                   const uint8_t *wire, size_t *pos,
                                   size_t total_size, uint32_t ttl,
                                   size_t rdlength,
                                   mm_ctx_t *mm)
{
	if (rrset == NULL || wire == NULL || pos == NULL) {
		return KNOT_EINVAL;
	}

	if (rdlength == 0) {
		return knot_rrset_add_rdata(rrset, NULL, 0, ttl, mm);
	}

	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);

	/* Check for obsolete record. */
	if (desc->type_name == NULL) {
		desc = get_obsolete_rdata_descriptor(rrset->type);
	}

	uint8_t rdata_buffer[rdlength + KNOT_DNAME_MAXLEN];
	memset(rdata_buffer, 0, rdlength + KNOT_DNAME_MAXLEN);

	size_t offset = 0; // offset within in-memory RDATA
	size_t parsed = 0; // actual count of parsed octets
	const size_t packet_offset = *pos;

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END &&
	     parsed < rdlength; ++i) {
		const int item = desc->block_types[i];
		if (descriptor_item_is_dname(item)) {
			int wire_size = knot_dname_wire_check(wire + *pos,
			                                      wire + *pos + rdlength,
			                                      wire);
			if (wire_size <= 0) {
				return KNOT_EMALF;
			}
			int unpacked_size = knot_dname_unpack(
				rdata_buffer + offset, wire + *pos,
				KNOT_DNAME_MAXLEN, wire);
			if (unpacked_size <= 0) {
				return KNOT_EMALF;
			}

			parsed += wire_size;

			*pos += wire_size;
			offset += unpacked_size;
		} else if (descriptor_item_is_fixed(item)) {
			int ret = binary_store(rdata_buffer, &offset, packet_offset,
			                       wire, pos, rdlength, item);
			if (ret != KNOT_EOK) {
				return ret;
			}
			parsed += item;
		} else if (descriptor_item_is_remainder(item)) {
			/* Item size has to be calculated. */
			size_t remainder_size = rdlength - parsed;
			int ret = binary_store(rdata_buffer, &offset, packet_offset,
			                       wire, pos, rdlength, remainder_size);
			if (ret != KNOT_EOK) {
				return ret;
			}
			parsed += remainder_size;
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			/* Read fixed part - 2 shorts. */
			const size_t naptr_fixed_part_size = 4;
			int ret = binary_store(rdata_buffer, &offset, packet_offset,
			                       wire, pos, rdlength, naptr_fixed_part_size);
			if (ret != KNOT_EOK) {
				return ret;
			}
			parsed += naptr_fixed_part_size;
			for (int j = 0; j < 3; ++j) {
				/* Read sizes of TXT's - one byte. */
				uint8_t txt_size = *(wire + (*pos)) + 1;
				int ret = binary_store(rdata_buffer, &offset,
				                       packet_offset, wire, pos,
				                       rdlength, txt_size);
				if (ret != KNOT_EOK) {
				}
				parsed += txt_size;
			}
		}
	}

	return knot_rrset_add_rdata(rrset, rdata_buffer, offset, ttl, mm);
}

int knot_rrset_add_rdata(knot_rrset_t *rrset,
                         const uint8_t *rdata, const uint16_t size,
                         const uint32_t ttl, mm_ctx_t *mm)
{
	if (rrset == NULL || (rdata == NULL && size > 0)) {
		return KNOT_EINVAL;
	}

	knot_rdata_t rr[knot_rdata_array_size(size)];
	knot_rdata_init(rr, size, rdata, ttl);

	return knot_rdataset_add(&rrset->rrs, rr, mm);
}

bool knot_rrset_equal(const knot_rrset_t *r1,
                      const knot_rrset_t *r2,
                      knot_rrset_compare_type_t cmp)
{
	if (cmp == KNOT_RRSET_COMPARE_PTR) {
		return r1 == r2;
	}

	if (r1->type != r2->type) {
		return false;
	}

	if (r1->owner && r2->owner) {
		if (!knot_dname_is_equal(r1->owner, r2->owner)) {
			return false;
		}
	} else if (r1->owner != r2->owner) { // At least one is NULL.
		return false;
	}

	if (cmp == KNOT_RRSET_COMPARE_WHOLE) {
		return knot_rdataset_eq(&r1->rrs, &r2->rrs);
	}

	return true;
}

bool knot_rrset_empty(const knot_rrset_t *rrset)
{
	if (rrset) {
		uint16_t rr_count = rrset->rrs.rr_count;
		return rr_count == 0;
	} else {
		return true;
	}
}

uint32_t knot_rrset_ttl(const knot_rrset_t *rrset)
{
	return knot_rdata_ttl(knot_rdataset_at(&(rrset->rrs), 0));
}

