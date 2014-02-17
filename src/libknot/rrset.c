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

#include <config.h>
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
#include "libknot/rdata.h"

static uint32_t rrset_rdata_offset(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata_indices == NULL ||
	    pos >= rrset->rdata_count || pos == 0) {
		return 0;
	}

	assert(rrset->rdata_count >= 2);
	return rrset->rdata_indices[pos - 1];
}

uint8_t *rrset_rdata_pointer(const knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || rrset->rdata == NULL
	    || pos >= rrset->rdata_count) {
		return NULL;
	}

	return rrset->rdata + rrset_rdata_offset(rrset, pos);
}

static uint16_t rrset_rdata_naptr_bin_chunk_size(const knot_rrset_t *rrset,
                                               size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	size_t size = 0;
	uint8_t *rdata = rrset_rdata_pointer(rrset, pos);
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

void knot_rrset_rdata_dump(const knot_rrset_t *rrset, size_t rdata_pos)
{
dbg_rrset_exec_detail(
	dbg_rrset_detail("      ------- RDATA pos=%zu -------\n", rdata_pos);
	if (rrset->rdata_count == 0) {
		dbg_rrset_detail("      There are no rdata in this RRset!\n");
		dbg_rrset_detail("      ------- RDATA -------\n");
		return;
	}
	const rdata_descriptor_t *desc =
		get_rdata_descriptor(knot_rrset_type(rrset));

	size_t offset = 0;
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		const uint8_t *rdata = rrset_rdata_pointer(rrset, rdata_pos);
		if (descriptor_item_is_dname(item)) {
			const knot_dname_t *dname = rdata + offset;
			char *name = knot_dname_to_str(dname);
			dbg_rrset_detail("block=%d: (%p) DNAME=%s\n",
			        i, dname, name);
			free(name);
			offset += knot_dname_size(dname);
		} else if (descriptor_item_is_fixed(item)) {
			dbg_rrset_detail("block=%d Raw data (size=%d):\n",
			                 i, item);
			dbg_rrset_hex_detail((char *)(rdata + offset), item);
			                      offset += item;
		} else if (descriptor_item_is_remainder(item)) {
			dbg_rrset_detail("block=%d Remainder (size=%zu):\n",
			        i, rrset_rdata_item_size(rrset,
			                                 rdata_pos) - offset);
			dbg_rrset_hex_detail((char *)(rdata + offset),
			          rrset_rdata_item_size(rrset,
			                                rdata_pos) - offset);
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			uint16_t naptr_chunk_size =
				rrset_rdata_naptr_bin_chunk_size(rrset, rdata_pos);
			dbg_rrset_detail("NAPTR, REGEXP block (size=%u):\n",
			        naptr_chunk_size);
			dbg_rrset_hex_detail((char *)(rdata + offset), naptr_chunk_size);
			offset += naptr_chunk_size;
		}
	}
);
}

static size_t rrset_rdata_remainder_size(const knot_rrset_t *rrset,
                                         size_t offset, size_t pos)
{
	size_t ret = rrset_rdata_item_size(rrset, pos) - offset;
	assert(ret <= rrset_rdata_size_total(rrset));
	return ret;
}

int rrset_rdata_compare_one(const knot_rrset_t *rrset1,
                            const knot_rrset_t *rrset2,
                            size_t pos1, size_t pos2)
{
	assert(rrset1 != NULL);
	assert(rrset2 != NULL);

	uint8_t *r1 = rrset_rdata_pointer(rrset1, pos1);
	uint8_t *r2 = rrset_rdata_pointer(rrset2, pos2);
	assert(rrset1->type == rrset2->type);
	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset1->type);
	int cmp = 0;
	size_t offset = 0;

	// TODO: this can be much simpler: Get data for memcmp and sizes in ifs
	// compare only once
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		if (descriptor_item_is_dname(desc->block_types[i])) {
			const knot_dname_t *dname1 = r1 + offset;
			int size1 = knot_dname_size(dname1);
			const knot_dname_t *dname2 = r2 + offset;
			int size2 = knot_dname_size(dname2);
			cmp = memcmp(dname1, dname2,
			             size1 <= size2 ? size1 : size2);
			if (cmp == 0 && size1 != size2) {
				cmp = size1 < size2 ? -1 : 1;
			}
			offset += knot_dname_size(dname1);
		} else if (descriptor_item_is_fixed(desc->block_types[i])) {
			cmp = memcmp(r1 + offset, r2 + offset,
			             desc->block_types[i]);
			offset += desc->block_types[i];
		} else if (descriptor_item_is_remainder(desc->block_types[i])) {
			size_t size1 = rrset_rdata_remainder_size(rrset1, offset,
			                                          pos1);
			size_t size2 = rrset_rdata_remainder_size(rrset2, offset,
			                                          pos2);
			cmp = memcmp(r1 + offset, r2 + offset,
			             size1 <= size2 ? size1 : size2);
			if (cmp == 0 && size1 != size2) {
				cmp = size1 < size2 ? -1 : 1;
			}
			/* No need to move offset, this should be end anyway. */
			assert(desc->block_types[i + 1] == KNOT_RDATA_WF_END);
		} else {
			assert(rrset1->type == KNOT_RRTYPE_NAPTR);
			uint16_t naptr_chunk_size1 =
				rrset_rdata_naptr_bin_chunk_size(rrset1, pos1);
			uint16_t naptr_chunk_size2 =
				rrset_rdata_naptr_bin_chunk_size(rrset2, pos2);
			cmp = memcmp(r1, r2,
			             naptr_chunk_size1 <= naptr_chunk_size2 ?
			             naptr_chunk_size1 : naptr_chunk_size2);
			if (cmp == 0 && naptr_chunk_size1 == naptr_chunk_size2) {
				cmp = naptr_chunk_size1 < naptr_chunk_size2 ? -1 : 1;
			}

			/*
			 * It does not matter which one we assign. If the
			 * offsets were different, then cmp != 0, if yes,
			 * NAPTR DNAME will be on correct offset.
			 */
			offset += naptr_chunk_size1;
		}

		if (cmp != 0) {
			return cmp;
		}
	}

	assert(cmp == 0);
	return 0;
}

static int knot_rrset_header_to_wire(const knot_rrset_t *rrset,
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

	dbg_rrset_detail("  TTL: %u\n", rrset->ttl);
	knot_wire_write_u32(*pos, rrset->ttl);
	*pos += sizeof(uint32_t);

	assert(owner_len != 0);
	*size += owner_len + type_cls_ttl_len;

	return KNOT_EOK;
}

/* [code-review] Split to more functions, this one's too long. */
static int knot_rrset_rdata_to_wire_one(const knot_rrset_t *rrset,
                                        uint16_t rdata_pos, uint8_t **pos,
                                        size_t max_size, size_t *rr_size,
                                        knot_compr_t *compr)
{
	assert(rrset);
	assert(pos);

	/* Put RR header to wire. */
	size_t size = 0;
	int ret = knot_rrset_header_to_wire(rrset, pos, max_size,
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
	uint8_t *rdata = rrset_rdata_pointer(rrset, rdata_pos);
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
			dbg_packet("%s: putting compressed name\n", __func__);
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
			assert(ret + size + rdlength <= max_size);
dbg_response_exec_detail(
			char *name = knot_dname_to_str(dname);
			dbg_response_detail("Compressed dname=%s size: %d\n",
			                    name, ret);
			free(name);
);
			*pos += ret;
			rdlength += ret;
			offset += knot_dname_size(dname);
			compr->wire_pos += ret;
		} else if (descriptor_item_is_dname(item)) {
			dbg_packet("%s: putting uncompressed name\n", __func__);
			const knot_dname_t *dname = rdata + offset;
dbg_rrset_exec_detail(
			char *name = knot_dname_to_str(dname);
			dbg_rrset_detail("Saving this DNAME=%s\n", name);
			free(name);
);
			// save whole domain name
			size_t maxb = max_size - size - rdlength;
			int dname_size = knot_dname_to_wire(*pos, dname, maxb);
			if (dname_size < 0)
				return KNOT_ESPACE;
			/* Store first dname compression hint. */
			if (compr && !knot_pkt_compr_hint(compr->rrinfo, hint_id)) {
				knot_pkt_compr_hint_set(compr->rrinfo, hint_id, compr->wire_pos, dname_size);
			}
			dbg_rrset_detail("Uncompressed dname size: %d\n",
			                 dname_size);
			*pos += dname_size;
			rdlength += dname_size;
			offset += dname_size;
			if (compr) {
				compr->wire_pos += dname_size;
			}
		} else if (descriptor_item_is_fixed(item)) {
			dbg_rrset_detail("Saving static chunk, size=%d\n",
			                 item);
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
			dbg_rrset_detail("Saving remaining chunk, size=%zu, "
			                 "size with remainder=%zu\n",
			                 remainder_size,
			                 size + rdlength + remainder_size);
			if (size + rdlength + remainder_size > max_size) {
				dbg_rrset("rr: to_wire: Remainder does not fit "
				          "to wire.\n");
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
				dbg_rrset("rr: to_wire: NAPTR chunk does not "
				          "fit to wire.\n");
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

	*rr_size = size;
	dbg_packet("%s: written rrset %zu bytes\n", __func__, *rr_size);
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
	if (rrset->rdata_count == 0) {
		size_t header_size = 0;
		int ret = knot_rrset_header_to_wire(rrset, pos, max_size, comp,
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
	for (uint16_t i = 0; i < rrset->rdata_count; ++i) {
		dbg_rrset_detail("rrset: to_wire: Current max_size=%zu\n",
			         max_size);
		size_t rr_size = 0;
		int ret = knot_rrset_rdata_to_wire_one(rrset, i, pos, max_size,
		                                       &rr_size, comp);
		if (ret != KNOT_EOK) {
			dbg_rrset("rrset: to_wire: Cannot convert RR. "
			          "Reason: %s.\n", knot_strerror(ret));
			return ret;
		}
		dbg_rrset_detail("Converted RR nr=%d, size=%zu\n", i, rr_size);
		/* Change size of whole RRSet. */
		size += rr_size;
		/* Change max size. */
		max_size -= rr_size;
	}

	dbg_rrset_detail("Max size: %zu, size: %zu\n", max_size, size);

	return size;
}

static int knot_rrset_rdata_store_binary(uint8_t *rdata, size_t *offset,
                                         size_t packet_offset,
                                         const uint8_t *wire,
                                         size_t *pos,
                                         size_t rdlength,
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

static size_t rrset_binary_size_one(const knot_rrset_t *rrset,
                                      size_t rdata_pos)
{
	const rdata_descriptor_t *desc =
		get_rdata_descriptor(knot_rrset_type(rrset));

	size_t offset = 0;
	size_t size = 0;
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		uint8_t *rdata = rrset_rdata_pointer(rrset, rdata_pos);
		if (descriptor_item_is_dname(item)) {
			const knot_dname_t *dname = rdata + offset;
			int dname_size = knot_dname_size(dname);
			offset += dname_size;
			size += dname_size;
		} else if (descriptor_item_is_fixed(item)) {
			offset += item;
			size += item;
		} else if (descriptor_item_is_remainder(item)) {
			size += rrset_rdata_item_size(rrset, rdata_pos) -
			        offset;
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			uint16_t naptr_chunk_size =
				rrset_rdata_naptr_bin_chunk_size(rrset, rdata_pos);
			/*
			 * Regular expressions in NAPTR are TXT's, so they
			 * can be upto 64k long.
			 */
			size += naptr_chunk_size + 2;
			offset += naptr_chunk_size;
		}
	}

	return size;
}

static void rrset_serialize_rr(const knot_rrset_t *rrset, size_t rdata_pos,
                               uint8_t *stream, size_t *size)
{
	const rdata_descriptor_t *desc =
		get_rdata_descriptor(knot_rrset_type(rrset));

	size_t offset = 0;
	*size = 0;
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		uint8_t *rdata = rrset_rdata_pointer(rrset, rdata_pos);
		assert(rdata);
		if (descriptor_item_is_dname(item)) {
			const knot_dname_t *dname = rdata + offset;
			int dname_len = knot_dname_to_wire(stream + *size, dname,
			                                   KNOT_DNAME_MAXLEN);
			*size += dname_len;
			offset += dname_len;
		} else if (descriptor_item_is_fixed(item)) {
			memcpy(stream + *size, rdata + offset, item);
			offset += item;
			*size += item;
		} else if (descriptor_item_is_remainder(item)) {
			uint16_t remainder_size =
				rrset_rdata_item_size(rrset,
			                              rdata_pos) - offset;
			memcpy(stream + *size, rdata + offset, remainder_size);
			*size += remainder_size;
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			/* Copy static chunk. */
			uint16_t naptr_chunk_size =
				rrset_rdata_naptr_bin_chunk_size(rrset, rdata_pos);
			/* We need a length. */
			memcpy(stream + *size, &naptr_chunk_size,
			       sizeof(uint16_t));
			*size += sizeof(uint16_t);
			/* Write data. */
			memcpy(stream + *size, rdata + offset, naptr_chunk_size);
		}
	}

	dbg_rrset_detail("RR nr=%zu serialized, size=%zu\n", rdata_pos, *size);
}

static int rrset_deserialize_rr(knot_rrset_t *rrset, size_t rdata_pos,
                                uint8_t *stream, uint32_t rdata_size,
                                size_t *read)
{
	const rdata_descriptor_t *desc =
		get_rdata_descriptor(knot_rrset_type(rrset));

	size_t stream_offset = 0;
	size_t rdata_offset = 0;
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		uint8_t *rdata = rrset_rdata_pointer(rrset, rdata_pos);
		if (descriptor_item_is_dname(item)) {
			const knot_dname_t *dname = stream + stream_offset;
			int dname_size = knot_dname_size(dname);

			memcpy(rdata + rdata_offset, dname, dname_size);
			stream_offset += dname_size;
			rdata_offset += dname_size;
		} else if (descriptor_item_is_fixed(item)) {
			memcpy(rdata + rdata_offset, stream + stream_offset, item);
			rdata_offset += item;
			stream_offset += item;
		} else if (descriptor_item_is_remainder(item)) {
			size_t remainder_size = rdata_size - stream_offset;
			memcpy(rdata + rdata_offset, stream + stream_offset,
			       remainder_size);
			stream_offset += remainder_size;
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			/* Read size. */
			uint16_t naptr_chunk_size;
			memcpy(&naptr_chunk_size, stream + stream_offset,
			       sizeof(uint16_t));
			stream_offset += sizeof(uint16_t);
			memcpy(rdata + rdata_offset, stream + stream_offset,
			       naptr_chunk_size);
			stream_offset += naptr_chunk_size;
			rdata_offset += rdata_offset;
		}
	}
	*read = stream_offset;
	return KNOT_EOK;
}

int knot_rrset_remove_rdata_pos(knot_rrset_t *rrset, size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return KNOT_EINVAL;
	}

	/* Reorganize the actual RDATA array. */
	uint8_t *rdata_to_remove = rrset_rdata_pointer(rrset, pos);
	dbg_rrset_detail("rr: remove_rdata_pos: Removing data=%p on "
	                 "position=%zu\n", rdata_to_remove, pos);
	assert(rdata_to_remove);
	if (pos != rrset->rdata_count - 1) {
		/* Not the last item in array - we need to move the data. */
		uint8_t *next_rdata = rrset_rdata_pointer(rrset, pos + 1);
		assert(next_rdata);
		size_t remainder_size = rrset_rdata_size_total(rrset)
		                        - rrset_rdata_offset(rrset, pos + 1);
		/*
		 * Copy the all following RR data to where this item is.
		 * No need to worry about exceeding allocated space now.
		 */
		memmove(rdata_to_remove, next_rdata, remainder_size);
	}

	uint32_t removed_size = rrset_rdata_item_size(rrset, pos);
	uint32_t new_size = rrset_rdata_size_total(rrset) - removed_size;

	if (new_size == 0) {
		assert(rrset->rdata_count == 1);
		free(rrset->rdata);
		rrset->rdata = NULL;
		free(rrset->rdata_indices);
		rrset->rdata_indices = NULL;
	} else {
		/* Resize RDATA array, the change might be worth reallocation.*/
		rrset->rdata = xrealloc(rrset->rdata, new_size);
		/*
		 * Handle RDATA indices. All indices larger than the removed one
		 * have to be adjusted. Last index will be changed later.
		 */
		for (uint16_t i = pos; i < rrset->rdata_count - 1; ++i) {
			rrset->rdata_indices[i] = rrset->rdata_indices[i + 1] - removed_size;
		}

		/* Save size of the whole RDATA array. Note: probably not needed! */
		rrset->rdata_indices[rrset->rdata_count - 2] = new_size;

		/* Resize indices, not always needed, but we'll do it to be proper. */
		rrset->rdata_indices =
			xrealloc(rrset->rdata_indices,
		                 (rrset->rdata_count - 1) * sizeof(uint32_t));
	}

	--rrset->rdata_count;

	dbg_rrset_detail("rrset: remove rdata pos: RR after removal:\n");
	knot_rrset_dump(rrset);

	return KNOT_EOK;
}

uint32_t rrset_rdata_size_total(const knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rdata_indices == NULL ||
	    rrset->rdata_count == 0) {
		return 0;
	}

	// Last index denotes end of all RRs.
	return (rrset->rdata_indices[rrset->rdata_count - 1]);
}

knot_rrset_t *knot_rrset_new(knot_dname_t *owner, uint16_t type,
                             uint16_t rclass, uint32_t ttl, mm_ctx_t *mm)
{
	knot_rrset_t *ret = mm_alloc(mm, sizeof(knot_rrset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->rdata = NULL;
	ret->rdata_count = 0;
	ret->rdata_indices = NULL;

	ret->owner = owner;
	ret->type = type;
	ret->rclass = rclass;
	ret->ttl = ttl;

	ret->additional = NULL;

	return ret;
}

knot_rrset_t *knot_rrset_new_from(const knot_rrset_t *tpl, mm_ctx_t *mm)
{
	if (!tpl) {
		return NULL;
	}

	knot_dname_t *owner = knot_dname_copy(tpl->owner);
	if (!owner) {
		return NULL;
	}

	return knot_rrset_new(owner, tpl->type, tpl->rclass, tpl->ttl, mm);
}

int knot_rrset_add_rdata(knot_rrset_t *rrset,
                         const uint8_t *rdata, uint16_t size, mm_ctx_t *mm)
{
	if (rrset == NULL || rdata == NULL || size == 0) {
		return KNOT_EINVAL;
	}

	uint8_t *p = knot_rrset_create_rdata(rrset, size, mm);
	memcpy(p, rdata, size);

	return KNOT_EOK;
}

static uint8_t* knot_rrset_create_rdata_at_pos(knot_rrset_t *rrset,
                                               size_t pos, uint16_t size,
                                               mm_ctx_t *mm)
{
	if (rrset == NULL || pos > rrset->rdata_count) {
		return NULL;
	}
	if (pos == rrset->rdata_count) {
		return knot_rrset_create_rdata(rrset, size, mm);
	}

	uint32_t total_size = rrset_rdata_size_total(rrset);

	// Realloc actual data.
	void *tmp = mm_realloc(mm, rrset->rdata, total_size + size, total_size);
	if (tmp) {
		rrset->rdata = tmp;
	} else {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	/*
	 * Move already existing data to from position we want to add to.
	 * But only if we don't want to add new item after last item.
	 */
	uint8_t *old_pointer = rrset_rdata_pointer(rrset, pos);
	assert(old_pointer);
	memmove(old_pointer + size, old_pointer,
	        rrset_rdata_size_total(rrset) - rrset_rdata_offset(rrset, pos));
	
	// Realloc indices. We will allocate exact size to save space.
	tmp = mm_realloc(mm, rrset->rdata_indices,
	                (rrset->rdata_count + 1) * sizeof(uint32_t),
	                 rrset->rdata_count * sizeof(uint32_t));
	if (tmp) {
		rrset->rdata_indices = tmp;
	} else {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	// Move indices.
	memmove(rrset->rdata_indices + pos + 1, rrset->rdata_indices + pos,
	        (rrset->rdata_count - pos) * sizeof(uint32_t));
	// Init new index
	rrset->rdata_indices[pos] = pos ? rrset->rdata_indices[pos - 1] : 0;
	++rrset->rdata_count;
	// Adjust all following items
	for (uint16_t i = pos; i < rrset->rdata_count; ++i) {
		rrset->rdata_indices[i] += size;
	}

	// Return pointer from correct position (now contains bogus data).
	return old_pointer;
}

static int knot_rrset_add_rdata_at_pos(knot_rrset_t *rrset, size_t pos,
                                       const uint8_t *rdata, uint16_t size,
                                       mm_ctx_t *mm)
{
	if (rrset == NULL || rdata == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t *p = knot_rrset_create_rdata_at_pos(rrset, pos, size, mm);
	if (p == NULL) {
		return KNOT_ERROR;
	}
	memcpy(p, rdata, size);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

uint8_t* knot_rrset_create_rdata(knot_rrset_t *rrset, uint16_t size,
                                 mm_ctx_t *mm)
{
	if (rrset == NULL) {
		return NULL;
	}

	uint32_t total_size = rrset_rdata_size_total(rrset);

	/* Realloc indices. We will allocate exact size to save space. */
	void *tmp = mm_realloc(mm, rrset->rdata_indices,
	                       (rrset->rdata_count + 1) * sizeof(uint32_t),
	                       rrset->rdata_count * sizeof(uint32_t));
	if (tmp) {
		rrset->rdata_indices = tmp;
	} else {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	/* Realloc actual data. */
	tmp = mm_realloc(mm, rrset->rdata, total_size + size, total_size);
	if (tmp) {
		rrset->rdata = tmp;
	} else {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	/* Pointer to new memory. */
	uint8_t *dst = rrset->rdata + total_size;

	/* Update indices. */
	if (rrset->rdata_count == 0) {
		rrset->rdata_indices[0] = size;
	} else {
		rrset->rdata_indices[rrset->rdata_count - 1] = total_size;
		rrset->rdata_indices[rrset->rdata_count] = total_size + size;
	}

	++rrset->rdata_count;

	return dst;
}

/*----------------------------------------------------------------------------*/


uint16_t rrset_rdata_item_size(const knot_rrset_t *rrset,
                               size_t pos)
{
	if (rrset == NULL || rrset->rdata_indices == NULL ||
	    rrset->rdata_count == 0) {
		//invalid case
		return 0;
	}

	if (rrset->rdata_count == 1 || pos == 0) {
		//first RR or only one RR (either size of first RR or total size)
		return rrset->rdata_indices[0];
	}

	assert(rrset->rdata_count >= 2 && pos != 0);
	return rrset->rdata_indices[pos] - rrset->rdata_indices[pos - 1];
}

const knot_dname_t *knot_rrset_owner(const knot_rrset_t *rrset)
{
	return rrset->owner;
}

knot_dname_t *knot_rrset_get_owner(const knot_rrset_t *rrset)
{
	return rrset->owner;
}

int knot_rrset_set_owner(knot_rrset_t *rrset, const knot_dname_t *owner)
{
	if (rrset == NULL) {
		return KNOT_EINVAL;
	}

	/* Copy the new owner. */
	knot_dname_t *owner_copy = NULL;
	if (owner) {
		owner_copy = knot_dname_copy(owner);
		if (owner_copy == NULL) {
			return KNOT_ENOMEM;
		}
	}

	/* Free old owner and assign. */
	knot_dname_free(&rrset->owner);
	rrset->owner = owner_copy;
	return KNOT_EOK;
}

void knot_rrset_set_ttl(knot_rrset_t *rrset, uint32_t ttl)
{
	if (rrset) {
		rrset->ttl = ttl;
	}
}

uint16_t knot_rrset_type(const knot_rrset_t *rrset)
{
	return rrset->type;
}

uint16_t knot_rrset_class(const knot_rrset_t *rrset)
{
	return rrset->rclass;
}

uint32_t knot_rrset_ttl(const knot_rrset_t *rrset)
{
	return rrset->ttl;
}

uint8_t *knot_rrset_get_rdata(const knot_rrset_t *rrset, size_t rdata_pos)
{
	return rrset_rdata_pointer(rrset, rdata_pos);
}

uint16_t knot_rrset_rdata_rr_count(const knot_rrset_t *rrset)
{
	if (rrset != NULL) {
		return rrset->rdata_count;
	} else {
		return 0;
	}
}

/*!
 * \brief Compare two RR sets, order of RDATA is not significant.
 */
int knot_rrset_rdata_equal(const knot_rrset_t *r1, const knot_rrset_t *r2)
{
	if (r1 == NULL || r2 == NULL || (r1->type != r2->type) ||
	    r1->rdata_count == 0 || r2->rdata_count == 0) {
		return KNOT_EINVAL;
	}

	if (r1->rdata_count != r2->rdata_count) {
		return 0;
	}

	for (uint16_t i = 0; i < r1->rdata_count; i++) {
		bool found = false;
		for (uint16_t j = 0; j < r2->rdata_count; j++) {
			if (rrset_rdata_compare_one(r1, r2, i, j) == 0) {
				found = true;
				break;
			}
		}

		if (!found) {
			return 0;
		}
	}

	return 1;
}

int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, size_t *size,
                       size_t max_size, uint16_t *rr_count, knot_compr_t *compr)
{
	if (rrset == NULL || wire == NULL || size == NULL || rr_count == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t *pos = wire;

dbg_rrset_exec_detail(
	dbg_rrset_detail("Converting following RRSet:\n");
	knot_rrset_dump(rrset);
);

	int ret = knot_rrset_to_wire_aux(rrset, &pos, max_size, compr);
	if (ret < 0) {
		// some RR didn't fit in, so no RRs should be used
		// TODO: remove last entries from compression table
		dbg_rrset_verb("Some RR didn't fit in.\n");
		return KNOT_ESPACE;
	}

	// Check if the whole RRSet fit into packet.
	assert(ret <= max_size);
	assert(pos - wire == ret);

	*size = ret;

	dbg_rrset_detail("Size after: %zu\n", *size);

	// If the rrset is empty set record counter to 1.
	*rr_count = rrset->rdata_count > 0 ? rrset->rdata_count : 1;

	return KNOT_EOK;
}

int knot_rrset_to_wire_one(const knot_rrset_t *rrset, uint16_t rr_number,
                           uint8_t *wire, size_t max_size, size_t *outsize,
                           knot_compr_t *compr)
{
	if (!rrset || !wire || !outsize)
		return KNOT_EINVAL;

	uint8_t *pos = wire;
	return knot_rrset_rdata_to_wire_one(rrset, rr_number, &pos, max_size,
					    outsize, compr);
}

int knot_rrset_rdata_from_wire_one(knot_rrset_t *rrset,
                                   const uint8_t *wire, size_t *pos,
                                   size_t total_size, size_t rdlength,
                                   mm_ctx_t *mm)
{
	if (rrset == NULL || wire == NULL || pos == NULL) {
		return KNOT_EINVAL;
	}

	if (rdlength == 0) {
		/* Nothing to parse, APLs can have 0 RDLENGTH, but only APLs. */
		if (rrset->type == KNOT_RRTYPE_APL) {
			// Add empty RDATA
			return knot_rrset_create_rdata(rrset, 0, mm) == NULL ?
			       KNOT_ENOMEM : KNOT_EOK;
		} else {
			return KNOT_EOK;
		}
	}

	dbg_rrset_detail("rr: parse_rdata_wire: Parsing RDATA of size=%zu,"
	                 " wire_size=%zu, type=%d.\n", rdlength, total_size,
	                 rrset->type);

	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);

	/* Check for obsolete record. */
	if (desc->type_name == NULL) {
		desc = get_obsolete_rdata_descriptor(rrset->type);
	}

	/*! \todo This estimate is very rough - just to have enough space for
	 *        possible unpacked dname. Should be later replaced by exact
	 *        size counting.
	 */
	uint8_t rdata_buffer[rdlength + KNOT_DNAME_MAXLEN];
	memset(rdata_buffer, 0, rdlength + KNOT_DNAME_MAXLEN);

	size_t offset = 0; // offset within in-memory RDATA
	size_t parsed = 0; // actual count of parsed octets
	const size_t packet_offset = *pos;

	/*! \todo [RRSet refactor]
	 *        This could be A LOT simpler - copy it as a whole,
	 *        unpack dnames and just do some format checks if necessary.
	 *        But it's questionable, if copying the memory when unpacking
	 *        dnames, wouldn't be too expensive.
	 */

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

dbg_rrset_exec_detail(
			dbg_rrset_detail("rr: parse_rdata_wire: Parsed DNAME, "
			                 "length=%d.\n", wire_size);
			char *name = knot_dname_to_str(rdata_buffer + offset);
			dbg_rrset_detail("rr: parse_rdata_wire: Parsed "
			                 "DNAME=%s\n", name);
			free(name);
);
			*pos += wire_size;
			offset += unpacked_size;
		} else if (descriptor_item_is_fixed(item)) {
			dbg_rrset_detail("rr: parse_rdata_wire: Saving static "
			                 "chunk of size=%u\n", item);
			int ret = knot_rrset_rdata_store_binary(rdata_buffer,
			                                        &offset,
			                                        packet_offset,
			                                        wire,
			                                        pos,
			                                        rdlength,
			                                        item);
			if (ret != KNOT_EOK) {
				dbg_rrset("rrset: rdata_from_wire: "
				          "Cannot store fixed RDATA chunk. "
				          "Reason: %s.\n", knot_strerror(ret));
				return ret;
			}
			parsed += item;
		} else if (descriptor_item_is_remainder(item)) {
			/* Item size has to be calculated. */
			size_t remainder_size = rdlength - parsed;
			dbg_rrset_detail("rr: parse_rdata_wire: Saving remaining "
			                 "chunk of size=%zu\n", remainder_size);
			int ret = knot_rrset_rdata_store_binary(rdata_buffer,
			                                        &offset,
			                                        packet_offset,
			                                        wire,
			                                        pos,
			                                        rdlength,
			                                        remainder_size);
			if (ret != KNOT_EOK) {
				dbg_rrset("rrset: rdata_from_wire: "
				          "Cannot store RDATA remainder of "
				          "size=%zu, RDLENGTH=%zu. "
				          "Reason: %s.\n", remainder_size,
				          rdlength, knot_strerror(ret));
				return ret;
			}
			parsed += remainder_size;
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			/* Read fixed part - 2 shorts. */
			const size_t naptr_fixed_part_size = 4;
			int ret = knot_rrset_rdata_store_binary(rdata_buffer,
			                                        &offset,
			                                        packet_offset,
			                                        wire,
			                                        pos,
			                                        rdlength,
			                                        naptr_fixed_part_size);
			if (ret != KNOT_EOK) {
				dbg_rrset("rrset: rdata_from_wire: "
				          "Cannot store NAPTR fixed part. "
				          "Reason: %s.\n", knot_strerror(ret));
				return ret;
			}
			parsed += naptr_fixed_part_size;
			for (int j = 0; j < 3; ++j) {
				/* Read sizes of TXT's - one byte. */
				uint8_t txt_size = *(wire + (*pos)) + 1;
				dbg_rrset_detail("rrset: rdata_from_wire: "
				                 "Read TXT nr=%d size=%d\n", j,
				                 txt_size);
				int ret = knot_rrset_rdata_store_binary(rdata_buffer,
				                                        &offset,
				                                        packet_offset,
				                                        wire,
				                                        pos,
				                                        rdlength,
				                                        txt_size);
				if (ret != KNOT_EOK) {
					dbg_rrset("rrset: rdata_from_wire: "
					          "Cannot store NAPTR TXTs. "
					          "Reason: %s.\n", knot_strerror(ret));
					return ret;
				}
				parsed += txt_size;
			}
		}
	}

	uint8_t *rdata = knot_rrset_create_rdata(rrset, offset, mm);
	if (rdata == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(rdata, rdata_buffer, offset);

	return KNOT_EOK;
}

int knot_rrset_equal(const knot_rrset_t *r1,
                     const knot_rrset_t *r2,
                     knot_rrset_compare_type_t cmp)
{
	if (cmp == KNOT_RRSET_COMPARE_PTR) {
		return r1 == r2;
	}


	if (!knot_dname_is_equal(r1->owner, r2->owner))
		return false;

	if (r1->rclass != r2->rclass || r1->type != r2->type)
		return false;

	if (cmp == KNOT_RRSET_COMPARE_WHOLE)
		return knot_rrset_rdata_equal(r1, r2);

	return true;
}

int knot_rrset_deep_copy(const knot_rrset_t *from, knot_rrset_t **to,
                         mm_ctx_t *mm)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	dbg_rrset_detail("rr: deep_copy: Copying RRs of type %d\n",
	                 from->type);
	*to = knot_rrset_new_from(from, mm);
	if (*to == NULL) {
		*to = NULL;
		return KNOT_ENOMEM;
	}

	(*to)->rdata_count = from->rdata_count;
	(*to)->additional = NULL; /* Never copy. */

	/* Just copy arrays - actual data + indices. */
	(*to)->rdata = mm_alloc(mm, rrset_rdata_size_total(from));
	if ((*to)->rdata == NULL) {
		ERR_ALLOC_FAILED;
		knot_rrset_deep_free(to, 1, mm);
		return KNOT_ENOMEM;
	}
	memcpy((*to)->rdata, from->rdata, rrset_rdata_size_total(from));

	(*to)->rdata_indices = mm_alloc(mm, sizeof(uint32_t) * from->rdata_count);
	if ((*to)->rdata_indices == NULL) {
		ERR_ALLOC_FAILED;
		knot_rrset_deep_free(to, 1, mm);
		return KNOT_ENOMEM;
	}
	memcpy((*to)->rdata_indices, from->rdata_indices,
	       sizeof(uint32_t) * from->rdata_count);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_rrset_rotate(knot_rrset_t *rrset)
{
	/*! \todo Maybe implement properly one day. */
	//rrset->rdata = rrset->rdata->next;
}

/*----------------------------------------------------------------------------*/

void knot_rrset_free(knot_rrset_t **rrset)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	knot_dname_free(&(*rrset)->owner);

	if (rrset_additional_needed((*rrset)->type)) {
		free((*rrset)->additional);
	}

	free(*rrset);
	*rrset = NULL;
}

static void rrset_deep_free_content(knot_rrset_t *rrset, int free_owner,
                                    mm_ctx_t *mm)
{
	assert(rrset);

	mm_free(mm, rrset->rdata);
	mm_free(mm, rrset->rdata_indices);
	if (free_owner) {
		knot_dname_free(&rrset->owner);
	}
}

void knot_rrset_deep_free(knot_rrset_t **rrset, int free_owner, mm_ctx_t *mm)
{
	/*! \bug The number of different frees in rrset is too damn high! */
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	rrset_deep_free_content(*rrset, free_owner, mm);

	if (rrset_additional_needed((*rrset)->type)) {
		mm_free(mm, (*rrset)->additional);
	}

	mm_free(mm, *rrset);
	*rrset = NULL;
}

static int knot_rrset_add_rr_n(knot_rrset_t *rrset, const knot_rrset_t *rr,
                               size_t pos, mm_ctx_t *mm)
{
	if (rrset == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}
	if (!knot_rrset_equal(rrset, rr, KNOT_RRSET_COMPARE_HEADER)) {
		// Adding to a different header
		return KNOT_EINVAL;
	}

	uint8_t *new_rdata =
		knot_rrset_create_rdata(rrset,
	                                rrset_rdata_item_size(rr, pos),
	                                mm);
	if (new_rdata == NULL) {
		return KNOT_ERROR;
	}

	memcpy(new_rdata, rrset_rdata_pointer(rr, pos),
	       rrset_rdata_item_size(rr, pos));

	return KNOT_EOK;
}

int knot_rrset_merge(knot_rrset_t *rrset1, const knot_rrset_t *rrset2,
                     mm_ctx_t *mm)
{
	for (uint16_t i = 0; i < rrset2->rdata_count; ++i) {
		int ret = knot_rrset_add_rr_n(rrset1, rrset2, i, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int knot_rrset_add_rr_sort_n(knot_rrset_t *rrset, const knot_rrset_t *rr,
                                    int *merged, int *deleted, size_t pos,
                                    mm_ctx_t *mm)
{
	if (rrset == NULL || rr == NULL) {
		dbg_rrset("rrset: add_rr_sort: NULL arguments.");
		return KNOT_EINVAL;
	}

dbg_rrset_exec_detail(
	char *name = knot_dname_to_str(rrset->owner);
	dbg_rrset_detail("rrset: add_rr_sort: Merging %s.\n", name);
	free(name);
);

	if ((!knot_dname_is_equal(rrset->owner, rr->owner))
	    || rrset->rclass != rr->rclass
	    || rrset->type != rr->type) {
		dbg_rrset("rrset: add_rr_sort: Trying to merge "
		          "different RRs.\n");
		return KNOT_EINVAL;
	}

	int found = 0;
	int duplicated = 0;
	// Compare RR with all RRs in the first RRSet.
	size_t insert_to = 0;
	for (uint16_t j = 0; j < rrset->rdata_count && (!duplicated && !found); ++j) {
		int cmp = rrset_rdata_compare_one(rrset, rr, j, pos);
		if (cmp == 0) {
			// Duplication - no need to merge this RR
			duplicated = 1;
		} else if (cmp > 0) {
			// Found position to insert
			found = 1;
		} else {
			// Not yet - it might be next position
			insert_to = j + 1;
		}
	}

	if (!duplicated) {
		*merged += 1; // = need to shallow free rrset2
		// Insert RR to RRSet
		int ret = knot_rrset_add_rdata_at_pos(rrset, insert_to,
			                  rrset_rdata_pointer(rr, pos),
			                  rrset_rdata_item_size(rr, pos),
			                  mm);
		if (ret != KNOT_EOK) {
			dbg_rrset("rrset: add_rr: Could not "
			          "add RDATA to RRSet. (%s)\n",
			          knot_strerror(ret));
			return ret;
		}
	} else {
		assert(!found);
		*deleted += 1; // = need to shallow free rr
	}

	return KNOT_EOK;
}

int knot_rrset_merge_sort(knot_rrset_t *rrset1, const knot_rrset_t *rrset2,
                          int *merged_rrs, int *deleted_rrs, mm_ctx_t *mm)
{
	int result = KNOT_EOK;
	int merged = 0;
	int deleted = 0;

	for (uint16_t i = 0; i < rrset2->rdata_count; ++i) {
		result = knot_rrset_add_rr_sort_n(rrset1, rrset2, &merged,
		                                  &deleted, i, mm);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (merged_rrs) {
		*merged_rrs = merged;
	}

	if (deleted_rrs) {
		*deleted_rrs = deleted;
	}

	return result;
}

/*!
 * \todo Not optimal, rewrite!
 */
int knot_rrset_sort_rdata(knot_rrset_t *rrset)
{
	if (!rrset) {
		return KNOT_EINVAL;
	}

	// 1. create temporary rrset
	// 2. sort-merge given rrset into temporary rrset
	// 3. swap the contents, free the temporary

	knot_rrset_t *sorted = knot_rrset_new(rrset->owner, rrset->type,
	                                      rrset->rclass, rrset->ttl,
	                                      NULL);
	if (!sorted) {
		return KNOT_ENOMEM;
	}

	int result = knot_rrset_merge_sort(sorted, rrset, NULL, NULL, NULL);
	if (result != KNOT_EOK) {
		knot_rrset_deep_free(&sorted, 1, NULL);
		return result;
	}

	rrset_deep_free_content(rrset, 0, NULL);
	*rrset = *sorted;
	free(sorted);

	return KNOT_EOK;
}

bool knot_rrset_is_nsec3rel(const knot_rrset_t *rr)
{
	assert(rr != NULL);

	/* Is NSEC3 or non-empty RRSIG covering NSEC3. */
	return ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
	        || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
	            && knot_rdata_rrsig_type_covered(rr, 0)
	            == KNOT_RRTYPE_NSEC3));
}

/*----------------------------------------------------------------------------*/

void knot_rrset_dump(const knot_rrset_t *rrset)
{
dbg_rrset_exec_detail(
	if (rrset == NULL) {
		return;
	}

	dbg_rrset_detail("      ------- RRSET -------\n");

	char *name = knot_dname_to_str(rrset->owner);
	dbg_rrset_detail("  owner: %s\n", name);
	free(name);
	dbg_rrset_detail("  type: %u\n", rrset->type);
	dbg_rrset_detail("  class: %d\n",  rrset->rclass);
	dbg_rrset_detail("  ttl: %d\n", rrset->ttl);
	dbg_rrset_detail("  RDATA count: %d\n", rrset->rdata_count);

	dbg_rrset_detail("RDATA indices (total=%d):\n",
	        rrset_rdata_size_total(rrset));

	for (uint16_t i = 0; i < rrset->rdata_count; i++) {
		dbg_rrset_detail("%d=%d\n", i, rrset_rdata_offset(rrset, i));
	}

	if (knot_rrset_rdata_rr_count(rrset) == 0) {
		dbg_rrset_detail("NO RDATA\n");
	}

	for (uint16_t i = 0; i < knot_rrset_rdata_rr_count(rrset); i++) {
		knot_rrset_rdata_dump(rrset, i);
	}
);
}

uint64_t rrset_binary_size(const knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rdata_count == 0) {
		return 0;
	}
	uint64_t size = sizeof(uint64_t) + // size at the beginning
	              knot_dname_size(knot_rrset_owner(rrset)) + // owner data
	              sizeof(uint16_t) + // type
	              sizeof(uint16_t) + // class
	              sizeof(uint32_t) + // ttl
	              sizeof(uint16_t) +  //RR count
	              sizeof(uint32_t) * rrset->rdata_count; // RR indices
	for (uint16_t i = 0; i < rrset->rdata_count; i++) {
		/* Space to store length of one RR. */
		size += sizeof(uint32_t);
		/* Actual data. */
		size += rrset_binary_size_one(rrset, i);
	}

	return size;
}

int rrset_serialize(const knot_rrset_t *rrset, uint8_t *stream, size_t *size)
{
	if (rrset == NULL || rrset->rdata_count == 0) {
		return KNOT_EINVAL;
	}

	uint64_t rrset_length = rrset_binary_size(rrset);
	dbg_rrset_detail("rr: serialize: Binary size=%"PRIu64"\n", rrset_length);
	memcpy(stream, &rrset_length, sizeof(uint64_t));

	size_t offset = sizeof(uint64_t);
	/* Save RR indices. Size first. */
	memcpy(stream + offset, &rrset->rdata_count, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	memcpy(stream + offset, rrset->rdata_indices,
	       rrset->rdata_count * sizeof(uint32_t));
	offset += sizeof(uint32_t) * rrset->rdata_count;
	/* Save owner. */
	offset += knot_dname_to_wire(stream + offset, rrset->owner, rrset_length - offset);

	/* Save static data. */
	memcpy(stream + offset, &rrset->type, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	memcpy(stream + offset, &rrset->rclass, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	memcpy(stream + offset, &rrset->ttl, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	/* Copy RDATA. */
	for (uint16_t i = 0; i < rrset->rdata_count; i++) {
		size_t size_one = 0;
		/* This cannot fail, if it does, RDATA are malformed. TODO */
		/* TODO this can be written later. */
		uint32_t rr_size = rrset_binary_size_one(rrset, i);
		dbg_rrset_detail("rr: serialize: RR index=%d size=%d\n",
		                 i, rr_size);
		memcpy(stream + offset, &rr_size, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		rrset_serialize_rr(rrset, i, stream + offset, &size_one);
		assert(size_one == rr_size);
		offset += size_one;
	}

	*size = offset;
	assert(*size == rrset_length);
	dbg_rrset_detail("rr: serialize: RRSet serialized, size=%zu\n", *size);
	return KNOT_EOK;
}

int rrset_serialize_alloc(const knot_rrset_t *rrset, uint8_t **stream,
                          size_t *size)
{
	/* Get the binary size. */
	*size = rrset_binary_size(rrset);
	if (*size == 0) {
		/* Nothing to serialize. */
		dbg_rrset("rrset: serialize alloc: No data to serialize.\n");
		return KNOT_EINVAL;
	}

	/* Prepare memory. */
	*stream = malloc(*size);
	if (*stream == NULL) {
		return KNOT_ENOMEM;
	}

	return rrset_serialize(rrset, *stream, size);
}

int rrset_deserialize(uint8_t *stream, size_t *stream_size,
                      knot_rrset_t **rrset)
{
	if (sizeof(uint64_t) > *stream_size) {
		dbg_rrset("rr: deserialize: No space for length.\n");
		return KNOT_ESPACE;
	}
	uint64_t rrset_length = 0;
	memcpy(&rrset_length, stream, sizeof(uint64_t));
	if (rrset_length > *stream_size) {
		dbg_rrset("rr: deserialize: No space for whole RRSet. "
		          "(given=%zu needed=%"PRIu64")\n", *stream_size,
		          rrset_length);
		return KNOT_ESPACE;
	}

	size_t offset = sizeof(uint64_t);
	uint16_t rdata_count = 0;
	memcpy(&rdata_count, stream + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	uint32_t *rdata_indices = xmalloc(rdata_count * sizeof(uint32_t));
	memcpy(rdata_indices, stream + offset,
	       rdata_count * sizeof(uint32_t));
	offset += rdata_count * sizeof(uint32_t);
	/* Read owner from the stream. */
	unsigned owner_size = knot_dname_size(stream + offset);
	knot_dname_t *owner = knot_dname_copy_part(stream + offset, owner_size);
	assert(owner);
	offset += owner_size;
	/* Read type. */
	uint16_t type = 0;
	memcpy(&type, stream + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	/* Read class. */
	uint16_t rclass = 0;
	memcpy(&rclass, stream + offset, sizeof(uint16_t));
	offset += sizeof(uint16_t);
	/* Read TTL. */
	uint32_t ttl = 0;
	memcpy(&ttl, stream + offset, sizeof(uint32_t));
	offset += sizeof(uint32_t);

	/* Create new RRSet. */
	*rrset = knot_rrset_new(owner, type, rclass, ttl, NULL);
	if (*rrset == NULL) {
		knot_dname_free(&owner);
		free(rdata_indices);
		return KNOT_ENOMEM;
	}

	(*rrset)->rdata_indices = rdata_indices;
	(*rrset)->rdata_count = rdata_count;

	(*rrset)->rdata = xmalloc(rdata_indices[rdata_count - 1]);
	memset((*rrset)->rdata, 0, rdata_indices[rdata_count - 1]);
	/* Read RRs. */
	for (uint16_t i = 0; i < (*rrset)->rdata_count; i++) {
		/*
		 * There's always size of rdata in the beginning.
		 * Needed because of remainders.
		 */
		uint32_t rdata_size = 0;
		memcpy(&rdata_size, stream + offset, sizeof(uint32_t));
		offset += sizeof(uint32_t);
		size_t read = 0;
		int ret = rrset_deserialize_rr((*rrset), i, stream + offset,
		                               rdata_size, &read);
		if (ret != KNOT_EOK) {
			free((*rrset)->rdata);
			free(rdata_indices);
			return ret;
		}
		/* TODO handle malformations. */
		dbg_rrset_detail("rr: deserialaze: RR read size=%zu,"
		                 "actual=%"PRIu32"\n", read, rdata_size);
		assert(read == rdata_size);
		offset += read;
	}

dbg_rrset_exec_detail(
	dbg_rrset_detail("RRSet deserialized:\n");
	knot_rrset_dump(*rrset);
);
	*stream_size = *stream_size - offset;

	return KNOT_EOK;
}

int knot_rrset_find_rr_pos(const knot_rrset_t *rr_search_in,
                           const knot_rrset_t *rr_reference, size_t pos,
                           size_t *pos_out)
{
	int found = 0;
	for (uint16_t i = 0; i < rr_search_in->rdata_count && !found; ++i) {
		if (rrset_rdata_compare_one(rr_search_in,
		                            rr_reference, i, pos) == 0) {
			*pos_out = i;
			found = 1;
		}
	}

	return found ? KNOT_EOK : KNOT_ENOENT;
}

static int knot_rrset_remove_rr(knot_rrset_t *rrset,
                                const knot_rrset_t *rr_from, size_t rdata_pos)
{
	/*
	 * Position in first and second rrset can differ, we have
	 * to search for position first.
	 */
	size_t pos_to_remove = 0;
	int ret = knot_rrset_find_rr_pos(rrset, rr_from, rdata_pos,
	                                 &pos_to_remove);
	if (ret == KNOT_EOK) {
		/* Position found, can be removed. */
		dbg_rrset_detail("rr: remove_rr: Counter position found=%zu\n",
		                 pos_to_remove);
		assert(pos_to_remove < rrset->rdata_count);
		ret = knot_rrset_remove_rdata_pos(rrset, pos_to_remove);
		if (ret != KNOT_EOK) {
			dbg_rrset("Cannot remove RDATA from RRSet (%s).\n",
			          knot_strerror(ret));
			return ret;
		}
	} else {
		dbg_rrset_verb("rr: remove_rr: RDATA not found (%s).\n",
		               knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

int knot_rrset_add_rr_from_rrset(knot_rrset_t *dest, const knot_rrset_t *source,
                                 size_t rdata_pos, mm_ctx_t *mm)
{
	if (dest == NULL || source == NULL ||
	    rdata_pos >= source->rdata_count) {
		return KNOT_EINVAL;
	}

	/* Get size of RDATA to be copied. */
	uint16_t item_size = rrset_rdata_item_size(source, rdata_pos);
	/* Reserve space in dest RRSet. */
	uint8_t *rdata = knot_rrset_create_rdata(dest, item_size, mm);
	if (rdata == NULL) {
		dbg_rrset("rr: add_rr_from_rrset: Could not create RDATA.\n");
		return KNOT_ERROR;
	}

	/* Copy actual data. */
	memcpy(rdata, rrset_rdata_pointer(source, rdata_pos), item_size);

	return KNOT_EOK;
}

int knot_rrset_remove_rr_using_rrset(knot_rrset_t *from,
                                     const knot_rrset_t *what,
                                     knot_rrset_t **rr_deleted)
{
	if (from == NULL || what == NULL || rr_deleted == NULL) {
		return KNOT_EINVAL;
	}

	knot_rrset_t *return_rr = knot_rrset_new_from(what, NULL);
	if (return_rr == NULL) {
		return KNOT_ENOMEM;
	}
	for (uint16_t i = 0; i < what->rdata_count; ++i) {
		int ret = knot_rrset_remove_rr(from, what, i);
		if (ret == KNOT_EOK) {
			/* RR was removed, can be added to 'return' RRSet. */
			ret = knot_rrset_add_rr_from_rrset(return_rr, what, i, NULL);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&return_rr, 0, NULL);
				dbg_xfrin("xfr: Could not add RR (%s).\n",
				          knot_strerror(ret));
				return ret;
			}
			dbg_rrset_detail("rrset: remove_rr_using_rrset: "
			                 "Successfuly removed and returned this RR:\n");
			knot_rrset_rdata_dump(return_rr, return_rr->rdata_count - 1);
		} else if (ret != KNOT_ENOENT) {
			/* NOENT is OK, but other errors are not. */
			dbg_rrset("rrset: remove_using_rrset: "
			          "RRSet removal failed (%s).\n",
			          knot_strerror(ret));
			knot_rrset_deep_free(&return_rr, 0, NULL);
			return ret;
		}
	}

	*rr_deleted = return_rr;
	return KNOT_EOK;
}

int knot_rrset_remove_rr_using_rrset_del(knot_rrset_t *from,
                                         const knot_rrset_t *what)
{
	knot_rrset_t *rr_removed = NULL;
	int ret = knot_rrset_remove_rr_using_rrset(from, what, &rr_removed);
	knot_rrset_deep_free(&rr_removed, 1, NULL);
	return ret;
}

void knot_rrset_set_class(knot_rrset_t *rrset, uint16_t rclass)
{
	if (!rrset) {
		return;
	}

	rrset->rclass = rclass;
}

int knot_rrset_ds_check(const knot_rrset_t *rrset)
{
	// Check if the legth of the digest corresponds to the proper size of
	// the digest according to the given algorithm
	for (uint16_t i = 0; i < rrset->rdata_count; ++i) {
		/* 4 bytes before actual digest. */
		if (rrset_rdata_item_size(rrset, i) < 4) {
			/* Not even keytag, alg and alg type. */
			return KNOT_EMALF;
		}
		uint16_t len = rrset_rdata_item_size(rrset, i) - 4;
		uint8_t type = rrset_rdata_pointer(rrset, i)[3];
		if (type == 0 || len == 0) {
			return KNOT_EINVAL;
		} else if (len != knot_ds_digest_length(type)) {
			return KNOT_EDSDIGESTLEN;
		}
	}
	return KNOT_EOK;
}

int rrset_additional_needed(uint16_t rrtype)
{
	return (rrtype == KNOT_RRTYPE_MX ||
		rrtype == KNOT_RRTYPE_NS ||
		rrtype == KNOT_RRTYPE_SRV);
}

static int add_rdata_to_rrsig(knot_rrset_t *new_sig, uint16_t type,
                              const knot_rrset_t *rrsigs, mm_ctx_t *mm)
{
	for (size_t i = 0; i < rrsigs->rdata_count; ++i) {
		const uint16_t type_covered =
			knot_rdata_rrsig_type_covered(rrsigs, i);
		if (type_covered == type) {
			int ret = knot_rrset_add_rr_from_rrset(new_sig,
			                                       rrsigs,
			                                       i,
			                                       mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return new_sig->rdata_count > 0 ? KNOT_EOK : KNOT_ENOENT;
}

int knot_rrset_synth_rrsig(const knot_rrset_t *covered, const knot_rrset_t *rrsigs,
                           knot_rrset_t **out_sig, mm_ctx_t *mm)
{
	if (covered == NULL || rrsigs == NULL) {
		return KNOT_ENOENT;
	}

	if (out_sig == NULL || !knot_dname_is_equal(covered->owner, rrsigs->owner)) {
		return KNOT_EINVAL;
	}

	*out_sig = knot_rrset_new_from(covered, mm);
	if (*out_sig == NULL) {
		return KNOT_ENOMEM;
	}
	(*out_sig)->type = KNOT_RRTYPE_RRSIG;

	int ret = add_rdata_to_rrsig(*out_sig, covered->type, rrsigs, mm);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(out_sig, 1, mm);
		return ret;
	}

	return KNOT_EOK;
}

