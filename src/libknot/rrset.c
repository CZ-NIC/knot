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
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <inttypes.h>

#include "consts.h"
#include "common.h"
#include "common/mempattern.h"
#include "rrset.h"
#include "common/descriptor.h"
#include "util/debug.h"
#include "util/utils.h"
#include "packet/response.h"
#include "util/wire.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static int rrset_retain_dnames_in_rr(knot_dname_t **dname, void *data)
{
	UNUSED(data);
	if (dname == NULL || *dname == NULL) {
		return KNOT_EINVAL;
	}

	knot_dname_retain(*dname);
	return KNOT_EOK;
}

static int rrset_release_dnames_in_rr(knot_dname_t **dname, void *data)
{
	UNUSED(data);
	if (dname == NULL || *dname == NULL) {
		return KNOT_EINVAL;
	}

	knot_dname_release(*dname);
	return KNOT_EOK;
}

static uint32_t rrset_rdata_offset(const knot_rrset_t *rrset,
                                   size_t pos)
{
	if (rrset == NULL || rrset->rdata_indices == NULL ||
	    pos >= rrset->rdata_count || pos == 0) {
		return 0;
	}

	assert(rrset->rdata_count >= 2);
	return rrset->rdata_indices[pos - 1];
}

static uint8_t *rrset_rdata_pointer(const knot_rrset_t *rrset,
                                    size_t pos)
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
			knot_dname_t *dname;
			memcpy(&dname, rdata + offset, sizeof(knot_dname_t *));
			char *name = knot_dname_to_str(dname);
			if (dname == NULL) {
				dbg_rrset_detail("DNAME error.\n");
				return;
			}
			dbg_rrset_detail("block=%d: (%p) DNAME=%s\n",
			        i, dname, name);
			free(name);
			offset += sizeof(knot_dname_t *);
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
	assert(rrset_rdata_item_size(rrset, pos) != 0);

	size_t ret = rrset_rdata_item_size(rrset, pos) - offset;
	assert(ret <= rrset_rdata_size_total(rrset));
	return ret;
}

/* [code-review] Please document at least parameters & return values. */
static int rrset_rdata_compare_one(const knot_rrset_t *rrset1,
                                   const knot_rrset_t *rrset2,
                                   size_t pos1, size_t pos2)
{
	/* [code-review] Just to be sure. */
	assert(rrset1 != NULL);
	assert(rrset2 != NULL);

	uint8_t *r1 = rrset_rdata_pointer(rrset1, pos1);
	uint8_t *r2 = rrset_rdata_pointer(rrset2, pos2);
	assert(rrset1->type == rrset2->type);
	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset1->type);
	int cmp = 0;
	size_t offset = 0;

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		if (descriptor_item_is_dname(desc->block_types[i])) {
			knot_dname_t *dname1 = NULL;
			memcpy(&dname1, r1 + offset, sizeof(knot_dname_t *));
			knot_dname_t *dname2 = NULL;
			memcpy(&dname2, r2 + offset, sizeof(knot_dname_t *));
			cmp = knot_dname_compare(dname1, dname2);
			offset += sizeof(knot_dname_t *);
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

	const uint8_t *owner;
	uint8_t owner_len;

	// Use compressed owner.
	if (compr) {
		owner = compr->owner.wire + compr->owner.pos;
		owner_len = compr->owner.size;
	// Use rrset owner.
	} else {
		owner = knot_dname_name(rrset->owner);
		owner_len = knot_dname_size(rrset->owner);
	}

	dbg_response("Max size: %zu, compressed owner: %s, owner size: %u\n",
	             max_size, compr ? "yes" : "no", owner_len);

	// Check wire space for header.
	if (*size + owner_len + type_cls_ttl_len + rrlen_len > max_size) {
		dbg_rrset_detail("Header does not fit into wire.\n");
		return KNOT_ESPACE;
	}

	// Write owner, type, class and ttl to wire.
	memcpy(*pos, owner, owner_len);
	*pos += owner_len;

	dbg_rrset_detail("  Type: %u\n", rrset->type);
	knot_wire_write_u16(*pos, rrset->type);
	*pos += sizeof(uint16_t);

	dbg_rrset_detail("  Class: %u\n", rrset->rclass);
	knot_wire_write_u16(*pos, rrset->rclass);
	*pos += sizeof(uint16_t);

	dbg_rrset_detail("  TTL: %u\n", rrset->ttl);
	knot_wire_write_u32(*pos, rrset->ttl);
	*pos += sizeof(uint32_t);

	*size += owner_len + type_cls_ttl_len;

	return KNOT_EOK;
}

/* [code-review] Split to more functions, this one's too long. */
static int knot_rrset_rdata_to_wire_one(const knot_rrset_t *rrset,
                                        size_t rdata_pos, uint8_t **pos,
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

	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		int item = desc->block_types[i];
		if (compr && descriptor_item_is_compr_dname(item)) {
			knot_dname_t *dname;
			memcpy(&dname, rdata + offset, sizeof(knot_dname_t *));
			assert(dname);
			int ret = knot_response_compress_dname(dname,
			            compr, *pos,
			            max_size - size - rdlength);
			if (ret < 0) {
				return KNOT_ESPACE;
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
			offset += sizeof(knot_dname_t *);
			compr->wire_pos += ret;
		} else if (descriptor_item_is_dname(item)) {
			knot_dname_t *dname;
			memcpy(&dname, rdata + offset, sizeof(knot_dname_t *));
			assert(dname && dname->name);
			if (size + rdlength + knot_dname_size(dname) > max_size) {
				dbg_rrset("rr: to_wire: DNAME does not fit into RR.\n");
				return KNOT_ESPACE;
			}
dbg_rrset_exec_detail(
			char *name = knot_dname_to_str(dname);
			dbg_rrset_detail("Saving this DNAME=%s\n", name);
			free(name);
);
			// save whole domain name
			memcpy(*pos, knot_dname_name(dname),
			       knot_dname_size(dname));
			dbg_rrset_detail("Uncompressed dname size: %d\n",
			                 knot_dname_size(dname));
			*pos += knot_dname_size(dname);
			rdlength += knot_dname_size(dname);
			offset += sizeof(knot_dname_t *);
			if (compr) {
				compr->wire_pos += knot_dname_size(dname);
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
	assert(size <= max_size);
	return KNOT_EOK;
}

static int knot_rrset_to_wire_aux(const knot_rrset_t *rrset, uint8_t **pos,
                                  size_t max_size, compression_param_t *comp)
{
	uint8_t wf_owner[256];
	size_t size = 0;

	assert(rrset != NULL);
	assert(rrset->owner != NULL);
	assert(pos != NULL);
	assert(*pos != NULL);

	dbg_rrset_detail("Max size: %zu, owner: %p, owner size: %d\n",
	                 max_size, rrset->owner, rrset->owner->size);

	knot_compr_t compr_info;
	if (comp) {
		dbg_response_detail("Compressing RR owner: %s.\n",
		                    rrset->owner->name);
		compr_info.table = comp->compressed_dnames;
		compr_info.wire = comp->wire;
		compr_info.wire_pos = comp->wire_pos;
		int ret = knot_response_compress_dname(rrset->owner, &compr_info,
		                                       wf_owner, max_size);
		if (ret < 0) {
			return KNOT_ESPACE;
		}

		compr_info.owner.pos = 0;
		compr_info.owner.wire = wf_owner;
		compr_info.owner.size = ret;

		dbg_response_detail("Compressed owner has size=%d\n",
		                    compr_info.owner.size);
	}

	dbg_rrset_detail("Max size: %zu, size: %zu\n", max_size, size);

	// No RDATA, just save header and 0 RDLENGTH.
	if (rrset->rdata_count == 0) {
		size_t header_size = 0;
		int ret = knot_rrset_header_to_wire(rrset, pos, max_size,
		                                    comp ? &compr_info : NULL,
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
		                                       &rr_size,
		                                       comp ? &compr_info : NULL);
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

static int rrset_type_multiple_dnames(const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_SOA || rrset->type == KNOT_RRTYPE_MINFO ||
	    rrset->type == KNOT_RRTYPE_RP) {
		return 1;
	} else {
		return 0;
	}
}

static int rrset_find_rr_pos_for_pointer(const knot_rrset_t *rrset,
                                         knot_dname_t **p, size_t *pos)
{
	if (p == NULL) {
		return 0;
	}

	/* [code-review] Added check of 'p' validity - whether it
	 * points to the RDATA array of 'rrset'.
	 */
	if ((size_t)p < (size_t)rrset->rdata
	    || (size_t)p > (size_t)rrset->rdata
	                   + rrset_rdata_size_total(rrset)) {
		// 'p' is not within the RDATA array
		return KNOT_ERANGE;
	}

	size_t offset = (size_t)p - (size_t)rrset->rdata;

	if (offset < rrset_rdata_item_size(rrset, 0)) {
		return 0;
	}
	for (uint16_t i = 0; i < rrset->rdata_count; ++i) {
		if (rrset_rdata_offset(rrset, i) > offset) {
			*pos = i - 1;
			return KNOT_EOK;
		} else if (rrset_rdata_offset(rrset, i) == offset) {
			*pos = i;
			return KNOT_EOK;
		}
	}
	*pos = rrset->rdata_count - 1;
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
			knot_dname_t *dname;
			memcpy(&dname, rdata + offset, sizeof(knot_dname_t *));
			assert(dname);
			offset += sizeof(knot_dname_t *);
			size += knot_dname_size(dname) + 1; // extra 1 - we need a size
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
		if (descriptor_item_is_dname(item)) {
			knot_dname_t *dname;
			memcpy(&dname, rdata + offset, sizeof(knot_dname_t *));
			assert(dname);
			memcpy(stream + *size, &dname->size, 1);
			*size += 1;
			memcpy(stream + *size, dname->name, dname->size);
			offset += sizeof(knot_dname_t *);
			*size += dname->size;
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
			/* Read dname size. */
			uint8_t dname_size = 0;
			memcpy(&dname_size, stream + stream_offset, 1);
			stream_offset += 1;
			knot_dname_t *dname =
				knot_dname_new_from_wire(stream + stream_offset,
			                                 dname_size, NULL);
			if (dname == NULL) {
				return KNOT_ERROR;
			}
			assert(dname->size == dname_size);
			memcpy(rdata + rdata_offset, &dname,
			       sizeof(knot_dname_t *));
			stream_offset += dname_size;
			rdata_offset += sizeof(knot_dname_t *);
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

	/* Handle DNAMEs inside RDATA. */
	int ret = rrset_rr_dnames_apply(rrset, pos, rrset_release_dnames_in_rr,
	                                NULL);
	if (ret != KNOT_EOK) {
		dbg_rrset("rr: remove_rdata_pos: Could not release DNAMEs "
		          "within RDATA (%s).\n", knot_strerror(ret));
		return ret;
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

	/*! \todo Realloc might not be needed. Only if the RRSet is large. */
	if (new_size == 0) {
		assert(rrset->rdata_count == 1);
		free(rrset->rdata);
		rrset->rdata = NULL;
		free(rrset->rdata_indices);
		rrset->rdata_indices = NULL;
	} else {
		/* [code-review] Should not be done always - as said in the TODO
		 *               above. But also, why here and not in the part
		 *               handling the RDATA array?
		 */
		rrset->rdata = xrealloc(rrset->rdata, new_size);
		/*
		 * Handle RDATA indices. All indices larger than the removed one
		 * have to be adjusted. Last index will be changed later.
		 */
		/* [code-review] The upper bound should be rdata_count - 2, it
		 *               has not yet been adjusted.
		 */
		for (uint16_t i = pos; i < rrset->rdata_count - 1; ++i) {
			rrset->rdata_indices[i] = rrset->rdata_indices[i + 1] - removed_size;
		}

		/* Save size of the whole RDATA array. Note: probably not needed! */
		rrset->rdata_indices[rrset->rdata_count - 2] = new_size;

		/* Resize indices, might not be needed, but we'll do it to be proper. */
		rrset->rdata_indices =
			xrealloc(rrset->rdata_indices,
		                 (rrset->rdata_count - 1) * sizeof(uint32_t));
	}

	--rrset->rdata_count;

	dbg_rrset_detail("rrset: remove rdata pos: RR after removal:\n");
	knot_rrset_dump(rrset);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

uint32_t rrset_rdata_size_total(const knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rdata_indices == NULL ||
	    rrset->rdata_count == 0) {
		return 0;
	}

	/* Last index denotes end of all RRs. */
	return (rrset->rdata_indices[rrset->rdata_count - 1]);
}

knot_rrset_t *knot_rrset_new(knot_dname_t *owner, uint16_t type,
                             uint16_t rclass, uint32_t ttl)
{
	knot_rrset_t *ret = xmalloc(sizeof(knot_rrset_t));

	ret->rdata = NULL;
	ret->rdata_count = 0;
	ret->rdata_indices = NULL;

	/* Retain reference to owner. */
	knot_dname_retain(owner);

	ret->owner = owner;
	ret->type = type;
	ret->rclass = rclass;
	ret->ttl = ttl;
	ret->rrsigs = NULL;

	return ret;
}

int knot_rrset_add_rdata(knot_rrset_t *rrset,
                         const uint8_t *rdata, uint16_t size)
{
	if (rrset == NULL || rdata == NULL || size == 0) {
		return KNOT_EINVAL;
	}

	uint8_t *p = knot_rrset_create_rdata(rrset, size);
	memcpy(p, rdata, size);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

uint8_t* knot_rrset_create_rdata(knot_rrset_t *rrset, uint16_t size)
{
	if (rrset == NULL || size == 0) {
		return NULL;
	}

	uint32_t total_size = rrset_rdata_size_total(rrset);

	/* Realloc indices. We will allocate exact size to save space. */
	/* TODO this sucks big time - allocation of length 1. */
	/* But another variable holding allocated count is out of question. What now?*/
	rrset->rdata_indices = xrealloc(rrset->rdata_indices,
	                                (rrset->rdata_count + 1) * sizeof(uint32_t));

	/* Realloc actual data. */
	rrset->rdata = xrealloc(rrset->rdata, total_size + size);

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

/*----------------------------------------------------------------------------*/

int knot_rrset_set_rrsigs(knot_rrset_t *rrset, knot_rrset_t *rrsigs)
{
	if (rrset == NULL) {
		return KNOT_EINVAL;
	}

	rrset->rrsigs = rrsigs;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_add_rrsigs(knot_rrset_t *rrset, knot_rrset_t *rrsigs,
                          knot_rrset_dupl_handling_t dupl)
{
	if (rrset == NULL || rrsigs == NULL
	    || knot_dname_compare_non_canon(rrset->owner, rrsigs->owner) != 0) {
		return KNOT_EINVAL;
	}

	int rc;
	if (rrset->rrsigs != NULL) {
		if (dupl == KNOT_RRSET_DUPL_MERGE) {
			int merged, deleted_rrs;
			rc = knot_rrset_merge_no_dupl(rrset->rrsigs, rrsigs,
			                              &merged, &deleted_rrs);
			if (rc != KNOT_EOK) {
				return rc;
			} else if (merged || deleted_rrs) {
				return 1;
			} else {
				return 0;
			}
		} else if (dupl == KNOT_RRSET_DUPL_SKIP) {
			return 2;
		} else if (dupl == KNOT_RRSET_DUPL_REPLACE) {
			rrset->rrsigs = rrsigs;
		}
	} else {
		if (rrset->ttl != rrsigs->ttl) {
			rrsigs->ttl = rrset->ttl;
		}
		rrset->rrsigs = rrsigs;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rrset_owner(const knot_rrset_t *rrset)
{
	return rrset->owner;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_rrset_get_owner(const knot_rrset_t *rrset)
{
	return rrset->owner;
}

/*----------------------------------------------------------------------------*/

void knot_rrset_set_owner(knot_rrset_t *rrset, knot_dname_t *owner)
{
	if (rrset) {
		/* Retain new owner and release old owner. */
		knot_dname_retain(owner);
		knot_dname_release(rrset->owner);
		rrset->owner = owner;
	}
}

/*----------------------------------------------------------------------------*/

void knot_rrset_set_ttl(knot_rrset_t *rrset, uint32_t ttl)
{
	if (rrset) {
		rrset->ttl = ttl;
	}
}

/*----------------------------------------------------------------------------*/

uint16_t knot_rrset_type(const knot_rrset_t *rrset)
{
	return rrset->type;
}

/*----------------------------------------------------------------------------*/

uint16_t knot_rrset_class(const knot_rrset_t *rrset)
{
	return rrset->rclass;
}

/*----------------------------------------------------------------------------*/

uint32_t knot_rrset_ttl(const knot_rrset_t *rrset)
{
	return rrset->ttl;
}

/*----------------------------------------------------------------------------*/

uint8_t *knot_rrset_get_rdata(const knot_rrset_t *rrset, size_t rdata_pos)
{
	return rrset_rdata_pointer(rrset, rdata_pos);
}

/*----------------------------------------------------------------------------*/

uint16_t knot_rrset_rdata_rr_count(const knot_rrset_t *rrset)
{
	if (rrset != NULL) {
		return rrset->rdata_count;
	} else {
		return 0;
	}
}

/*----------------------------------------------------------------------------*/

const knot_rrset_t *knot_rrset_rrsigs(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_rrset_get_rrsigs(knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

int knot_rrset_rdata_equal(const knot_rrset_t *r1, const knot_rrset_t *r2)
{
	if (r1 == NULL || r2 == NULL || (r1->type != r2->type) ||
	    r1->rdata_count == 0 || r2->rdata_count == 0) {
		return KNOT_EINVAL;
	}

	// compare RDATA sets (order is not significant)

	// find all RDATA from r1 in r2
	int found = 0;
	for (uint16_t i = 0; i < r1->rdata_count; i++) {
		found = 0;
		for (uint16_t j = 0; j < r2->rdata_count && !found; j++) {
			found = !rrset_rdata_compare_one(r1, r2, i, j);
		}
	}

	if (!found) {
		return 0;
	}

	// other way around
	for (uint16_t i = 0; i < r2->rdata_count; i++) {
		found = 0;
		for (uint16_t j = 0; j < r1->rdata_count && !found; j++) {
			found = !rrset_rdata_compare_one(r1, r2, j, i);
		}
	}

	if (!found) {
		return 0;
	}

	return 1;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, size_t *size,
                       size_t max_size, uint16_t *rr_count, void *data)
{
	if (rrset == NULL || wire == NULL || size == NULL || rr_count == NULL) {
		return KNOT_EINVAL;
	}

	compression_param_t *comp_data = (compression_param_t *)data;
	uint8_t *pos = wire;

dbg_rrset_exec_detail(
	dbg_rrset_detail("Converting following RRSet:\n");
	knot_rrset_dump(rrset);
);

	int ret = knot_rrset_to_wire_aux(rrset, &pos, max_size, comp_data);
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

/*----------------------------------------------------------------------------*/

int knot_rrset_rdata_from_wire_one(knot_rrset_t *rrset,
                                   const uint8_t *wire, size_t *pos,
                                   size_t total_size, size_t rdlength)
{
	int obsolete = 0;

	/* [code-review] Missing parameter checks. */

	if (rdlength == 0) {
		/* Nothing to parse, */
		return KNOT_EOK;
	}

	dbg_rrset_detail("rr: parse_rdata_wire: Parsing RDATA of size=%zu,"
	                 " wire_size=%zu, type=%d.\n", rdlength, total_size,
	                 rrset->type);

	size_t extra_dname_size = 0;
	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);

	/* Check for obsolete record. */
	if (desc->type_name == NULL) {
		desc = get_obsolete_rdata_descriptor(rrset->type);
		if (desc->type_name != NULL) {
			obsolete = 1;
		}
	}

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; ++i) {
		if (descriptor_item_is_dname(desc->block_types[i])) {
			if (obsolete) {
				extra_dname_size += KNOT_MAX_DNAME_LENGTH;
			} else {
				extra_dname_size += sizeof(knot_dname_t *);
			}
		}
	}

	uint8_t rdata_buffer[rdlength + extra_dname_size];
	memset(rdata_buffer, 0, rdlength + extra_dname_size);
	dbg_rrset_detail("rr: parse_rdata_wire: Added %zu bytes to buffer to "
	                 "store RDATA DNAME pointers.\n", extra_dname_size);

	size_t offset = 0; // offset within in-memory RDATA
	size_t parsed = 0; // actual count of parsed octets
	const size_t packet_offset = *pos;

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END &&
	     parsed < rdlength; ++i) {
		size_t pos2 = 0; //used for DNAME parsing
		const int item = desc->block_types[i];
		if (descriptor_item_is_dname(item)) {
			pos2 = *pos;
			knot_dname_t *dname = knot_dname_parse_from_wire(
					wire, &pos2, total_size, NULL, NULL);
			if (dname == NULL) {
				return KNOT_EMALF;
			}
			knot_dname_to_lower(dname);

			dbg_rrset_detail("rr: parse_rdata_wire: Parsed DNAME, "
			                 "length=%zu.\n", pos2 - *pos);
dbg_rrset_exec_detail(
			char *name = knot_dname_to_str(dname);
			dbg_rrset_detail("rr: parse_rdata_wire: Parsed "
			                 "DNAME=%s\n", name);
			free(name);
);
			if (obsolete) {
				memcpy(rdata_buffer + offset,
				       knot_dname_name(dname),
				       knot_dname_size(dname));
				offset += knot_dname_size(dname);
				knot_dname_free(&dname);
			} else {
				memcpy(rdata_buffer + offset, &dname,
				       sizeof(knot_dname_t *));
				offset += sizeof(knot_dname_t *);
			}
			parsed += pos2 - *pos;
			*pos = pos2;
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

	uint8_t *rdata = knot_rrset_create_rdata(rrset, offset);
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

	int res = knot_dname_compare_non_canon(r1->owner, r2->owner);
	if (res != 0) {
		return 0;
	}

	if (r1->rclass == r2->rclass &&
	    r1->type == r2->type) {
		res = 1;
	} else {
		res = 0;
	}

	if (cmp == KNOT_RRSET_COMPARE_WHOLE && res == 1) {
		res = knot_rrset_rdata_equal(r1, r2);
	}

	return res;
}

int knot_rrset_deep_copy(const knot_rrset_t *from, knot_rrset_t **to,
                         int copy_rdata_dnames)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	dbg_rrset_detail("rr: deep_copy: Copying RRs of type %d\n",
	                 from->type);

	*to = xmalloc(sizeof(knot_rrset_t));

	(*to)->owner = knot_dname_deep_copy(from->owner);
	if ((*to)->owner == NULL) {
		free(*to);
		*to = NULL;
		return KNOT_ENOMEM;
	}

	(*to)->rclass = from->rclass;
	(*to)->ttl = from->ttl;
	(*to)->type = from->type;
	(*to)->rdata_count = from->rdata_count;
	if (from->rrsigs != NULL) {
		int ret = knot_rrset_deep_copy(from->rrsigs, &(*to)->rrsigs,
		                           copy_rdata_dnames);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(to, 1, 0);
			return ret;
		}
	} else {
		(*to)->rrsigs = NULL;
	}

	/* Just copy arrays - actual data + indices. */
	(*to)->rdata = xmalloc(rrset_rdata_size_total(from));
	memcpy((*to)->rdata, from->rdata, rrset_rdata_size_total(from));

	(*to)->rdata_indices = xmalloc(sizeof(uint32_t) * from->rdata_count);
	memcpy((*to)->rdata_indices, from->rdata_indices,
	       sizeof(uint32_t) * from->rdata_count);
	/* Here comes the hard part. */
	if (copy_rdata_dnames) {
		knot_dname_t **dname_from = NULL;
		knot_dname_t **dname_to = NULL;
		knot_dname_t *dname_copy = NULL;
		while ((dname_from = knot_rrset_get_next_dname(from, dname_from))) {
dbg_rrset_exec_detail(
			char *name = knot_dname_to_str(*dname_from);
			dbg_rrset_detail("rrset: deep_copy: copying RDATA DNAME"
			                 "=%s\n", name);
			free(name);
);
			size_t off = (uint8_t*)dname_from - from->rdata;
			dname_to = (knot_dname_t **)((*to)->rdata + off);
			/* These pointers have to be the same. */
			assert(*dname_from == *dname_to);
			dname_copy = knot_dname_deep_copy(*dname_from);
			if (dname_copy == NULL) {
				dbg_rrset("rrset: deep_copy: Cannot copy RDATA"
				          " dname.\n");
				/*! \todo This will leak. Is it worth fixing? */
				/* [code-review] Why will it leak? */
				knot_rrset_deep_free(&(*to)->rrsigs, 1,
				                     copy_rdata_dnames);
				free((*to)->rdata);
				free((*to)->rdata_indices);
				free(*to);
				return KNOT_ENOMEM;
			}

			*dname_to = dname_copy;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_shallow_copy(const knot_rrset_t *from, knot_rrset_t **to)
{
	*to = (knot_rrset_t *)malloc(sizeof(knot_rrset_t));
	CHECK_ALLOC_LOG(*to, KNOT_ENOMEM);

	memcpy(*to, from, sizeof(knot_rrset_t));

	/* Retain owner. */
	knot_dname_retain((*to)->owner);

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

	/*! \todo Shouldn't we always release owner reference? */
	knot_dname_release((*rrset)->owner);

	free(*rrset);
	*rrset = NULL;
}

void knot_rrset_deep_free(knot_rrset_t **rrset, int free_owner,
                          int free_rdata_dnames)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	if ((*rrset)->rrsigs != NULL) {
		knot_rrset_deep_free(&(*rrset)->rrsigs, free_owner, free_rdata_dnames);
	}

	if (free_rdata_dnames) {
		rrset_dnames_apply(*rrset, rrset_release_dnames_in_rr,
	                           NULL);
	}

	free((*rrset)->rdata);
	free((*rrset)->rdata_indices);

	if (free_owner) {
		knot_dname_release((*rrset)->owner);
	}

	free(*rrset);
	*rrset = NULL;
}

void knot_rrset_deep_free_no_sig(knot_rrset_t **rrset, int free_owner,
                                 int free_rdata_dnames)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}

	if (free_rdata_dnames) {
		int ret = rrset_dnames_apply(*rrset, rrset_release_dnames_in_rr,
		                             NULL);
		if (ret != KNOT_EOK) {
			dbg_rrset("rr: deep_free: Could not free DNAMEs in RDATA.\n");
		}
	}

	free((*rrset)->rdata);
	free((*rrset)->rdata_indices);

	if (free_owner) {
		knot_dname_release((*rrset)->owner);
	}

	free(*rrset);
	*rrset = NULL;
}

int knot_rrset_merge(knot_rrset_t *rrset1, const knot_rrset_t *rrset2)
{
	if (rrset1 == NULL || rrset2 == NULL) {
		return KNOT_EINVAL;
	}

	/* Check, that we really merge RRSets? */
	if (rrset1->type != rrset2->type ||
	    rrset1->rclass != rrset2->rclass ||
	    (knot_dname_compare_non_canon(rrset1->owner, rrset2->owner) != 0)) {
		return KNOT_EINVAL;
	}

	/* Merging empty RRSets is OK. */
	if (rrset1->rdata_count == 0 && rrset2->rdata_count == 0) {
		return KNOT_EOK;
	}

	/* Add all RDATAs from rrset2 to rrset1 (i.e. concatenate two arrays) */

	/*! \note The following code should work for
	 *        all the cases i.e. R1 or R2 are empty.
	 */

	/* Reallocate actual RDATA array. */
	rrset1->rdata = xrealloc(rrset1->rdata, rrset_rdata_size_total(rrset1) +
	                         rrset_rdata_size_total(rrset2));

	/* The space is ready, copy the actual data. */
	memcpy(rrset1->rdata + rrset_rdata_size_total(rrset1),
	       rrset2->rdata, rrset_rdata_size_total(rrset2));

	/* Indices have to be readjusted. But space has to be made first. */
	rrset1->rdata_indices =
		xrealloc(rrset1->rdata_indices,
	        (rrset1->rdata_count + rrset2->rdata_count) *
	         sizeof(uint32_t));

	uint32_t rrset1_total_size = rrset_rdata_size_total(rrset1);
	uint32_t rrset2_total_size = rrset_rdata_size_total(rrset2);

	/*
	 * Move the indices. Discard the last item in the first array, as it
	 * contains total length of the data, which is now different.
	 */
	memcpy(rrset1->rdata_indices + rrset1->rdata_count,
	       rrset2->rdata_indices, rrset2->rdata_count);

	/* Go through the second part of index array and adjust offsets. */
	for (uint16_t i = 0; i < rrset2->rdata_count - 1; i++) {
		rrset1->rdata_indices[rrset1->rdata_count + i] +=
			rrset1_total_size;
	}

	rrset1->rdata_indices[rrset1->rdata_count + rrset2->rdata_count - 1] =
		rrset1_total_size + rrset2_total_size;

	rrset1->rdata_count += rrset2->rdata_count;

	return KNOT_EOK;
}

int knot_rrset_merge_no_dupl(knot_rrset_t *rrset1, const knot_rrset_t *rrset2,
                             int *merged, int *deleted_rrs)
{
	if (rrset1 == NULL || rrset2 == NULL) {
		dbg_rrset("rrset: merge_no_dupl: NULL arguments.");
		return KNOT_EINVAL;
	}

dbg_rrset_exec_detail(
	char *name = knot_dname_to_str(rrset1->owner);
	dbg_rrset_detail("rrset: merge_no_dupl: Merging %s.\n", name);
	free(name);
);

	if ((knot_dname_compare_non_canon(rrset1->owner, rrset2->owner) != 0)
	    || rrset1->rclass != rrset2->rclass
	    || rrset1->type != rrset2->type) {
		dbg_rrset("rrset: merge_no_dupl: Trying to merge "
		          "different RRs.\n");
		return KNOT_EINVAL;
	}

	*deleted_rrs = 0;
	*merged = 0;
	/* For each item in second RRSet, make sure it is not duplicated. */
	for (uint16_t i = 0; i < rrset2->rdata_count; i++) {
		int duplicated = 0;
		/* Compare with all RRs in the first RRSet. */
		for (uint16_t j = 0; j < rrset1->rdata_count && !duplicated;
		     j++) {
			duplicated = !rrset_rdata_compare_one(rrset1, rrset2,
			                                      j, i);
		}

		if (!duplicated) {
			*merged += 1; // = need to shallow free rrset2
			// This index goes to merged RRSet.
			int ret = knot_rrset_add_rdata(rrset1,
			                               rrset_rdata_pointer(rrset2, i),
			                               rrset_rdata_item_size(rrset2, i));
			if (ret != KNOT_EOK) {
				dbg_rrset("rrset: merge_no_dupl: Could not "
				          "add RDATA to RRSet. (%s)\n",
				          knot_strerror(ret));
				return ret;
			}
		} else {
			*deleted_rrs += 1; // = need to shallow free rrset2
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

bool knot_rrset_is_nsec3rel(const knot_rrset_t *rr)
{
	assert(rr != NULL);

	/* Is NSEC3 or non-empty RRSIG covering NSEC3. */
	return ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
	        || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
	            && knot_rrset_rdata_rrsig_type_covered(rr)
	            == KNOT_RRTYPE_NSEC3));
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rrset_rdata_cname_name(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	knot_dname_t *dname;
	memcpy(&dname, rrset->rdata, sizeof(knot_dname_t *));
	return dname;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rrset_rdata_dname_target(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}
	knot_dname_t *dname;
	memcpy(&dname, rrset->rdata, sizeof(knot_dname_t *));
	return dname;
}

/*---------------------------------------------------------------------------*/

const knot_dname_t *knot_rrset_rdata_soa_primary_ns(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}
	knot_dname_t *dname;
	memcpy(&dname, rrset->rdata, sizeof(knot_dname_t *));
	return dname;
}

const knot_dname_t *knot_rrset_rdata_soa_mailbox(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}
	knot_dname_t *dname;
	memcpy(&dname, rrset->rdata + sizeof(knot_dname_t *),
	       sizeof(knot_dname_t *));
	return dname;
}

const knot_dname_t *knot_rrset_rdata_rp_first_dname(const knot_rrset_t *rrset,
                                                    size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return NULL;
	}

	knot_dname_t *dname;
	memcpy(&dname, knot_rrset_get_rdata(rrset, pos), sizeof(knot_dname_t *));
	return dname;
}

const knot_dname_t *knot_rrset_rdata_rp_second_dname(const knot_rrset_t *rrset,
                                                     size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return NULL;
	}

	knot_dname_t *dname;
	memcpy(&dname, knot_rrset_get_rdata(rrset, pos) + sizeof(knot_dname_t *),
	       sizeof(knot_dname_t *));
	return dname;
}

const knot_dname_t *knot_rrset_rdata_minfo_first_dname(const knot_rrset_t *rrset,
                                                       size_t pos)
{
	return knot_rrset_rdata_rp_first_dname(rrset, pos);
}

const knot_dname_t *knot_rrset_rdata_minfo_second_dname(const knot_rrset_t *rrset,
                                                        size_t pos)
{
	return knot_rrset_rdata_rp_second_dname(rrset, pos);
}

uint32_t knot_rrset_rdata_soa_serial(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata + sizeof(knot_dname_t *) * 2);
}

/*---------------------------------------------------------------------------*/

void knot_rrset_rdata_soa_serial_set(knot_rrset_t *rrset, uint32_t serial)
{
	if (rrset == NULL) {
		return;
	}

	// the number is in network byte order, transform it
	knot_wire_write_u32(rrset->rdata + sizeof(knot_dname_t *) * 2,
	                    serial);
}

/*---------------------------------------------------------------------------*/

uint32_t knot_rrset_rdata_soa_refresh(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata +
	                          sizeof(knot_dname_t *) * 2 + 4);
}

/*---------------------------------------------------------------------------*/


uint32_t knot_rrset_rdata_soa_retry(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata +
	                          sizeof(knot_dname_t *) * 2 + 8);
}

/*---------------------------------------------------------------------------*/

uint32_t knot_rrset_rdata_soa_expire(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata +
	                          sizeof(knot_dname_t *) * 2 + 12);
}

/*---------------------------------------------------------------------------*/

uint32_t knot_rrset_rdata_soa_minimum(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u32(rrset->rdata +
	                          sizeof(knot_dname_t *) * 2 + 16);
}

/*---------------------------------------------------------------------------*/

uint16_t knot_rrset_rdata_rrsig_type_covered(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u16(rrset->rdata);
}

uint8_t knot_rrset_rdata_rrsig_algorithm(const knot_rrset_t *rrset,
                                         size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, rr_pos) + 2);
}

uint8_t knot_rrset_rdata_rrsig_labels(const knot_rrset_t *rrset,
                                      size_t rr_pos)

{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, rr_pos) + 3);
}

uint32_t knot_rrset_rdata_rrsig_original_ttl(const knot_rrset_t *rrset,
                                             size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u32(knot_rrset_get_rdata(rrset, rr_pos) + 4);
}

uint32_t knot_rrset_rdata_rrsig_sig_expiration(const knot_rrset_t *rrset,
                                               size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u32(knot_rrset_get_rdata(rrset, rr_pos) + 8);
}

uint32_t knot_rrset_rdata_rrsig_sig_inception(const knot_rrset_t *rrset,
                                              size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u32(knot_rrset_get_rdata(rrset, rr_pos) + 12);
}

uint16_t knot_rrset_rdata_rrsig_key_tag(const knot_rrset_t *rrset,
                                        size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u16(knot_rrset_get_rdata(rrset, rr_pos) + 16);
}

const knot_dname_t *knot_rrset_rdata_rrsig_signer_name(const knot_rrset_t *rrset,
                                                       size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return NULL;
	}

	const knot_dname_t *dname = NULL;
	memcpy(&dname, knot_rrset_get_rdata(rrset, rr_pos) + 18,
	       sizeof(knot_dname_t *));

	return dname;
}

uint16_t knot_rrset_rdata_dnskey_flags(const knot_rrset_t *rrset, size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u16(knot_rrset_get_rdata(rrset, rr_pos));
}

uint8_t knot_rrset_rdata_dnskey_proto(const knot_rrset_t *rrset, size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, rr_pos) + 2);
}

uint8_t knot_rrset_rdata_dnskey_alg(const knot_rrset_t *rrset, size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return 0;
	}

	return *(knot_rrset_get_rdata(rrset, rr_pos) + 3);
}

void knot_rrset_rdata_dnskey_key(const knot_rrset_t *rrset, size_t rr_pos,
                                 uint8_t **key, uint16_t *key_size)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return;
	}

	*key = knot_rrset_get_rdata(rrset, rr_pos) + 4;
	*key_size = rrset_rdata_item_size(rrset, rr_pos) - 4;
}

const knot_dname_t *knot_rrset_rdata_nsec_next(const knot_rrset_t *rrset,
                                               size_t rr_pos)
{
	if (rrset == NULL) {
		return NULL;
	}

	const knot_dname_t *dname;
	memcpy(&dname, rrset_rdata_pointer(rrset, rr_pos),
	       sizeof(knot_dname_t *));
	return dname;
}

void knot_rrset_rdata_nsec_bitmap(const knot_rrset_t *rrset, size_t rr_pos,
                                  uint8_t **bitmap, uint16_t *size)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return;
	}

	*bitmap = knot_rrset_get_rdata(rrset, rr_pos) + sizeof(knot_dname_t *);
	*size = rrset_rdata_item_size(rrset, rr_pos) - sizeof(knot_dname_t *);
}

void knot_rrset_rdata_nsec3_bitmap(const knot_rrset_t *rrset, size_t rr_pos,
                                   uint8_t **bitmap, uint16_t *size)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return;
	}

	/* Bitmap is last, skip all the items. */
	size_t offset = 1; //hash alg.
	offset += 1; //flags
	offset += 2; //iterations
	offset += 1; //salt lenght
	offset += knot_rrset_rdata_nsec3_salt_length(rrset, rr_pos); //sal
	uint8_t *next_hashed = NULL;
	uint8_t next_hashed_size = 0;
	knot_rrset_rdata_nsec3_next_hashed(rrset, rr_pos, &next_hashed,
	                                   &next_hashed_size);
	offset += 1; //hash length
	offset += next_hashed_size; //hash
	*bitmap = knot_rrset_get_rdata(rrset, rr_pos) + offset;
	*size = rrset_rdata_item_size(rrset, rr_pos) - offset;
}

/*---------------------------------------------------------------------------*/

uint8_t knot_rrset_rdata_nsec3_algorithm(const knot_rrset_t *rrset,
                                         size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos));
}

uint8_t knot_rrset_rdata_nsec3_flags(const knot_rrset_t *rrset,
                                     size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos) + 1);
}

/*---------------------------------------------------------------------------*/

uint16_t knot_rrset_rdata_nsec3_iterations(const knot_rrset_t *rrset,
                                           size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return knot_wire_read_u16(rrset_rdata_pointer(rrset, pos) + 2);
}

/*---------------------------------------------------------------------------*/

uint8_t knot_rrset_rdata_nsec3param_flags(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, 0) + 1);
}

/*---------------------------------------------------------------------------*/

uint8_t knot_rrset_rdata_nsec3param_algorithm(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, 0));
}

/*---------------------------------------------------------------------------*/

uint16_t knot_rrset_rdata_nsec3param_iterations(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return knot_wire_read_u16(rrset_rdata_pointer(rrset, 0) + 2);
}

/*---------------------------------------------------------------------------*/

uint8_t knot_rrset_rdata_nsec3param_salt_length(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, 0) + 4);
}

/*---------------------------------------------------------------------------*/

const uint8_t *knot_rrset_rdata_nsec3param_salt(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, 0) + 5;
}

/*---------------------------------------------------------------------------*/


uint8_t knot_rrset_rdata_nsec3_salt_length(const knot_rrset_t *rrset,
                                           size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}

	return *(rrset_rdata_pointer(rrset, pos) + 4);
}

void knot_rrset_rdata_nsec3_next_hashed(const knot_rrset_t *rrset, size_t pos,
                                        uint8_t **name, uint8_t *name_size)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return;
	}

	uint8_t salt_size = knot_rrset_rdata_nsec3_salt_length(rrset, pos);
	*name_size = *(knot_rrset_get_rdata(rrset, pos) + 4 + salt_size + 1);
	*name = knot_rrset_get_rdata(rrset, pos) + 4 + salt_size + 2;
}

/*---------------------------------------------------------------------------*/

const uint8_t *knot_rrset_rdata_nsec3_salt(const knot_rrset_t *rrset,
                                           size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return NULL;
	}

	return rrset_rdata_pointer(rrset, pos) + 5;
}

knot_dname_t **knot_rrset_get_next_rr_dname(const knot_rrset_t *rrset,
                                            knot_dname_t **prev_dname,
                                            size_t rr_pos)
{
	if (rrset == NULL || rr_pos >= rrset->rdata_count) {
		return NULL;
	}

	uint8_t *rdata = rrset_rdata_pointer(rrset, rr_pos);
	if (rrset_type_multiple_dnames(rrset)) {
		if (prev_dname == NULL) {
			/* The very first DNAME. */
			/* [code-review] How do you know the dname is the first
			 * item in the RDATA?
			 */
			return (knot_dname_t **)rdata;
		}
		assert((size_t)prev_dname >= (size_t)rdata);
		if ((size_t)prev_dname - (size_t)rdata == sizeof(knot_dname_t *)) {
			/* No DNAMEs left to return. */
			return NULL;
		} else {
			/* Return second DNAME from RR. */
			assert((size_t)prev_dname == (size_t)rdata);
			return (knot_dname_t **)(rdata + sizeof(knot_dname_t *));
		}
	} else {
		/*
		 * Return DNAME from normal RR, if any.
		 * Find DNAME in blocks. No need to check remainder.
		 */
		if (prev_dname) {
			/* Nothing left to return. */
			return NULL;
		}
		size_t offset = 0;
		const rdata_descriptor_t *desc =
			get_rdata_descriptor(rrset->type);
		for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; ++i) {
			if (descriptor_item_is_dname(desc->block_types[i])) {
				return (knot_dname_t **)(rdata + offset);
			} else if (descriptor_item_is_fixed(desc->block_types[i])) {
				offset += desc->block_types[i];
			} else if (!descriptor_item_is_remainder(desc->block_types[i])) {
				assert(rrset->type == KNOT_RRTYPE_NAPTR);
				offset +=
					rrset_rdata_naptr_bin_chunk_size(rrset,
				                                         rr_pos);
			}
		}
	}

	return NULL;
}

knot_dname_t **knot_rrset_get_next_dname(const knot_rrset_t *rrset,
                                         knot_dname_t **prev_dname)
{
	if (rrset == NULL || rrset->rdata_count == 0) {
		return NULL;
	}

	/* 1) Find in which RR is the given dname. */
	size_t pos = 0;
	int ret = rrset_find_rr_pos_for_pointer(rrset, prev_dname, &pos);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	/* 2) Try to get next dname from the RR. */
	knot_dname_t **next =
		knot_rrset_get_next_rr_dname(rrset, prev_dname, pos);

	/* 3) If not found and there is a next RR to search in, try it. */
	if (next == NULL && pos < rrset->rdata_count - 1) {
		// prev_dname = NULL because in this RR we haven't searched yet
		next = knot_rrset_get_next_rr_dname(rrset, NULL, pos + 1);
	}

	return next;
}

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

	dbg_rrset_detail("  RRSIGs:\n");
	if (rrset->rrsigs != NULL) {
	        knot_rrset_dump(rrset->rrsigs);
	} else {
	        dbg_rrset_detail("  none\n");
	}

	dbg_rrset_detail("RDATA indices (total=%d):\n",
	        rrset_rdata_size_total(rrset));

	for (uint16_t i = 0; i < rrset->rdata_count; i++) {
		dbg_rrset_detail("%d=%d ", i, rrset_rdata_offset(rrset, i));
	}
	dbg_rrset_detail("\n");

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
	              1 + // owner size
	              knot_dname_size(knot_rrset_owner(rrset)) + // owner data
	              sizeof(uint16_t) + // type
	              sizeof(uint16_t) + // class
	              sizeof(uint32_t) + // ttl
	              sizeof(uint16_t) +  //RR count
	              sizeof(uint32_t) * rrset->rdata_count; //RR indices
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
	/* Save owner. Size first. */
	memcpy(stream + offset, &rrset->owner->size, 1);
	++offset;
	memcpy(stream + offset, knot_dname_name(rrset->owner),
	       knot_dname_size(rrset->owner));
	offset += knot_dname_size(rrset->owner);

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
	uint8_t owner_size = *(stream + offset);
	offset += 1;
	knot_dname_t *owner = knot_dname_new_from_wire(stream + offset,
	                                               owner_size, NULL);
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
	*rrset = knot_rrset_new(owner, type, rclass, ttl);
	if (*rrset == NULL) {
		return KNOT_ENOMEM;
	}
	knot_dname_release(owner);

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
			knot_dname_release(owner);
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

const knot_dname_t *knot_rrset_rdata_ns_name(const knot_rrset_t *rrset,
                                             size_t rdata_pos)
{
	if (rrset == NULL) {
		return NULL;
	}

	const knot_dname_t *dname;
	memcpy(&dname, rrset_rdata_pointer(rrset, rdata_pos),
	       sizeof(knot_dname_t *));
	return dname;
}

const knot_dname_t *knot_rrset_rdata_mx_name(const knot_rrset_t *rrset,
                                             size_t rdata_pos)
{
	if (rrset == NULL) {
		return NULL;
	}

	knot_dname_t *dname;
	memcpy(&dname, rrset_rdata_pointer(rrset, rdata_pos) + 2,
	       sizeof(knot_dname_t *));
	return dname;
}

const knot_dname_t *knot_rrset_rdata_srv_name(const knot_rrset_t *rrset,
                                              size_t rdata_pos)
{
	if (rrset == NULL) {
		return NULL;
	}

	knot_dname_t *dname;
	memcpy(&dname, rrset_rdata_pointer(rrset, rdata_pos) + 6,
	       sizeof(knot_dname_t *));
	return dname;
}

const knot_dname_t *knot_rrset_rdata_name(const knot_rrset_t *rrset,
                                          size_t rdata_pos)
{
	if (rrset == NULL || rrset->rdata_count <= rdata_pos) {
		return NULL;
	}

	switch (rrset->type) {
		case KNOT_RRTYPE_NS:
			return knot_rrset_rdata_ns_name(rrset, rdata_pos);
		case KNOT_RRTYPE_MX:
			return knot_rrset_rdata_mx_name(rrset, rdata_pos);
		case KNOT_RRTYPE_SRV:
			return knot_rrset_rdata_srv_name(rrset, rdata_pos);
		case KNOT_RRTYPE_CNAME:
			return knot_rrset_rdata_cname_name(rrset);
	}

	return NULL;
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

int knot_rrset_remove_rr(knot_rrset_t *rrset,
                         const knot_rrset_t *rr_from, size_t rdata_pos)
{
	/* [code-review] Missing parameter checks. */
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

int knot_rrset_rdata_reset(knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return KNOT_EINVAL;
	}

	rrset->rdata = NULL;
	rrset->rdata_indices = NULL;
	rrset->rdata_count = 0;

	return KNOT_EOK;
}

int rrset_rr_dnames_apply(knot_rrset_t *rrset, size_t rdata_pos,
                          int (*func)(knot_dname_t **, void *), void *data)
{
	if (rrset == NULL || rdata_pos >= rrset->rdata_count || func == NULL) {
		return KNOT_EINVAL;
	}


	knot_dname_t **dname = NULL;
	while ((dname = knot_rrset_get_next_rr_dname(rrset, dname,
	                                             rdata_pos))) {
		assert(dname && *dname);
		int ret = func(dname, data);
		if (ret != KNOT_EOK) {
			dbg_rrset("rr: rr_dnames_apply: Function could not be"
			          "applied (%s).\n", knot_strerror(ret));
			return ret;
		}
	}

	return KNOT_EOK;
}

int rrset_dnames_apply(knot_rrset_t *rrset, int (*func)(knot_dname_t **, void *),
                       void *data)
{
	if (rrset == NULL || rrset->rdata_count == 0 || func == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < rrset->rdata_count; ++i) {
		int ret = rrset_rr_dnames_apply(rrset, i, func, data);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int knot_rrset_add_rr_from_rrset(knot_rrset_t *dest, const knot_rrset_t *source,
                                 size_t rdata_pos)
{
	if (dest == NULL || source == NULL ||
	    rdata_pos >= source->rdata_count) {
		return KNOT_EINVAL;
	}

	/* Get size of RDATA to be copied. */
	uint16_t item_size = rrset_rdata_item_size(source, rdata_pos);
	/* Reserve space in dest RRSet. */
	uint8_t *rdata = knot_rrset_create_rdata(dest, item_size);
	if (rdata == NULL) {
		dbg_rrset("rr: add_rr_from_rrset: Could not create RDATA.\n");
		return KNOT_ERROR;
	}

	/* Copy actual data. */
	memcpy(rdata, rrset_rdata_pointer(source, rdata_pos), item_size);

	/* Retain DNAMEs inside RDATA. */
	int ret = rrset_rr_dnames_apply((knot_rrset_t *)source, rdata_pos,
	                                rrset_retain_dnames_in_rr, NULL);
	if (ret != KNOT_EOK) {
		dbg_rrset("rr: add_rr_from_rrset: Could not retain DNAMEs"
		          " in RR (%s).\n", knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

int knot_rrset_remove_rr_using_rrset(knot_rrset_t *from,
                                     const knot_rrset_t *what,
                                     knot_rrset_t **rr_deleted, int ddns_check)
{
	/* [code-review] Missing parameter checks. */

	knot_rrset_t *return_rr = NULL;
	int ret = knot_rrset_shallow_copy(what, &return_rr);
	if (ret != KNOT_EOK) {
		dbg_rrset("remove_rr_using_rrset: Could not copy RRSet (%s).\n",
		          knot_strerror(ret));
		return ret;
	}
	/* Reset RDATA of returned RRSet. */
	knot_rrset_rdata_reset(return_rr);
	return_rr->rrsigs = NULL;

	for (uint16_t i = 0; i < what->rdata_count; ++i) {
		/*
		 * DDNS special handling - last apex NS should remain in the
		 * zone.
		 *
		 * TODO: this is not correct, the last NS from the 'what' RRSet
		 * may not even be in the zone.
		 */
		//TODO REVIEW LS : relevant?
		/* [code-review] Hm, it seems OK, but the variable should be
		 *               documented, maybe even named differently.
		 *               Setting it to 1 means: 'leave the last RR in
		 *               the RRSet'. Deciding whether to leave the last
		 *               there is on the caller. Thus the assert() is
		 *               wrong (it MAY be used in other cases).
		 *               Also there can be just break; instead of the
		 *               parameter setting and return.
		 */
		if (ddns_check && i == what->rdata_count - 1) {
			assert(knot_rrset_type(from) == KNOT_RRTYPE_NS);
			*rr_deleted = return_rr;
			return KNOT_EOK;
		}

		ret = knot_rrset_remove_rr(from, what, i);
		if (ret == KNOT_EOK) {
			/* RR was removed, can be added to 'return' RRSet. */
			ret = knot_rrset_add_rr_from_rrset(return_rr, what, i);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&return_rr, 0, 0);
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
			knot_rrset_deep_free(&return_rr, 0, 0);
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
	int ret = knot_rrset_remove_rr_using_rrset(from, what, &rr_removed, 0);
	knot_rrset_deep_free(&rr_removed, 1, 1);
	return ret;
//	for (uint16_t i = 0; i < what->rdata_count; ++i) {
//		int ret = knot_rrset_remove_rr(from, what, i);
//		if (ret != KNOT_ENOENT || ret != KNOT_EOK) {
//			/* NOENT is OK, but other errors are not. */
//			dbg_rrset("rrset: remove_rr_using_rrset: "
//			          "RRSet removal failed (%s).\n",
//			          knot_strerror(ret));
//			return ret;
//		}
//	}

//	return KNOT_EOK;
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
		uint8_t type = *(rrset_rdata_pointer(rrset, i) + 3);
		if (type == 0 || len == 0) {
			return KNOT_EINVAL;
		} else if (len != knot_ds_digest_length(type)) {
			return KNOT_EDSDIGESTLEN;
		}
	}
	return KNOT_EOK;
}
