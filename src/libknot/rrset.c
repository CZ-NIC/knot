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

#include "common.h"
#include "rrset.h"
#include "common/descriptor_new.h"
#include "util/debug.h"
#include "util/utils.h"

/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

size_t rrset_rdata_offset(const knot_rrset_t *rrset,
                          size_t pos)
{
	if (rrset == NULL || rrset->rdata_indices == NULL) {
		return 0;
	}
	
	if (pos == 0) {
		return 0;
	} else {
		return rrset->rdata_indices[pos - 1];
	}
}

size_t rrset_rdata_item_size(const knot_rrset_t *rrset,
                             size_t pos)
{
	if (rrset == NULL || rrset->rdata_indices || rrset->rdata_count == 0) {
		return 0;
	}
	
	return rrset_rdata_offset(rrset, pos) -
	                          rrset_rdata_offset(rrset, pos - 1);
}

static uint8_t *rrset_rdata_pointer(const knot_rrset_t *rrset,
                                    size_t pos)
{
	if (rrset == NULL || rrset->rdata == NULL
	    || rrset->rdata_count >= pos) {
		return NULL;
	}
	
	return rrset->rdata + rrset_rdata_offset(rrset, pos);
}

size_t rrset_rdata_naptr_bin_chunk_size(const knot_rrset_t *rrset,
                                        size_t pos)
{
	if (rrset == NULL || rrset->rdata_count >= pos) {
		return 0;
	}
	
	size_t size = 0;
	uint8_t *rdata = rrset_rdata_pointer(rrset, pos);
	assert(rdata);
	
	/* Two shorts at the beginning. */
	size += 4;
	/* 3 binary TXTs with length in the first byte. */
	for (int i = 0; i < 3; i++) {
		size += *(rdata + size);
	}
	
	/* 
	 * Dname remaning, but we usually want to get to the DNAME, so
	 * there's no need to include it in the returned size.
	 */
	
	return size;
}


static uint32_t rrset_rdata_size_total(const knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rdata_indices || rrset->rdata_count == 0) {
		return 0;
	}
	
	/* Last index denotes end of all RRs. */
	return (rrset->rdata_indices[rrset->rdata_count]);
}


/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_rrset_new(knot_dname_t *owner, uint16_t type,
                             uint16_t rclass, uint32_t ttl)
{
	knot_rrset_t *ret = malloc(sizeof(knot_rrset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	ret->rdata = NULL;

	/* Retain reference to owner. */
	knot_dname_retain(owner);

	ret->owner = owner;
	ret->type = type;
	ret->rclass = rclass;
	ret->ttl = ttl;
	ret->rrsigs = NULL;

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_add_rdata(knot_rrset_t *rrset,
                         uint8_t *rdata, uint32_t size)
{
	if (rrset == NULL || rdata == NULL) {
		return KNOT_EINVAL;
	}
	
	/* Realloc indices. We will allocate exact size to save space. */
	void *tmp = realloc(rrset->rdata_indices, rrset->rdata_count + 1);
	if (tmp == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	} else {
		rrset->rdata_indices = tmp;
	}
	
	if (rrset->rdata_count == 0) {
		rrset->rdata_indices[0] = size;
	} else {
		rrset->rdata_indices[rrset->rdata_count] =
			rrset->rdata_indices[rrset->rdata_count - 1] + size;
	}
	
	rrset->rdata_count++;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_remove_rdata(knot_rrset_t *rrset,
                            size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return KNOT_EINVAL;
	}

	/* Reorganize the array. */
	uint8_t *rdata_to_remove = rrset_rdata_pointer(rrset, pos);
	assert(rdata_to_remove);
	if (pos != rrset->rdata_count - 1) {
		/* Not the last item in array - we need to move the data. */
		uint8_t *next_rdata = rrset_rdata_pointer(rrset, pos + 1);
		assert(next_rdata);
		size_t next_rdata_size = rrset_rdata_item_size(rrset, pos + 1);
		/* Copy the next RR data to where this item is. */
		/* No need to worry about exceeding allocated space now. */
		memcpy(rdata_to_remove, next_rdata, next_rdata_size);
	}
	
	/*! \todo Realloc might not be needed. Only if the RRSet is large. */
	void *tmp = realloc(rrset->rdata,
	                    rrset_rdata_size_total(rrset) -
	                    rrset_rdata_item_size(rrset, pos));
	if (tmp == NULL) {
		/*
		 * I don't see how this can fail, but oh well. Should this
		 * happen, RDATA will not be in consistent state.
		 */
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	} else {
		rrset->rdata = tmp;
	}
	
	return KNOT_EOK;
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
	    || knot_dname_compare(rrset->owner, rrsigs->owner) != 0) {
		return KNOT_EINVAL;
	}

	int rc;
	if (rrset->rrsigs != NULL) {
		if (dupl == KNOT_RRSET_DUPL_MERGE) {
			rc = knot_rrset_merge_no_dupl((void **)&rrset->rrsigs,
			                              (void **)&rrsigs);
			if (rc != KNOT_EOK) {
				return rc;
			} else {
				return 1;
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

void knot_rrset_set_owner(knot_rrset_t *rrset, knot_dname_t* owner)
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

uint8_t *knot_rrset_get_rdata(knot_rrset_t *rrset, size_t rdata_pos)
{
	//V rdata-items
	if (rrset == NULL) {
		return NULL;
	} else {
		return rrset->rdata;
	}
}

/*----------------------------------------------------------------------------*/

int16_t knot_rrset_rdata_rr_count(const knot_rrset_t *rrset)
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
		assert(0);
		return NULL;
	} else {
		return rrset->rrsigs;
	}
}

static size_t rrset_rdata_remainder_size(const knot_rrset_t *rrset,
                                         size_t offset,
                                         size_t pos)
{
	if (pos == 0) {
		return rrset->rdata_indices[1] - offset;
	} else {
		return (rrset->rdata_indices[pos + 1] -
		        rrset->rdata_indices[pos]) - offset;
	}
}

/*----------------------------------------------------------------------------*/

static int rrset_rdata_compare_one(const knot_rrset_t *rrset1,
                                   const knot_rrset_t *rrset2,
                                   size_t pos1, size_t pos2, uint16_t type)
{
	uint8_t *r1 = rrset_rdata_pointer(rrset1, pos1);
	uint8_t *r2 = rrset_rdata_pointer(rrset2, pos2);
	assert(rrset1->type == rrset2->type);
	const rdata_descriptor_t *desc = get_rdata_descriptor(type);
	int cmp = 0;
	size_t offset = 0;

	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		if (descriptor_item_is_dname(desc->block_types[i])) {
			cmp = knot_dname_compare((knot_dname_t *)(r1 + offset),
			                         (knot_dname_t *)(r2 + offset));
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
			/* No need to move offset, this should be end anyway. */
			assert(desc->block_types[i + 1] == KNOT_RDATA_WF_END);
		} else {
			assert(rrset1->type == KNOT_RRTYPE_NAPTR);
			size_t naptr_chunk_size1 =
				rrset_rdata_naptr_bin_chunk_size(rrset1, pos1);
			size_t naptr_chunk_size2 =
				rrset_rdata_naptr_bin_chunk_size(rrset2, pos2);
			cmp = memcmp(r1, r2,
			             naptr_chunk_size1 <= naptr_chunk_size2 ?
			             naptr_chunk_size1 : naptr_chunk_size2);
			if (cmp != 0) {
				return cmp;
			}
		
			/* Binary part was equal, we have to compare DNAMEs. */
			assert(naptr_chunk_size1 == naptr_chunk_size2);
			offset += naptr_chunk_size1;
			cmp = knot_dname_compare((knot_dname_t *)(r1 + offset),
			                         (knot_dname_t *)(r2 + offset));
			offset += sizeof(knot_dname_t *);
		}

		if (cmp != 0) {
			return cmp;
		}
	}

	assert(cmp == 0);
	return 0;
}

int knot_rrset_compare_rdata(const knot_rrset_t *r1, const knot_rrset_t *r2)
{
	if (r1 == NULL || r2 == NULL) {
		return KNOT_EINVAL;
	}

	const rdata_descriptor_t *desc =
		get_rdata_descriptor(r1->type);
	if (desc == NULL) {
		return KNOT_EINVAL;
	}

	// compare RDATA sets (order is not significant)

	// find all RDATA from r1 in r2
	for (uint16_t i = 0; i < r1->rdata_count; i++) {
		int found = 0;
		for (uint16_t j = 0; j < r2->rdata_count; j++) {
			found =
				!rrset_rdata_compare_one(r1, r2, i, j,
			                                 r1->type);
			if (!found) {
				// RDATA from r1 not found in r2
				return 0;
			}
		}
	}
	
	for (uint16_t i = 0; i < r2->rdata_count; i++) {
		int found = 0;
		for (uint16_t j = 0; j < r1->rdata_count; j++) {
			found =
				!rrset_rdata_compare_one(r1, r2, i, j,
			                                 r1->type);
			if (!found) {
				// RDATA from r1 not found in r2
				return 0;
			}
		}
	}
	
	return 1;
}

/*----------------------------------------------------------------------------*/

static int knot_rrset_rdata_to_wire_one(const knot_rrset_t *rrset,
                                        size_t rdata_pos,
                                        size_t header_size,
                                        uint8_t **pos,
                                        uint16_t *rdlength,
                                        size_t max_size)
{
	assert(rrset);
	assert(pos);
	
	/* Get pointer into RDATA array. */
	uint8_t *rdata = rrset_rdata_pointer(rrset, rdata_pos);
	assert(rdata);
	/* Offset into one RDATA array. */
	size_t offset = 0;
	
	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);
	assert(desc);

	size_t size = header_size;
	
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		if (descriptor_item_is_dname(desc->block_types[i])) {
			knot_dname_t *dname = 
				(knot_dname_t *)(rdata + offset);
			assert(dname);
			if (size + *rdlength + dname->size > max_size) {
				return KNOT_ESPACE;
			}

			// save whole domain name
			memcpy(*pos, knot_dname_name(dname), 
			       knot_dname_size(dname));
			dbg_rrset_detail("Uncompressed dname size: %d\n",
			                 knot_dname_size(dname));
			*pos += knot_dname_size(dname);
			*rdlength += knot_dname_size(dname);
			offset += sizeof(knot_dname_t *);
		} else if (descriptor_item_is_fixed(desc->block_types[i])) {
			/* Fixed length chunk. */
			if (size + *rdlength + desc->block_types[i] > max_size) {
				return KNOT_ESPACE;
			}
			memcpy(*pos, rdata + offset,
			       desc->block_types[i]);
			*pos += desc->block_types[i];
			*rdlength += desc->block_types[i];
			offset += desc->block_types[i];
		} else if (descriptor_item_is_remainder(desc->block_types[i])) {
			/* Check that the remainder fits to stream. */
			size_t remainder_size =
				rrset_rdata_remainder_size(rrset, offset,
			                                   rdata_pos);
			if (size + *rdlength + remainder_size > max_size) {
				return KNOT_ESPACE;
			}
			memcpy(*pos, rdata + offset, remainder_size);
			*pos += remainder_size;
			*rdlength += remainder_size;
			offset += remainder_size;
		} else {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			/* Store the binary chunk. */
			size_t chunk_size =
			rrset_rdata_naptr_bin_chunk_size(rrset, rdata_pos);
			if (size + *rdlength + chunk_size > max_size) {
				return KNOT_ESPACE;
			}
			*pos += chunk_size;
			*rdlength += chunk_size;
			offset += chunk_size;
			/* Store domain name. */
			knot_dname_t *dname = 
				(knot_dname_t *)(rdata + offset);
			assert(dname);
			if (size + *rdlength + dname->size > max_size) {
				return KNOT_ESPACE;
			}

			// save whole domain name
			memcpy(*pos, knot_dname_name(dname), 
			       knot_dname_size(dname));
			dbg_rrset_detail("Uncompressed dname size: %d\n",
			                 knot_dname_size(dname));
			*pos += knot_dname_size(dname);
			*rdlength += knot_dname_size(dname);
			offset += sizeof(knot_dname_t *);
		}
	}
	
	return KNOT_EOK;
}

static int knot_rrset_to_wire_aux(const knot_rrset_t *rrset, 
                                  uint8_t **pos,
                                  size_t max_size)
{
	size_t size = 0;
	
	assert(rrset != NULL);
	assert(rrset->owner != NULL);
	assert(pos != NULL);
	assert(*pos != NULL);
	
	dbg_rrset_detail("Max size: %zu, owner: %p, owner size: %d\n",
	                 max_size, rrset->owner, rrset->owner->size);

	// check if owner fits
	if (size + knot_dname_size(rrset->owner) + 10 > max_size) {
		return KNOT_ESPACE;
	}
	
	memcpy(*pos, knot_dname_name(rrset->owner), 
	       knot_dname_size(rrset->owner));
	*pos += knot_dname_size(rrset->owner);
	size += knot_dname_size(rrset->owner);
	
	dbg_rrset_detail("Max size: %zu, size: %d\n", max_size, size);

	dbg_rrset_detail("Wire format:\n");

	// put rest of RR 'header'
	knot_wire_write_u16(*pos, rrset->type);
	dbg_rrset_detail("  Type: %u\n", rrset->type);
	*pos += 2;

	knot_wire_write_u16(*pos, rrset->rclass);
	dbg_rrset_detail("  Class: %u\n", rrset->rclass);
	*pos += 2;

	knot_wire_write_u32(*pos, rrset->ttl);
	dbg_rrset_detail("  TTL: %u\n", rrset->ttl);
	*pos += 4;

	// save space for RDLENGTH
	uint8_t *rdlength_pos = *pos;
	*pos += 2;

	size += 10;
	
	/* This should be checked in the calling function. TODO not an assert*/
//	assert(max_size >= size + *rdlength);
	
	dbg_rrset_detail("Max size: %zu, size: %d\n", max_size, size);

	const rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);
	assert(desc);
	uint16_t rdlength = 0;

	for (uint16_t i = 0; i < rrset->rdata_count; i++) {
		int ret = knot_rrset_rdata_to_wire_one(rrset, i, size,
		                                       pos, &rdlength,
		                                       max_size);
		if (ret != KNOT_EOK) {
			dbg_rrset("rrset: to_wire: Cannot convert RR. "
			          "Reason: %s.\n",
			          knot_strerror(ret));
			return ret;
		}
	}
	
	dbg_rrset_detail("Max size: %zu, size: %d\n", max_size, size);

	assert(size + rdlength <= max_size);
	size += rdlength;
	knot_wire_write_u16(rdlength_pos, rdlength);

	return size;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, size_t *size,
                       int *rr_count)
{
	// if no RDATA in RRSet, return
	if (rrset->rdata == NULL) {
		*size = 0;
		*rr_count = 0;
		return KNOT_EOK;
	}
	
	//TODO check with original code
	

	uint8_t *pos = wire;
	short rrset_size = 0;

	int ret = knot_rrset_to_wire_aux(rrset, &pos,
	                                       *size);
	
	assert(ret != 0);

	if (ret < 0) {
		// some RR didn't fit in, so no RRs should be used
		// TODO: remove last entries from compression table
		dbg_rrset_verb("Some RR didn't fit in.\n");
		return KNOT_ESPACE;
	}

	// the whole RRSet did fit in
	assert(rrset_size <= *size);
	assert(pos - wire == rrset_size);
	*size = ret;
	
	dbg_rrset_detail("Size after: %zu\n", *size);

	*rr_count = rrset->rdata_count;

	return KNOT_EOK;
}

static int knot_rrset_rdata_store_binary(uint8_t *rdata,
                                         size_t offset,
                                         const uint8_t *wire,
                                         size_t *pos,
                                         size_t rdlength,
                                         size_t size)
{
	assert(rdata);
	assert(wire);
	
	/* Check that size is OK. */
	if (*pos + size > rdlength) {
		dbg_rrset("rrset: rdata_store_binary: Exceeded RDLENGTH.\n");
		return KNOT_ESPACE;
	}
	
	/* Store actual data. */
	memcpy(rdata + offset, wire + *pos, size);
	
	/* Adjust pos acordlingly. */
	*pos += size;
	return KNOT_EOK;
}

/* This should never be called directly now i guess. */
int knot_rrset_rdata_from_wire_one(uint8_t **rdata, uint16_t type,
                                   const uint8_t *wire,
                                   size_t *pos, size_t total_size,
                                   size_t rdlength)
{
	int i = 0;
	size_t parsed = 0;

	if (rdlength == 0) {
		return KNOT_EOK;
	}
	
	// TODO is there a better way?
	uint8_t rdata_buffer[65536];
	size_t offset = 0;

	const rdata_descriptor_t *desc = get_rdata_descriptor(type);
	assert(desc);

	while (desc->block_types[i] != KNOT_RDATA_WF_END
	       && parsed < rdlength) {
		
		size_t pos2 = 0;
		
		if (descriptor_item_is_dname(desc->block_types[i])) {
			/* Since dnames can be compressed, */
			pos2 = *pos;
			knot_dname_t *dname =
				knot_dname_parse_from_wire(
					wire, &pos2, total_size, NULL);
			if (dname == NULL) {
				return KNOT_ERROR;
			}
			*((knot_dname_t **)rdata_buffer + offset) = dname;
			parsed += pos2 - *pos;
			*pos = pos2;
		} else if (descriptor_item_is_fixed(desc->block_types[i])) {
			int ret = knot_rrset_rdata_store_binary(rdata_buffer,
			                                        offset,
			                                        wire,
			                                        pos,
			                                        rdlength,
			                                        desc->block_types[i]);
			if (ret != KNOT_EOK) {
				dbg_rrset("rrset: rdata_from_wire: "
				          "Cannot store fixed RDATA chunk. "
				          "Reason: %s.\n", knot_strerror(ret));
				return ret;
			}
		} else if (descriptor_item_is_remainder(desc->block_types[i])) {
			/* Item size has to be calculated. */
			size_t remainder_size = rdlength - parsed;
			int ret = knot_rrset_rdata_store_binary(rdata_buffer,
			                                        offset,
			                                        wire,
			                                        pos,
			                                        rdlength,
			                                        remainder_size);
			if (ret != KNOT_EOK) {
				dbg_rrset("rrset: rdata_from_wire: "
				          "Cannot store RDATA remainder. "
				          "Reason: %s.\n", knot_strerror(ret));
				return ret;
			}
		} else {
			assert(type = KNOT_RRTYPE_NAPTR);
			/* Read fixed part - 2 shorts. */
			const size_t naptr_fixed_part_size = 4;
			int ret = knot_rrset_rdata_store_binary(rdata_buffer,
			                                        offset,
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
			offset += naptr_fixed_part_size;
			
			// TODO +1? Boundary checks!!!
			/* Read three binary TXTs. */
			for (int i = 0; i < 3; i++) {
				//maybe store the whole thing using store binary
				uint8_t txt_size = *(wire + (*pos + 1));
				offset += 1;
				int ret = knot_rrset_rdata_store_binary(rdata_buffer,
				                                        offset,
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
				offset += txt_size + 1;
			}
			
			/* Dname remaining. No need to note read size. */
			knot_dname_t *dname =
				knot_dname_parse_from_wire(
					wire, pos, total_size, NULL);
			if (dname == NULL) {
				return KNOT_ERROR;
			}
			*((knot_dname_t **)rdata_buffer + offset) = dname;
			offset += sizeof(knot_dname_t *);
		}
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_compare(const knot_rrset_t *r1,
                       const knot_rrset_t *r2,
                       knot_rrset_compare_type_t cmp)
{
	if (cmp == KNOT_RRSET_COMPARE_PTR) {
		return (r1 == r2);
	}

	int res = ((r1->rclass == r2->rclass)
	           && (r1->type == r2->type)
//	           && (r1->ttl == r2->ttl)
	           && knot_dname_compare(r1->owner, r2->owner) == 0);

	if (cmp == KNOT_RRSET_COMPARE_WHOLE && res) {
		res = knot_rrset_compare_rdata(r1, r2);
		if (res < 0) {
			return 0;
		}
	}

	return res;
}

/*----------------------------------------------------------------------------*/

int knot_rrset_deep_copy(const knot_rrset_t *from, knot_rrset_t **to,
                         int copy_rdata_dnames)
{
	if (from == NULL || to == NULL) {
		return KNOT_EINVAL;
	}

	int ret;

	*to = (knot_rrset_t *)calloc(1, sizeof(knot_rrset_t));
	CHECK_ALLOC_LOG(*to, KNOT_ENOMEM);

	(*to)->owner = from->owner;
	knot_dname_retain((*to)->owner);
	(*to)->rclass = from->rclass;
	(*to)->ttl = from->ttl;
	(*to)->type = from->type;
	if (from->rrsigs != NULL) {
		ret = knot_rrset_deep_copy(from->rrsigs, &(*to)->rrsigs,
		                           copy_rdata_dnames);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(to, 1, 0);
			return ret;
		}
	}
	assert((*to)->rrsigs == NULL || from->rrsigs != NULL);
	
	/* Just copy arrays - actual data + indices. */
	(*to)->rdata = malloc(rrset_rdata_size_total(from));
	if ((*to)->rdata == NULL) {
		ERR_ALLOC_FAILED;
		knot_rrset_deep_free(&(*to)->rrsigs, 1, copy_rdata_dnames);
		free(*to);
		return KNOT_ENOMEM;
	}
	memcpy((*to)->rdata, from->rdata, rrset_rdata_size_total(from));
	
	/* + 1 because last index holds length of all RDATA. */
	(*to)->rdata_indices = malloc(sizeof(uint32_t) * from->rdata_count + 1);
	if ((*to)->rdata == NULL) {
		ERR_ALLOC_FAILED;
		knot_rrset_deep_free(&(*to)->rrsigs, 1, copy_rdata_dnames);
		free((*to)->rdata);
		free(*to);
		return KNOT_ENOMEM;
	}
	memcpy((*to)->rdata_indices, from->rdata_indices,
	       rrset_rdata_size_total(from) + 1);
	
	/* Here comes the hard part. */
	if (copy_rdata_dnames) {
		knot_dname_t *dname_from = NULL;
		knot_dname_t **dname_to = NULL;
		knot_dname_t *dname_copy = NULL;
		while ((dname_from =
		        knot_rrset_get_next_dname(from, dname_from)) != NULL) {
			dname_to =
				knot_rrset_get_next_dname_pointer(*to,
					dname_to);
			/* These pointers have to be the same. */
			assert(dname_from == *dname_to);
			dname_copy = knot_dname_deep_copy(dname_from);
			if (dname_copy == NULL) {
				dbg_rrset("rrset: deep_copy: Cannot copy RDATA"
				          " dname.\n");
				/*! \todo This will leak. Is it worth fixing? */
				knot_rrset_deep_free(&(*to)->rrsigs, 1,
				                     copy_rdata_dnames);
				free((*to)->rdata);
				free((*to)->rdata_indices);
				free(*to);
				return KNOT_ENOMEM;
			}
			
			/* This cannot work, test. TODO */
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

/*----------------------------------------------------------------------------*/

void knot_rrset_rdata_deep_free_one(knot_rrset_t *rrset, size_t pos,
                                    int free_dnames)
{
	if (rrset == NULL || rrset->rdata == NULL ||
	    rrset->rdata_indices == NULL) {
		return;
	}
	
	size_t offset = 0;
	uint8_t *rdata = rrset_rdata_pointer(rrset, pos);
	if (rdata == NULL) {
		return;
	}
	
	if (free_dnames) {
		/* Go through the data and free dnames. Pointers can stay. */
		const rdata_descriptor_t *desc =
			get_rdata_descriptor(rrset->type);
		for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END;i++) {
			if (descriptor_item_is_dname(desc->block_types[i])) {
				knot_dname_t *dname =
					(knot_dname_t *)rdata + offset;
				knot_dname_release(dname);
				offset += sizeof(knot_dname_t *);
			} else if (descriptor_item_is_fixed(
			           desc->block_types[i])) {
				offset += desc->block_types[i];
			} else if (!descriptor_item_is_remainder(
			           desc->block_types[i])) {
				assert(rrset->type == KNOT_RRTYPE_NAPTR);
				/* Skip the binary beginning. */
				offset += rrset_rdata_naptr_bin_chunk_size(rrset,
				                                       pos);
				knot_dname_t *dname =
					(knot_dname_t *)rdata + offset;
				knot_dname_release(dname);
			}
		}
	}
	
	free(rrset->rdata);
	free(rrset->rdata_indices);
	rrset->rdata_count = 0;
	
	return;
}

void knot_rrset_deep_free(knot_rrset_t **rrset, int free_owner,
                          int free_rdata_dnames)
{
	if (rrset == NULL || *rrset == NULL) {
		return;
	}
	
	// rdata have to be freed no matter what
	for (uint16_t i = 0; i < (*rrset)->rdata_count; i++) {
		knot_rrset_rdata_deep_free_one(*rrset, i,
		                               free_rdata_dnames);
	}

	// RRSIGs should have the same owner as this RRSet, so do not delete it
	if ((*rrset)->rrsigs != NULL) {
		knot_rrset_deep_free(&(*rrset)->rrsigs, 0, free_rdata_dnames);
	}

	if (free_owner) {
		knot_dname_release((*rrset)->owner);
	}

	free(*rrset);
	*rrset = NULL;
}

/*----------------------------------------------------------------------------*/

// This might not be needed, we have to store the last index anyway
//	/*
//	 * The last one has to be traversed.
//	 */
//	rdata_descriptor_t *desc = get_rdata_descriptor(rrset->type);
//	assert(desc);
//	size_t size = 0;
//	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
//		int type = desc->block_types[i];
//		if (descriptor_item_is_dname(type)) {
//			size += sizeof(knot_dname_t *);
//		} else if (descriptor_item_is_fixed(type)) {
//			size += type;
//		} else if (descriptor_item_is_remainder(type)) {
//			// size has to be computed from index
//			size += 
//		} else {
//			//TODO naptr
//		}
//	}
//}


int knot_rrset_merge(void **r1, void **r2)
{
	knot_rrset_t *rrset1 = (knot_rrset_t *)(*r1);
	knot_rrset_t *rrset2 = (knot_rrset_t *)(*r2);
	if (rrset1 == NULL || rrset2 == NULL) {
		return KNOT_EINVAL;
	}
	
	/* Check, that we really merge RRSets? */
	if ((knot_dname_compare(rrset1->owner, rrset2->owner) != 0)
	    || rrset1->rclass != rrset2->rclass
	    || rrset1->type != rrset2->type) {
		return KNOT_EINVAL;
	}

	/* Add all RDATAs from rrset2 to rrset1 (i.e. concatenate two arrays) */
	
	/*! \note The following code should work for
	 *        all the cases i.e. R1 or R2 are empty.
	 */
	
	/* Reallocate actual RDATA array. */
	void *tmp = realloc(rrset1->rdata, rrset_rdata_size_total(rrset1) +
	                    rrset_rdata_size_total(rrset2));
	if (tmp == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	} else {
		rrset1->rdata = tmp;
	}
	
	/* The space is ready, copy the actual data. */
	memcpy(rrset1->rdata + rrset_rdata_size_total(rrset1),
	       rrset2->rdata, rrset_rdata_size_total(rrset2));
	
	/* Indices have to be readjusted. But space has to be made first. */
	tmp = realloc(rrset1->rdata_indices,
	              rrset1->rdata_count + rrset2->rdata_count + 1);
	if (tmp == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	} else {
		rrset1->rdata = tmp;
	}
	
	uint32_t rrset1_total_size = rrset_rdata_size_total(rrset1);
	
	/*
	 * Move the indices. Discard the last item in the first array, as it 
	 * contains total length of the data, which is now different.
	 */
	memcpy(rrset1->rdata_indices + rrset1->rdata_count,
	       rrset2->rdata_indices, rrset2->rdata_count);
	
	/* Go through the second part of index array and adjust offsets. */
	for (uint16_t i = 0; i < rrset2->rdata_count; i++) {
		rrset1->rdata_indices[rrset1->rdata_count + i] +=
			rrset1_total_size;
	}
	
	rrset1->rdata_count += rrset2->rdata_count;
	
	return KNOT_EOK;
}

int knot_rrset_merge_no_dupl(void **r1, void **r2)
{
	// TODO!
	return knot_rrset_merge(r1, r2);
}
//	if (r1 == NULL || r2 == NULL) {
//		dbg_rrset("rrset: merge_no_dupl: NULL arguments.");
//		return KNOT_EINVAL;
//	}
	
//	knot_rrset_t *rrset1 = (knot_rrset_t *)(*r1);
//	knot_rrset_t *rrset2 = (knot_rrset_t *)(*r2);
//	if (rrset1 == NULL || rrset2 == NULL) {
//		dbg_rrset("rrset: merge_no_dupl: NULL arguments.");
//		return KNOT_EINVAL;
//	}

	
//dbg_rrset_exec_detail(
//	char *name = knot_dname_to_str(rrset1->owner);
//	dbg_rrset_detail("rrset: merge_no_dupl: Merging %s.\n", name);
//	free(name);
//);

//	if ((knot_dname_compare(rrset1->owner, rrset2->owner) != 0)
//	    || rrset1->rclass != rrset2->rclass
//	    || rrset1->type != rrset2->type) {
//		dbg_rrset("rrset: merge_no_dupl: Trying to merge "
//		          "different RRs.\n");
//		return KNOT_EINVAL;
//	}

//	knot_rdata_t *walk2 = rrset2->rdata;

//	// no RDATA in RRSet 1
//	if (rrset1->rdata == NULL && rrset2->rdata != NULL) {
//		/*
//		 * This function has to assure that there are no duplicates in 
//		 * second RRSet's list. This can be done by putting a first 
//		 * item from the second list as a first item of the first list
//		 * and then simply continuing with inserting items from second
//		 * list to the first one.
//		 *
//		 * However, we must store pointer to second item in the second
//		 * list, as the 'next' pointer of the first item will be altered
//		 */

//		// Store pointer to the second item in RRSet2 RDATA so that
//		// we later start from this item.
//		walk2 = knot_rrset_rdata_get_next(rrset2, walk2);
//		assert(walk2 == rrset2->rdata->next || walk2 == NULL);

//		// Connect the first item from second list to the first list.
//		rrset1->rdata = rrset2->rdata;
//		// Close the cyclic list (by pointing to itself).
//		rrset1->rdata->next = rrset1->rdata;
//	} else if (rrset2->rdata == NULL) {
//		return KNOT_EOK;
//	}
	
//	/*
//	 * Check that rrset1 does not contain any rdata from rrset2, if so
//	 * such RDATA shall not be inserted. 
//	 */
	
//	/* Get last RDATA from first rrset, we'll need it for insertion. */
//	knot_rdata_t *insert_after = rrset1->rdata;
//	while (insert_after->next != rrset1->rdata) {
//		dbg_rrset_detail("rrset: merge_dupl: first rrset rdata: %p.\n",
//		                 insert_after);
//		insert_after = insert_after->next;
//	}
//	assert(insert_after->next == rrset1->rdata);

//	while (walk2 != NULL) {
//		knot_rdata_t *walk1 = rrset1->rdata;
//		char dupl = 0;
//		while ((walk1 != NULL) &&
//		       !dupl) {
//			const knot_rrtype_descriptor_t *desc =
//				knot_rrtype_descriptor_by_type(rrset1->type);
//			assert(desc);
//			/* If walk1 and walk2 are equal, do not insert. */
//			dupl = !knot_rdata_compare(walk1, walk2,
//			                           desc->wireformat);
//			walk1 = knot_rrset_rdata_get_next(rrset1, walk1);
//			dbg_rrset_detail("rrset: merge_dupl: next item: %p.\n",
//			                 walk1);
//		}
//		if (!dupl) {
//			dbg_rrset_detail("rrset: merge_dupl: Inserting "
//			                 "unique item (%p).\n",
//			                 walk2);
//			knot_rdata_t *tmp = walk2;
//			/*
//			 * We need to move this, insertion
//			 * will corrupt pointers.
//			 */
//			walk2 = knot_rrset_rdata_get_next(rrset2, walk2);
//			/* Insert this item at the end of first list. */
//			tmp->next = insert_after->next;
//			insert_after->next = tmp;
//			insert_after = tmp;
//			/*!< \todo This message has to be removed after bugfix. */
//			dbg_rrset_detail("rrset: merge_no_dupl: Insert after=%p"
//			                 ", tmp=%p, tmp->next=%p, "
//			                 " rrset1->rdata=%p"
//			                 "\n",
//			                 insert_after, tmp, tmp->next,
//			                 rrset1->rdata);
//			assert(tmp->next == rrset1->rdata);
//		} else {
//			dbg_rrset_detail("rrset: merge_dupl: Skipping and "
//			                 "freeing duplicated item "
//			                 "of type: %s (%p).\n",
//			                 knot_rrtype_to_string(rrset1->type),
//			                 walk2);
//			/* 
//			 * Not freeing this item will result in a leak. 
//			 * Since this operation destroys the second 
//			 * list, we have to free the item here.
//			 */
//			knot_rdata_t *tmp = walk2;
//			dbg_rrset_detail("rrset: merge_dupl: freeing: %p.\n",
//			                 tmp);
//			walk2 = knot_rrset_rdata_get_next(rrset2, walk2);
//			knot_rdata_deep_free(&tmp, rrset1->type, 1);
//			assert(tmp == NULL);
//			/* Maybe caller should be warned about this. */
//		}
//	}
//	assert(walk2 == NULL);
//dbg_rrset_exec_detail(
//	dbg_rrset_detail("rrset: merge_dupl: RDATA after merge:\n ");
//	knot_rdata_t *walk1 = rrset1->rdata;
//	while (walk1 != NULL) {
//		dbg_rrset_detail("%p ->\n", walk1);
//		walk1 = knot_rrset_rdata_get_next(rrset1, walk1);
//	}
//	dbg_rrset_detail("rrset: merge_dupl: RDATA after merge: r1:%p r2: %p\n",
//	                 rrset1->rdata, rrset2->rdata);
//);
//	/*
//	 * Since there is a possibility of corrupted list for second RRSet, it
//	 * is safer to set its list to NULL, so that it cannot be used.
//	 */
//	rrset2->rdata = NULL;

//	return KNOT_EOK;
//}

uint32_t knot_rrset_rdata_length(const knot_rrset_t *rrset, size_t rdata_pos)
{
	return 0;
}

uint32_t knot_rrset_rdata_length_total(const knot_rrset_t *rrset)
{
	return 0;
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rrset_rdata_cname_name(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}
	
	return (const knot_dname_t *)(rrset->rdata);
}

/*----------------------------------------------------------------------------*/

const knot_dname_t *knot_rrset_rdata_dname_target(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return NULL;
	}
	return (const knot_dname_t *)(rrset->rdata);
}

/*---------------------------------------------------------------------------*/

int64_t knot_rrset_rdata_soa_serial(const knot_rrset_t *rrset)
{
	if (rrset == NULL) {
		return 0;
	}
	
	//read u64??? TODO
	return knot_wire_read_u32(rrset->rdata + 
	                          sizeof(knot_dname_t *) * 2);

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

/*---------------------------------------------------------------------------*/

uint8_t knot_rrset_rdata_nsec3_algorithm(const knot_rrset_t *rrset,
                                         size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}
	
	return *(rrset_rdata_pointer(rrset, pos));
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

uint8_t knot_rrset_rdata_nsec3_salt_length(const knot_rrset_t *rrset,
                                           size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return 0;
	}
	
	return *(rrset_rdata_pointer(rrset, pos) + 4);
}

/*---------------------------------------------------------------------------*/

const uint8_t *knot_rrset_rdata_nsec3_salt(const knot_rrset_t *rrset,
                                           size_t pos)
{
	if (rrset == NULL || pos >= rrset->rdata_count) {
		return NULL;
	}
	
	return rrset_rdata_pointer(rrset, pos) + 4;
}

knot_dname_t *knot_rrset_get_next_dname(const knot_rrset_t *rrset,
                                        knot_dname_t *prev_dname)
{
	if (rrset == NULL) {
		return NULL;
	}
	
	for (uint16_t i = 0; i < rrset->rdata_count; i++) {
		knot_dname_t **ret =
			knot_rrset_rdata_get_next_dname_pointer(rrset,
		                                                &prev_dname, i);
		if (ret != NULL) {
			return (knot_dname_t *)ret;
		}
	}
	
	return NULL;
}

knot_dname_t **knot_rrset_get_next_dname_pointer(const knot_rrset_t *rrset,
                                                knot_dname_t **prev_dname)
{
	if (rrset == NULL) {
		return NULL;
	}
	
	for (uint16_t i = 0; i < rrset->rdata_count; i++) {
		knot_dname_t **ret =
			knot_rrset_rdata_get_next_dname_pointer(rrset,
		                                                prev_dname, i);
		if (ret != NULL) {
			return ret;
		}
	}
	
	return NULL;
}

knot_dname_t **knot_rrset_rdata_get_next_dname_pointer(
	const knot_rrset_t *rrset,
	knot_dname_t **prev_dname, size_t pos)
{
	if (rrset == NULL) {
		return NULL;
	}
	
	// Get descriptor
	const rdata_descriptor_t *desc =
		get_rdata_descriptor(rrset->type);
	int next = 0;
	size_t offset = 0;
	uint8_t *rdata = rrset_rdata_pointer(rrset, pos);
	if (prev_dname == NULL) {
		next = 1;
	}
	// Cycle through blocks and find dnames
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; i++) {
		if (descriptor_item_is_dname(desc->block_types[i])) {
			if (next) {
//				toto je imho spatne, ale who knows TODO
				return (knot_dname_t **)(rdata + offset);
			}
			
			knot_dname_t *dname =
				(knot_dname_t *)(rdata +
			                         offset);

			assert(prev_dname);
			
			if (dname == *prev_dname) {
				//we need to return next dname
				next = 1;
			}
			offset += sizeof(knot_dname_t *);
		} else if (descriptor_item_is_fixed(desc->block_types[i])) {
			offset += desc->block_types[i];
		} else if (!descriptor_item_is_remainder(desc->block_types[i])) {
			assert(rrset->type == KNOT_RRTYPE_NAPTR);
			offset += rrset_rdata_naptr_bin_chunk_size(rrset, pos);
			if (next) {
				return (knot_dname_t **)(rdata + offset);
			}
			
			knot_dname_t *dname =
				(knot_dname_t *)(rdata +
			                         offset);
			
			assert(prev_dname);
			
			if (dname == *prev_dname) {
				//we need to return next dname
				next = 1;
			}
			
			/* 
			 * Offset does not contain dname from NAPTR yet.
			 * It should not matter, since this block type
			 * is the only one in the RR anyway, but to be sure...
			 */
			offset += sizeof(knot_dname_t *); // now it does
		}
	}
	
	return NULL;
}

