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
#include <stdbool.h>
#include <stdint.h>

#include "libknot/rrset.h"

#include "libknot/consts.h"
#include "libknot/common.h"
#include "libknot/mempattern.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/errcode.h"
#include "libknot/rrtype/naptr.h"

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

int knot_rrset_rr_to_canonical(knot_rrset_t *rrset)
{
	if (rrset == NULL || rrset->rrs.rr_count != 1) {
		return KNOT_EINVAL;
	}

	/* Convert owner for all RRSets. */
	int ret = knot_dname_to_lower(rrset->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Convert DNAMEs in RDATA only for RFC4034 types. */
	if (!knot_rrtype_should_be_lowercased(rrset->type)) {
		return KNOT_EOK;
	}

	const rdata_descriptor_t *desc = knot_get_rdata_descriptor(rrset->type);
	if (desc->type_name == NULL) {
		desc = knot_get_obsolete_rdata_descriptor(rrset->type);
	}

	knot_rdata_t *rdata = knot_rdataset_at(&rrset->rrs, 0);
	assert(rdata);
	uint16_t rdlen = knot_rdata_rdlen(rdata);
	uint8_t *pos = knot_rdata_data(rdata);
	uint8_t *endpos = pos + rdlen;

	/* No RDATA */
	if (rdlen == 0) {
		return KNOT_EOK;
	}

	/* Otherwise, whole and not malformed RDATA are expected. */
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; ++i) {
		int type = desc->block_types[i];
		switch (type) {
		case KNOT_RDATA_WF_COMPRESSIBLE_DNAME:
		case KNOT_RDATA_WF_DECOMPRESSIBLE_DNAME:
		case KNOT_RDATA_WF_FIXED_DNAME:
			ret = knot_dname_to_lower(pos);
			if (ret != KNOT_EOK) {
				return ret;
			}
			pos += knot_dname_size(pos);
			break;
		case KNOT_RDATA_WF_NAPTR_HEADER:
			pos += knot_naptr_header_size(pos, endpos);
			break;
		case KNOT_RDATA_WF_REMAINDER:
			break;
		default:
			/* Fixed size block */
			assert(type > 0);
			pos += type;
		}
	}

	return KNOT_EOK;
}

