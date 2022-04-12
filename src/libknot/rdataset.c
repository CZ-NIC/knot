/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <string.h>
#include <stdlib.h>

#include "libknot/attribute.h"
#include "libknot/rdataset.h"
#include "contrib/mempattern.h"

static knot_rdata_t *rr_seek(const knot_rdataset_t *rrs, uint16_t pos)
{
	assert(rrs);
	assert(0 < rrs->count);
	assert(pos < rrs->count);

	uint8_t *raw = (uint8_t *)(rrs->rdata);
	for (uint16_t i = 0; i < pos; ++i) {
		raw += knot_rdata_size(((knot_rdata_t *)raw)->len);
	}

	return (knot_rdata_t *)raw;
}

static int find_rr_pos(const knot_rdataset_t *rrs, const knot_rdata_t *rr)
{
	knot_rdata_t *search_rr = rrs->rdata;
	for (uint16_t i = 0; i < rrs->count; ++i) {
		if (knot_rdata_cmp(rr, search_rr) == 0) {
			return i;
		}
		search_rr = knot_rdataset_next(search_rr);
	}

	return KNOT_ENOENT;
}

static int add_rr_at(knot_rdataset_t *rrs, const knot_rdata_t *rr, knot_rdata_t *ins_pos,
                     knot_mm_t *mm)
{
	assert(rrs);
	assert(rr);
	const size_t ins_offset = (uint8_t *)ins_pos - (uint8_t *)rrs->rdata;
	assert(ins_offset <= rrs->size);

	if (rrs->count == UINT16_MAX) {
		return KNOT_ESPACE;
	} else if (rrs->size > UINT32_MAX - knot_rdata_size(UINT16_MAX)) {
		return KNOT_ESPACE;
	}

	const size_t rr_size = knot_rdata_size(rr->len);

	// Realloc RDATA.
	knot_rdata_t *tmp = mm_realloc(mm, rrs->rdata, rrs->size + rr_size,
	                               rrs->size);
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	} else {
		rrs->rdata = tmp;
	}

	uint8_t *ins_pos_raw = (uint8_t *)rrs->rdata + ins_offset;
	// RDATA may have to be rearanged.  Moving zero-length region is OK.
	memmove(ins_pos_raw + rr_size, ins_pos_raw, rrs->size - ins_offset);

	// Set new RDATA.
	knot_rdata_init((knot_rdata_t *)ins_pos_raw, rr->len, rr->data);
	rrs->count++;
	rrs->size += rr_size;

	return KNOT_EOK;
}

static int remove_rr_at(knot_rdataset_t *rrs, uint16_t pos, knot_mm_t *mm)
{
	assert(rrs);
	assert(0 < rrs->count);
	assert(pos < rrs->count);

	knot_rdata_t *old_rr = rr_seek(rrs, pos);
	knot_rdata_t *last_rr = rr_seek(rrs, rrs->count - 1);

	size_t old_size = knot_rdata_size(old_rr->len);

	// Move RDATA.
	uint8_t *old_threshold = (uint8_t *)old_rr + old_size;
	uint8_t *last_threshold = (uint8_t *)last_rr + knot_rdata_size(last_rr->len);
	assert(old_threshold <= last_threshold);
	memmove(old_rr, old_threshold, last_threshold - old_threshold);

	if (rrs->count > 1) {
		// Realloc RDATA.
		knot_rdata_t *tmp = mm_realloc(mm, rrs->rdata, rrs->size - old_size,
		                               rrs->size);
		if (tmp == NULL) {
			return KNOT_ENOMEM;
		} else {
			rrs->rdata = tmp;
		}
	} else {
		// Free RDATA.
		mm_free(mm, rrs->rdata);
		rrs->rdata = NULL;
	}
	rrs->count--;
	rrs->size -= old_size;

	return KNOT_EOK;
}

_public_
void knot_rdataset_clear(knot_rdataset_t *rrs, knot_mm_t *mm)
{
	if (rrs == NULL) {
		return;
	}

	mm_free(mm, rrs->rdata);
	knot_rdataset_init(rrs);
}

_public_
int knot_rdataset_copy(knot_rdataset_t *dst, const knot_rdataset_t *src, knot_mm_t *mm)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	dst->count = src->count;
	dst->size = src->size;

	if (src->count > 0) {
		assert(src->rdata != NULL);
		dst->rdata = mm_alloc(mm, src->size);
		if (dst->rdata == NULL) {
			return KNOT_ENOMEM;
		}
		memcpy(dst->rdata, src->rdata, src->size);
	} else {
		assert(src->size == 0);
		dst->rdata = NULL;
	}

	return KNOT_EOK;
}

_public_
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, uint16_t pos)
{
	if (rrs == NULL || rrs->count == 0 || pos >= rrs->count) {
		return NULL;
	}

	return rr_seek(rrs, pos);
}

_public_
int knot_rdataset_add(knot_rdataset_t *rrs, const knot_rdata_t *rr, knot_mm_t *mm)
{
	if (rrs == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	// Optimize a little for insertion at the end, for larger RRsets.
	if (rrs->count > 4) {
		knot_rdata_t *last = rr_seek(rrs, rrs->count - 1);
		if (knot_rdata_cmp(last, rr) < 0) {
			return add_rr_at(rrs, rr, knot_rdataset_next(last), mm);
		}
	}

	// Look for the right place to insert.
	knot_rdata_t *ins_pos = rrs->rdata;
	for (int i = 0; i < rrs->count; ++i, ins_pos = knot_rdataset_next(ins_pos)) {
		int cmp = knot_rdata_cmp(ins_pos, rr);
		if (cmp == 0) {
			// Duplicate - no need to add this RR.
			return KNOT_EOK;
		} else if (cmp > 0) {
			// Found position to insert.
			return add_rr_at(rrs, rr, ins_pos, mm);
		}
	}

	assert(rrs->rdata == NULL || (uint8_t *)rrs->rdata + rrs->size == (uint8_t *)ins_pos);

	// If flow gets here, it means that we should insert at the current position (append).
	return add_rr_at(rrs, rr, ins_pos, mm);
}

_public_
bool knot_rdataset_eq(const knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2)
{
	if (rrs1 == NULL || rrs2 == NULL || rrs1->count != rrs2->count) {
		return false;
	}

	knot_rdata_t *rr1 = rrs1->rdata;
	knot_rdata_t *rr2 = rrs2->rdata;
	for (uint16_t i = 0; i < rrs1->count; ++i) {
		if (knot_rdata_cmp(rr1, rr2) != 0) {
			return false;
		}
		rr1 = knot_rdataset_next(rr1);
		rr2 = knot_rdataset_next(rr2);
	}

	return true;
}

_public_
bool knot_rdataset_member(const knot_rdataset_t *rrs, const knot_rdata_t *rr)
{
	if (rrs == NULL) {
		return false;
	}

	knot_rdata_t *cmp_rr = rrs->rdata;
	for (uint16_t i = 0; i < rrs->count; ++i) {
		int cmp = knot_rdata_cmp(cmp_rr, rr);
		if (cmp == 0) {
			// Match.
			return true;
		} else if (cmp > 0) {
			// 'Greater' RR present, no need to continue.
			return false;
		}
		cmp_rr = knot_rdataset_next(cmp_rr);
	}

	return false;
}

_public_
bool knot_rdataset_subset(const knot_rdataset_t *subset, const knot_rdataset_t *of)
{
	if (subset == NULL || (of != NULL && subset->rdata == of->rdata)) {
		return true;
	}

	knot_rdata_t *rd = subset->rdata;
	for (uint16_t i = 0; i < subset->count; ++i) {
		if (!knot_rdataset_member(of, rd)) {
			return false;
		}
		rd = knot_rdataset_next(rd);
	}

	return true;
}

_public_
int knot_rdataset_merge(knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2,
                        knot_mm_t *mm)
{
	if (rrs1 == NULL || rrs2 == NULL) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rr2 = rrs2->rdata;
	for (uint16_t i = 0; i < rrs2->count; ++i) {
		int ret = knot_rdataset_add(rrs1, rr2, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
		rr2 = knot_rdataset_next(rr2);
	}

	return KNOT_EOK;
}

_public_
int knot_rdataset_intersect(const knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2,
                            knot_rdataset_t *out, knot_mm_t *mm)
{
	if (rrs1 == NULL || rrs2 == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	knot_rdataset_init(out);
	knot_rdata_t *rr1 = rrs1->rdata;
	for (uint16_t i = 0; i < rrs1->count; ++i) {
		if (knot_rdataset_member(rrs2, rr1)) {
			// Add RR into output intersection RRSet.
			int ret = knot_rdataset_add(out, rr1, mm);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(out, mm);
				return ret;
			}
		}
		rr1 = knot_rdataset_next(rr1);
	}

	return KNOT_EOK;
}

_public_
int knot_rdataset_intersect2(knot_rdataset_t *from, const knot_rdataset_t *what,
                             knot_mm_t *mm)
{
	if (from == NULL || what == NULL) {
		return KNOT_EINVAL;
	}

	if (from->rdata == what->rdata) {
		return KNOT_EOK;
	}

	knot_rdata_t *rr1 = from->rdata;
	for (uint16_t i = 0; i < from->count; ) {
		if (!knot_rdataset_member(what, rr1)) {
			int ret = remove_rr_at(from, i, mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
			if (i < from->count) {
				// Just to make sure rr1 remains valid if re-allocated.
				rr1 = rr_seek(from, i);
			}
		} else {
			i++;
			rr1 = knot_rdataset_next(rr1);
		}
	}

	return KNOT_EOK;
}

_public_
int knot_rdataset_subtract(knot_rdataset_t *from, const knot_rdataset_t *what,
                           knot_mm_t *mm)
{
	if (from == NULL || what == NULL) {
		return KNOT_EINVAL;
	}

	if (from->rdata == what->rdata) {
		knot_rdataset_clear(from, mm);
		knot_rdataset_init((knot_rdataset_t *) what);
		return KNOT_EOK;
	}

	knot_rdata_t *to_remove = what->rdata;
	for (uint16_t i = 0; i < what->count; ++i) {
		int pos_to_remove = find_rr_pos(from, to_remove);
		if (pos_to_remove >= 0) {
			int ret = remove_rr_at(from, pos_to_remove, mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
		to_remove = knot_rdataset_next(to_remove);
	}

	return KNOT_EOK;
}
