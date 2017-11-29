/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <string.h>
#include <stdlib.h>

#include "libknot/attribute.h"
#include "libknot/rdataset.h"
#include "libknot/errcode.h"
#include "contrib/mempattern.h"

static knot_rdata_t *rr_seek(const knot_rdataset_t *rrs, uint16_t pos)
{
	assert(rrs);
	assert(0 < rrs->rr_count);
	assert(pos < rrs->rr_count);

	uint8_t *raw = (uint8_t *)(rrs->data);
	for (uint16_t i = 0; i < pos; ++i) {
		raw += knot_rdata_size(((knot_rdata_t *)raw)->len);
	}

	return (knot_rdata_t *)raw;
}

static int find_rr_pos(const knot_rdataset_t *rrs, const knot_rdata_t *rr)
{
	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rdata_t *search_rr = rr_seek(rrs, i);
		if (knot_rdata_cmp(rr, search_rr) == 0) {
			return i;
		}
	}

	return KNOT_ENOENT;
}

static int add_rr_at(knot_rdataset_t *rrs, const knot_rdata_t *rr, uint16_t pos,
                     knot_mm_t *mm)
{
	assert(rrs);
	assert(rr);
	assert(pos <= rrs->rr_count);

	if (rrs->rr_count == UINT16_MAX) {
		return KNOT_ESPACE;
	}

	size_t total_size = knot_rdataset_size(rrs);
	size_t new_size = knot_rdata_size(rr->len);

	// Realloc RDATA.
	knot_rdata_t *tmp = mm_realloc(mm, rrs->data, total_size + new_size,
	                               total_size);
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	} else {
		rrs->data = tmp;
	}

	if (rrs->rr_count == 0 || pos == rrs->rr_count) {
		// No need to rearange RDATA.
		rrs->rr_count++;
		knot_rdata_t *new_rr = rr_seek(rrs, pos);
		knot_rdata_init(new_rr, rr->len, rr->data);
		return KNOT_EOK;
	}

	// RDATA have to be rearanged.
	knot_rdata_t *old_rr = rr_seek(rrs, pos);
	knot_rdata_t *last_rr = rr_seek(rrs, rrs->rr_count - 1);

	// Make space for new RDATA by moving the array.
	uint8_t *dst = (uint8_t *)old_rr + new_size;
	assert(old_rr <= last_rr);
	size_t len = ((uint8_t *)last_rr - (uint8_t *)old_rr) +
	             knot_rdata_size(last_rr->len);
	memmove(dst, old_rr, len);

	// Set new RDATA.
	knot_rdata_init(old_rr, rr->len, rr->data);
	rrs->rr_count++;

	return KNOT_EOK;
}

static int remove_rr_at(knot_rdataset_t *rrs, uint16_t pos, knot_mm_t *mm)
{
	assert(rrs);
	assert(0 < rrs->rr_count);
	assert(pos < rrs->rr_count);

	knot_rdata_t *old_rr = rr_seek(rrs, pos);
	knot_rdata_t *last_rr = rr_seek(rrs, rrs->rr_count - 1);

	size_t total_size = knot_rdataset_size(rrs);
	size_t old_size = knot_rdata_size(old_rr->len);

	// Move RDATA.
	uint8_t *old_threshold = (uint8_t *)old_rr + old_size;
	uint8_t *last_threshold = (uint8_t *)last_rr + knot_rdata_size(last_rr->len);
	assert(old_threshold <= last_threshold);
	memmove(old_rr, old_threshold, last_threshold - old_threshold);

	if (rrs->rr_count > 1) {
		// Realloc RDATA.
		knot_rdata_t *tmp = mm_realloc(mm, rrs->data, total_size - old_size,
		                               total_size);
		if (tmp == NULL) {
			return KNOT_ENOMEM;
		} else {
			rrs->data = tmp;
		}
	} else {
		// Free RDATA.
		mm_free(mm, rrs->data);
		rrs->data = NULL;
	}
	rrs->rr_count--;

	return KNOT_EOK;
}

_public_
void knot_rdataset_init(knot_rdataset_t *rrs)
{
	if (rrs == NULL) {
		return;
	}

	rrs->rr_count = 0;
	rrs->data = NULL;
}

_public_
void knot_rdataset_clear(knot_rdataset_t *rrs, knot_mm_t *mm)
{
	if (rrs == NULL) {
		return;
	}

	mm_free(mm, rrs->data);
	knot_rdataset_init(rrs);
}

_public_
int knot_rdataset_copy(knot_rdataset_t *dst, const knot_rdataset_t *src, knot_mm_t *mm)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	dst->rr_count = src->rr_count;
	size_t src_size = knot_rdataset_size(src);
	dst->data = mm_alloc(mm, src_size);
	if (dst->data == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(dst->data, src->data, src_size);

	return KNOT_EOK;
}

_public_
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, uint16_t pos)
{
	if (rrs == NULL || rrs->rr_count == 0 || pos >= rrs->rr_count) {
		return NULL;
	}

	return rr_seek(rrs, pos);
}

_public_
size_t knot_rdataset_size(const knot_rdataset_t *rrs)
{
	if (rrs == NULL || rrs->rr_count == 0) {
		return 0;
	}

	const knot_rdata_t *last = rr_seek(rrs, rrs->rr_count - 1);
	return (uint8_t *)last + knot_rdata_size(last->len) - (uint8_t *)rrs->data;
}

_public_
int knot_rdataset_add(knot_rdataset_t *rrs, const knot_rdata_t *rr, knot_mm_t *mm)
{
	if (rrs == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	// First insert to empty rdataset.
	if (rrs->rr_count == 0) {
		return add_rr_at(rrs, rr, 0, mm);
	}

	for (int i = rrs->rr_count - 1; i >= 0; --i) {
		const knot_rdata_t *rrset_rr = rr_seek(rrs, i);
		int cmp = knot_rdata_cmp(rrset_rr, rr);
		if (cmp == 0) {
			// Duplicate - no need to add this RR.
			return KNOT_EOK;
		} else if (cmp < 0) {
			// Found position to insert.
			return add_rr_at(rrs, rr, i + 1, mm);
		}
	}

	// If flow gets here, it means that we should insert at the first position.
	return add_rr_at(rrs, rr, 0, mm);
}

_public_
int knot_rdataset_reserve(knot_rdataset_t *rrs, uint16_t size, knot_mm_t *mm)
{
	if (rrs == NULL) {
		return KNOT_EINVAL;
	} else if (rrs->rr_count == UINT16_MAX) {
		return KNOT_ESPACE;
	}

	size_t old_size = knot_rdataset_size(rrs);
	size_t new_size = old_size + knot_rdata_size(size);

	knot_rdata_t *tmp = mm_realloc(mm, rrs->data, new_size, old_size);
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	}
	rrs->data = tmp;
	rrs->rr_count++;

	// We have to initialise the 'size' field in the reserved space.
	rr_seek(rrs, rrs->rr_count - 1)->len = size;

	return KNOT_EOK;
}

_public_
int knot_rdataset_unreserve(knot_rdataset_t *rrs, knot_mm_t *mm)
{
	if (rrs == NULL || rrs->rr_count == 0) {
		return KNOT_EINVAL;
	}

	return remove_rr_at(rrs, rrs->rr_count - 1, mm);
}

_public_
bool knot_rdataset_eq(const knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2)
{
	if (rrs1 == NULL || rrs2 == NULL || rrs1->rr_count != rrs2->rr_count) {
		return false;
	}

	for (uint16_t i = 0; i < rrs1->rr_count; ++i) {
		const knot_rdata_t *rr1 = rr_seek(rrs1, i);
		const knot_rdata_t *rr2 = rr_seek(rrs2, i);
		if (knot_rdata_cmp(rr1, rr2) != 0) {
			return false;
		}
	}

	return true;
}

_public_
bool knot_rdataset_member(const knot_rdataset_t *rrs, const knot_rdata_t *rr)
{
	if (rrs == NULL) {
		return false;
	}

	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rdata_t *cmp_rr = rr_seek(rrs, i);
		int cmp = knot_rdata_cmp(cmp_rr, rr);
		if (cmp == 0) {
			// Match.
			return true;
		} else if (cmp > 0) {
			// 'Greater' RR present, no need to continue.
			return false;
		}
	}

	return false;
}

_public_
int knot_rdataset_merge(knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2,
                        knot_mm_t *mm)
{
	if (rrs1 == NULL || rrs2 == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < rrs2->rr_count; ++i) {
		const knot_rdata_t *rr = rr_seek(rrs2, i);
		int ret = knot_rdataset_add(rrs1, rr, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
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
	for (uint16_t i = 0; i < rrs1->rr_count; ++i) {
		const knot_rdata_t *rr = rr_seek(rrs1, i);
		if (knot_rdataset_member(rrs2, rr)) {
			// Add RR into output intersection RRSet.
			int ret = knot_rdataset_add(out, rr, mm);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(out, mm);
				return ret;
			}
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

	if (from->data == what->data) {
		knot_rdataset_clear(from, mm);
		knot_rdataset_init((knot_rdataset_t *) what);
		return KNOT_EOK;
	}

	for (uint16_t i = 0; i < what->rr_count; ++i) {
		const knot_rdata_t *to_remove = rr_seek(what, i);
		int pos_to_remove = find_rr_pos(from, to_remove);
		if (pos_to_remove >= 0) {
			int ret = remove_rr_at(from, pos_to_remove, mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

_public_
int knot_rdataset_sort_at(knot_rdataset_t *rrs, uint16_t pos, knot_mm_t *mm)
{
	if (rrs == NULL || rrs->rr_count == 0 || pos >= rrs->rr_count) {
		return KNOT_EINVAL;
	}

	const knot_rdata_t *rr = rr_seek(rrs, pos);

	knot_rdata_t *earlier_rr = NULL;
	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		if (i == pos) {
			// It already is at the position.
			return KNOT_EOK;
		}
		earlier_rr = rr_seek(rrs, i);
		int cmp = knot_rdata_cmp(earlier_rr, rr);
		if (cmp == 0) {
			// Duplicate - we need to remove this RR.
			return remove_rr_at(rrs, pos, mm);
		} else if (cmp > 0) {
			// Found position to move.
			break;
		}
	}
	assert(earlier_rr);

	// Save the RDATA to be moved.
	uint8_t buf[knot_rdata_size(rr->len)];
	knot_rdata_t *tmp_rr = (knot_rdata_t *)buf;
	knot_rdata_init(tmp_rr, rr->len, rr->data);

	// Move the array or just part of it.
	assert(pos > 0);
	knot_rdata_t *last_rr = rr_seek(rrs, pos - 1);
	uint8_t *moved = (uint8_t *)earlier_rr + knot_rdata_size(tmp_rr->len);
	assert(earlier_rr <= last_rr);
	size_t len = ((uint8_t *)last_rr - (uint8_t *)earlier_rr) +
	             knot_rdata_size(last_rr->len);
	memmove(moved, earlier_rr, len);

	// Set new RDATA.
	knot_rdata_init(earlier_rr, tmp_rr->len, tmp_rr->data);

	return KNOT_EOK;
}
