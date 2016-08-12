/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdio.h>
#include <stdlib.h>

#include "libknot/attribute.h"
#include "libknot/rdataset.h"
#include "libknot/errcode.h"
#include "contrib/mempattern.h"

static knot_rdata_t *rr_seek(knot_rdata_t *d, size_t pos)
{
	if (d == NULL) {
		return NULL;
	}

	size_t offset = 0;
	for (size_t i = 0; i < pos; i++) {
		knot_rdata_t *rr = d + offset;
		offset += knot_rdata_array_size(knot_rdata_rdlen(rr));
	}

	return d + offset;
}

static int find_rr_pos(const knot_rdataset_t *search_in,
                       const knot_rdata_t *rr)
{
	for (uint16_t i = 0; i < search_in->rr_count; ++i) {
		const knot_rdata_t *search_rr = knot_rdataset_at(search_in, i);
		if (knot_rdata_cmp(rr, search_rr) == 0) {
			return i;
		}
	}

	return KNOT_ENOENT;
}

static int add_rr_at(knot_rdataset_t *rrs, const knot_rdata_t *rr, size_t pos,
                     knot_mm_t *mm)
{
	if (rrs == NULL || pos > rrs->rr_count) {
		return KNOT_EINVAL;
	}
	const uint16_t size = knot_rdata_rdlen(rr);
	const uint32_t ttl = knot_rdata_ttl(rr);
	const uint8_t *rdata = knot_rdata_data(rr);

	size_t total_size = knot_rdataset_size(rrs);

	// Realloc data.
	void *tmp = mm_realloc(mm, rrs->data,
	                       total_size + knot_rdata_array_size(size),
	                       total_size);
	if (tmp) {
		rrs->data = tmp;
	} else {
		return KNOT_ENOMEM;
	}

	if (rrs->rr_count == 0 || pos == rrs->rr_count) {
		// No need to rearange RDATA
		rrs->rr_count++;
		knot_rdata_t *new_rr = knot_rdataset_at(rrs, pos);
		knot_rdata_init(new_rr, size, rdata, ttl);
		return KNOT_EOK;
	}

	// RDATA have to be rearanged.
	knot_rdata_t *last_rr = knot_rdataset_at(rrs, rrs->rr_count - 1);
	knot_rdata_t *old_rr = knot_rdataset_at(rrs, pos);
	assert(last_rr);
	assert(old_rr);

	// Make space for new data by moving the array
	memmove(old_rr + knot_rdata_array_size(size), old_rr,
	        (last_rr + knot_rdata_array_size(knot_rdata_rdlen(last_rr))) - old_rr);

	// Set new RR
	knot_rdata_init(old_rr, size, rdata, ttl);

	rrs->rr_count++;
	return KNOT_EOK;
}

static int remove_rr_at(knot_rdataset_t *rrs, size_t pos, knot_mm_t *mm)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *old_rr = knot_rdataset_at(rrs, pos);
	knot_rdata_t *last_rr = knot_rdataset_at(rrs, rrs->rr_count - 1);
	assert(old_rr);
	assert(last_rr);

	size_t total_size = knot_rdataset_size(rrs);
	uint16_t old_size = knot_rdata_rdlen(old_rr);

	uint8_t *old_threshold = old_rr + knot_rdata_array_size(old_size);
	uint8_t *last_threshold = last_rr + knot_rdata_array_size(knot_rdata_rdlen(last_rr));
	// Move RDATA
	memmove(old_rr, old_threshold,
	        last_threshold - old_threshold);

	if (rrs->rr_count > 1) {
		// Realloc RDATA
		void *tmp = mm_realloc(mm, rrs->data,
		                       total_size - (knot_rdata_array_size(old_size)),
		                       total_size);
		if (tmp == NULL) {
			return KNOT_ENOMEM;
		} else {
			rrs->data = tmp;
		}
	} else {
		// Free RDATA
		mm_free(mm, rrs->data);
		rrs->data = NULL;
	}
	rrs->rr_count--;

	return KNOT_EOK;
}

_public_
void knot_rdataset_init(knot_rdataset_t *rrs)
{
	if (rrs) {
		rrs->rr_count = 0;
		rrs->data = NULL;
	}
}

_public_
void knot_rdataset_clear(knot_rdataset_t *rrs, knot_mm_t *mm)
{
	if (rrs) {
		mm_free(mm, rrs->data);
		knot_rdataset_init(rrs);
	}
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
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, size_t pos)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return NULL;
	}

	return rr_seek(rrs->data, pos);
}

_public_
size_t knot_rdataset_size(const knot_rdataset_t *rrs)
{
	if (rrs == NULL) {
		return 0;
	}

	size_t total_size = 0;
	for (size_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rdata_t *rr = knot_rdataset_at(rrs, i);
		assert(rr);
		total_size += knot_rdata_array_size(knot_rdata_rdlen(rr));
	}

	return total_size;
}

_public_
uint32_t knot_rdataset_ttl(const knot_rdataset_t *rrs)
{
	return knot_rdata_ttl(knot_rdataset_at(rrs, 0));
}

_public_
void knot_rdataset_set_ttl(knot_rdataset_t *rrs, uint32_t ttl)
{
	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		knot_rdata_t *rrset_rr = knot_rdataset_at(rrs, i);
		knot_rdata_set_ttl(rrset_rr, ttl);
	}
}

_public_
int knot_rdataset_add(knot_rdataset_t *rrs, const knot_rdata_t *rr, knot_mm_t *mm)
{
	if (rrs == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rdata_t *rrset_rr = knot_rdataset_at(rrs, i);
		int cmp = knot_rdata_cmp(rrset_rr, rr);
		if (cmp == 0) {
			// Duplication - no need to add this RR
			return KNOT_EOK;
		} else if (cmp > 0) {
			// Found position to insert
			return add_rr_at(rrs, rr, i, mm);
		}
	}

	// If flow gets here, it means that we should insert at the last position
	return add_rr_at(rrs, rr, rrs->rr_count, mm);
}

_public_
int knot_rdataset_reserve(knot_rdataset_t *rrs, size_t size, knot_mm_t *mm)
{
	if (rrs == NULL || size > MAX_RDLENGTH) {
		return KNOT_EINVAL;
	}

	size_t total_size = knot_rdataset_size(rrs);
	size_t new_size = total_size + knot_rdata_array_size(size);

	uint8_t *tmp = mm_realloc(mm, rrs->data, new_size, total_size);
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	}

	rrs->data = tmp;
	rrs->rr_count++;

	// We have to initialise the 'size' field in the reserved space.
	knot_rdata_t *rr = knot_rdataset_at(rrs, rrs->rr_count - 1);
	assert(rr);
	knot_rdata_set_rdlen(rr, size);

	return KNOT_EOK;
}

_public_
int knot_rdataset_unreserve(knot_rdataset_t *rrs, knot_mm_t *mm)
{
	return remove_rr_at(rrs, rrs->rr_count - 1, mm);
}

_public_
bool knot_rdataset_eq(const knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2)
{
	if (rrs1->rr_count != rrs2->rr_count) {
		return false;
	}

	for (uint16_t i = 0; i < rrs1->rr_count; ++i) {
		const knot_rdata_t *rr1 = knot_rdataset_at(rrs1, i);
		const knot_rdata_t *rr2 = knot_rdataset_at(rrs2, i);
		if (knot_rdata_cmp(rr1, rr2) != 0) {
			return false;
		}
	}

	return true;
}

_public_
bool knot_rdataset_member(const knot_rdataset_t *rrs, const knot_rdata_t *rr,
                          bool cmp_ttl)
{
	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rdata_t *cmp_rr = knot_rdataset_at(rrs, i);
		if (cmp_ttl) {
			if (knot_rdata_ttl(rr) != knot_rdata_ttl(cmp_rr)) {
				continue;
			}
		}
		int cmp = knot_rdata_cmp(cmp_rr, rr);
		if (cmp == 0) {
			// Match.
			return true;
		}
		if (cmp > 0) {
			// 'Greater' RR present, no need to continue.
			return false;
		}
	}
	return false;
}

_public_
int knot_rdataset_merge(knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2, knot_mm_t *mm)
{
	if (rrs1 == NULL || rrs2 == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < rrs2->rr_count; ++i) {
		const knot_rdata_t *rr = knot_rdataset_at(rrs2, i);
		int ret = knot_rdataset_add(rrs1, rr, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

_public_
int knot_rdataset_intersect(const knot_rdataset_t *a, const knot_rdataset_t *b,
                            knot_rdataset_t *out, knot_mm_t *mm)
{
	if (a == NULL || b == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	knot_rdataset_init(out);
	const bool compare_ttls = false;
	for (uint16_t i = 0; i < a->rr_count; ++i) {
		const knot_rdata_t *rr = knot_rdataset_at(a, i);
		if (knot_rdataset_member(b, rr, compare_ttls)) {
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
		const knot_rdata_t *to_remove = knot_rdataset_at(what, i);
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
int knot_rdataset_sort_at(knot_rdataset_t *rrs, size_t pos, knot_mm_t *mm)
{
	if (rrs == NULL || rrs->rr_count == 0) {
		return KNOT_EINVAL;
	}

	knot_rdata_t *rr = knot_rdataset_at(rrs, pos);
	assert(rr);

	knot_rdata_t *earlier_rr = NULL;
	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		if (i == pos) {
			// It already is at the position
			return KNOT_EOK;
		}
		earlier_rr = knot_rdataset_at(rrs, i);
		int cmp = knot_rdata_cmp(earlier_rr, rr);
		if (cmp == 0) {
			// Duplication - we need to remove this RR
			return remove_rr_at(rrs, pos, mm);
		} else if (cmp > 0) {
			// Found position to move
			break;
		}
	}

	// RDATA have to be rearanged.
	knot_rdata_t *last_rr = knot_rdataset_at(rrs, pos - 1);
	assert(last_rr);
	assert(earlier_rr);

	// Save the RR to be moved
	const uint16_t size = knot_rdata_rdlen(rr);
	const uint32_t ttl = knot_rdata_ttl(rr);
	const uint8_t *rdata = knot_rdata_data(rr);

	knot_rdata_t tmp_rr[knot_rdata_array_size(size)];
	knot_rdata_init(tmp_rr, size, rdata, ttl);

	// Move the array or just part of it
	knot_rdata_t *earlier_rr_moved = earlier_rr + knot_rdata_array_size(size);
	size_t last_rr_size = knot_rdata_array_size(knot_rdata_rdlen(last_rr));
	memmove(earlier_rr_moved, earlier_rr, (last_rr + last_rr_size) - earlier_rr);

	// Set new RR
	knot_rdata_init(earlier_rr, size, knot_rdata_data(tmp_rr), ttl);

	return KNOT_EOK;
}
