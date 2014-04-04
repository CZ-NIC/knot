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

#include "libknot/rr.h"
#include "libknot/rdata.h"
#include "libknot/common.h"
#include "common/errcode.h"

#pragma pack(push, 1)

struct rr_offsets {
	uint32_t ttl;
	uint16_t size;
	uint8_t rdata[];
};

#pragma pack(pop)

#warning "missing #ifdefs for #pragma once, couldn't find the right define"

static void *mm_realloc(mm_ctx_t *mm, void *what, size_t size, size_t prev_size)
{
	if (mm) {
		void *p = mm->alloc(mm->ctx, size);
		if (knot_unlikely(p == NULL)) {
			return NULL;
		} else {
			if (what) {
				memcpy(p, what,
				       prev_size < size ? prev_size : size);
			}
			if (mm->free) {
				mm->free(what);
			}
			return p;
		}
	} else {
		return realloc(what, size);
	}
}

static knot_rr_t *rr_seek(knot_rr_t *d, size_t pos)
{
	if (d == NULL) {
		return NULL;
	}

	size_t offset = 0;
	for (size_t i = 0; i < pos; i++) {
		knot_rr_t *rr = d + offset;
		offset += knot_rr_array_size(knot_rr_rdata_size(rr));
	}

	return d + offset;
}

static size_t rrs_size(const knot_rrs_t *rrs)
{
	if (rrs == NULL) {
		return 0;
	}

	size_t total_size = 0;
	for (size_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rr_t *rr = knot_rrs_rr(rrs, i);
		assert(rr);
		total_size += knot_rr_array_size(knot_rr_rdata_size(rr));
	}

	return total_size;
}

static int add_rr_at(knot_rrs_t *rrs, const knot_rr_t *rr, size_t pos,
                     mm_ctx_t *mm)
{
	if (rrs == NULL || pos > rrs->rr_count) {
		return KNOT_EINVAL;
	}
	const uint16_t size = knot_rr_rdata_size(rr);
	const uint32_t ttl = knot_rr_ttl(rr);
	const uint8_t *rdata = knot_rr_rdata(rr);

	size_t total_size = rrs_size(rrs);

	// Realloc data.
	void *tmp = mm_realloc(mm, rrs->data,
	                       total_size + knot_rr_array_size(size),
	                       total_size);
	if (tmp) {
		rrs->data = tmp;
	} else {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	if (rrs->rr_count == 0 || pos == rrs->rr_count) {
		// No need to rearange RDATA
		rrs->rr_count++;
		knot_rr_t *new_rr = knot_rrs_rr(rrs, pos);
		knot_rr_set_size(new_rr, size);
		knot_rr_set_ttl(new_rr, ttl);
		memcpy(knot_rr_rdata, rdata, size);
		return KNOT_EOK;
	}

	// RDATA have to be rearanged.
	knot_rr_t *last_rr = knot_rrs_rr(rrs, rrs->rr_count - 1);
	knot_rr_t *old_rr = knot_rrs_rr(rrs, pos);
	assert(last_rr);
	assert(old_rr);

	// Make space for new data by moving the array
	memmove(old_rr + knot_rr_array_size(size), old_rr,
	        (last_rr + knot_rr_array_size(knot_rr_rdata_size(last_rr))) - old_rr);

	// Set new RR
	knot_rr_set_size(old_rr, size);
	knot_rr_set_ttl(old_rr, ttl);
	memcpy(knot_rr_rdata(old_rr), rdata, size);

	rrs->rr_count++;
	return KNOT_EOK;
}

uint16_t knot_rr_rdata_size(const knot_rr_t *rr)
{
	return ((struct rr_offsets *)rr)->size;
}

void knot_rr_set_size(knot_rr_t *rr, uint16_t size)
{
	((struct rr_offsets *)rr)->size = size;
}

uint32_t knot_rr_ttl(const knot_rr_t *rr)
{
	return ((struct rr_offsets *)rr)->ttl;
}

void knot_rr_set_ttl(knot_rr_t *rr, uint32_t ttl)
{
	((struct rr_offsets *)rr)->ttl = ttl;
}

uint8_t *knot_rr_rdata(const knot_rr_t *rr)
{
	return ((struct rr_offsets *)rr)->rdata;
}

size_t knot_rr_array_size(uint16_t size)
{
	return size + sizeof(struct rr_offsets);
}

int knot_rr_cmp(const knot_rr_t *rr1, const knot_rr_t *rr2)
{
	if (rr1 == NULL && rr2 != NULL) {
		return -1;
	}
	if (rr1 != NULL && rr2 == NULL) {
		return 1;
	}
	if (rr1 == NULL && rr2 == NULL) {
		return 0;
	}
	const uint8_t *r1 = knot_rr_rdata(rr1);
	const uint8_t *r2 = knot_rr_rdata(rr2);
	uint16_t l1 = knot_rr_rdata_size(rr1);
	uint16_t l2 = knot_rr_rdata_size(rr2);
	int cmp = memcmp(r1, r2, MIN(l1, l2));
	if (cmp == 0 && l1 != l2) {
		cmp = l1 < l2 ? -1 : 1;
	}
	return cmp;
}

void knot_rrs_init(knot_rrs_t *rrs)
{
	if (rrs) {
		rrs->rr_count = 0;
		rrs->data = NULL;
	}
}

void knot_rrs_clear(knot_rrs_t *rrs, mm_ctx_t *mm)
{
	if (rrs) {
		mm_free(mm, rrs->data);
		rrs->data = NULL;
		rrs->rr_count = 0;
	}
}

int knot_rrs_copy(knot_rrs_t *dst, const knot_rrs_t *src, mm_ctx_t *mm)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	dst->rr_count = src->rr_count;
	size_t src_size = rrs_size(src);
	dst->data = mm_alloc(mm, src_size);
	if (dst->data == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	memcpy(dst->data, src->data, src_size);
	return KNOT_EOK;
}

knot_rr_t *knot_rrs_rr(const knot_rrs_t *rrs, size_t pos)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return NULL;
	}

	return rr_seek(rrs->data, pos);
}

uint8_t *knot_rrs_rr_rdata(const knot_rrs_t *rrs, size_t pos)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return NULL;
	}

	return knot_rr_rdata(knot_rrs_rr(rrs, pos));
}

uint16_t knot_rrs_rr_size(const knot_rrs_t *rrs, size_t pos)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return 0;
	}

	return knot_rr_rdata_size(knot_rrs_rr(rrs, pos));
}

uint32_t knot_rrs_rr_ttl(const knot_rrs_t *rrs, size_t pos)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return 0;
	}

	return knot_rr_ttl(knot_rrs_rr(rrs, pos));
}

int knot_rrs_add_rr(knot_rrs_t *rrs, const knot_rr_t *rr, mm_ctx_t *mm)
{
	if (rrs == NULL || rr == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < rrs->rr_count; ++i) {
		const knot_rr_t *rrset_rr = knot_rrs_rr(rrs, i);
		int cmp = knot_rr_cmp(rrset_rr, rr);
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

int knot_rrs_remove_rr_at_pos(knot_rrs_t *rrs, size_t pos, mm_ctx_t *mm)
{
	if (rrs == NULL || pos >= rrs->rr_count) {
		return KNOT_EINVAL;
	}

	knot_rr_t *old_rr = knot_rrs_rr(rrs, pos);
	knot_rr_t *last_rr = knot_rrs_rr(rrs, rrs->rr_count - 1);
	assert(old_rr);
	assert(last_rr);

	size_t total_size = rrs_size(rrs);
	uint16_t old_size = knot_rr_rdata_size(old_rr);

	void *old_threshold = old_rr + knot_rr_array_size(old_size);
	void *last_threshold = last_rr + knot_rr_array_size(knot_rr_rdata_size(last_rr));
	// Move RDATA
	memmove(old_rr, old_threshold,
	        last_threshold - old_threshold);

	if (rrs->rr_count > 1) {
		// Realloc RDATA
		void *tmp = mm_realloc(mm, rrs->data,
		                       total_size - (knot_rr_array_size(old_size)),
		                       total_size);
		if (tmp == NULL) {
			ERR_ALLOC_FAILED;
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

bool knot_rrs_eq(const knot_rrs_t *rrs1, const knot_rrs_t *rrs2)
{
	if (rrs1->rr_count != rrs2->rr_count) {
		return false;
	}

	for (uint16_t i = 0; i < rrs1->rr_count; ++i) {
		const knot_rr_t *rr1 = knot_rrs_rr(rrs1, i);
		const knot_rr_t *rr2 = knot_rrs_rr(rrs2, i);
		if (knot_rr_cmp(rr1, rr2) != 0) {
			return false;
		}
	}

	return true;
}

int knot_rrs_synth_rrsig(uint16_t type, const knot_rrs_t *rrsig_rrs,
                         knot_rrs_t *out_sig, mm_ctx_t *mm)
{
	if (rrsig_rrs == NULL) {
		return KNOT_ENOENT;
	}

	if (out_sig == NULL || out_sig->rr_count > 0) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < rrsig_rrs->rr_count; ++i) {
		if (type == knot_rrs_rrsig_type_covered(rrsig_rrs, i)) {
			const knot_rr_t *rr_to_copy = knot_rrs_rr(rrsig_rrs, i);
			int ret = knot_rrs_add_rr(out_sig, rr_to_copy, mm);
			if (ret != KNOT_EOK) {
				knot_rrs_clear(out_sig, mm);
				return ret;
			}
		}
	}

	return out_sig->rr_count > 0 ? KNOT_EOK : KNOT_ENOENT;
}

int knot_rrs_merge(knot_rrs_t *rrs1, const knot_rrs_t *rrs2, mm_ctx_t *mm)
{
	if (rrs1 == NULL || rrs2 == NULL) {
		return KNOT_EINVAL;
	}

	for (uint16_t i = 0; i < rrs2->rr_count; ++i) {
		const knot_rr_t *rr = knot_rrs_rr(rrs2, i);
		int ret = knot_rrs_add_rr(rrs1, rr, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}
