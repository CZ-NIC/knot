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
	dst->rdata = mm_alloc(mm, src->size);
	if (dst->rdata == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(dst->rdata, src->rdata, src->size);

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

static inline knot_rdata_t * rdataset_end(const knot_rdataset_t *rrs)
{
	return (knot_rdata_t *)((uint8_t *)rrs->rdata + rrs->size);
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

	assert(rdataset_end(rrs) == ins_pos);

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
	// TODO: this won't be efficient if the second set is large,
	// especially if using mempools (quadratic work).
	// A merging pass alike to _subtract() would be linear,
	// if extended with a sane re-allocation strategy.

	return KNOT_EOK;
}

_public_
int knot_rdataset_intersect(const knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2,
                            knot_rdataset_t *out, knot_mm_t *mm)
{
	if (rrs1 == NULL || rrs2 == NULL || out == NULL) {
		return KNOT_EINVAL;
	}

	// Prepare for simultaneous "ordered merging" of both sequences.
	knot_rdataset_init(out);
	knot_rdata_t *rr1 = rrs1->rdata, *rr2 = rrs2->rdata;
	const knot_rdata_t *const rr1_end = rdataset_end(rrs1),
			   *const rr2_end = rdataset_end(rrs2);

	while (rr1 < rr1_end && rr2 < rr2_end) {
		const int cmp = knot_rdata_cmp(rr1, rr2);
		if (cmp < 0) {
			rr1 = knot_rdataset_next(rr1);
		} else if (cmp > 0) {
			rr2 = knot_rdataset_next(rr2);
		} else {
			int ret = add_rr_at(out, rr1, rdataset_end(out), mm);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(out, mm);
				return ret;
			}
			rr1 = knot_rdataset_next(rr1);
			rr2 = knot_rdataset_next(rr2);
			// TODO: better re-allocation strategy; important for mempools.
		}
	}
	assert(rr1 <= rr1_end && rr2 <= rr2_end);

	return KNOT_EOK;
}

_public_
int knot_rdataset_subtract(knot_rdataset_t *from, const knot_rdataset_t *what,
                           knot_mm_t *mm)
{
	if (from == NULL || what == NULL) {
		return KNOT_EINVAL;
	}

	if (from->rdata == what->rdata) { // optimization
		knot_rdataset_clear(from, mm);
		return KNOT_EOK;
	}

	// Prepare for simultaneous "ordered merging" of both sequences.
	knot_rdata_t *fr = from->rdata, *wh = what->rdata;
	uint8_t *out = (uint8_t *)fr;
	const knot_rdata_t *const fr_end = rdataset_end(from),
			   *const wh_end = rdataset_end(what);

	while (fr < fr_end && wh < wh_end) {
		const int cmp = knot_rdata_cmp(fr, wh);
		if (cmp > 0) { // nothing happens
			wh = knot_rdataset_next(wh);
		} else if (cmp == 0) { // this RR drops out
			--from->count;
			from->size -= knot_rdata_size(fr->len);
			fr = knot_rdataset_next(fr);
		} else { // the RR is kept
			if (out != (uint8_t *)fr) { // but we need to move it
				uint16_t size = knot_rdata_size(fr->len);
				memmove(out, fr, size); // move even padding
				out += size;
			}
			fr = knot_rdataset_next(fr);
		}
	}
	assert(fr <= fr_end && wh <= wh_end);

	// Done; just clean up.
	if (from->count == 0) {
		assert(from->size == 0);
		mm_free(mm, from->rdata);
		from->rdata = NULL;
	}
	// TODO: mm_realloc if the size decreased a lot?
	// Note that in mempools that would *worsen* memory usage.

	return KNOT_EOK;
}
