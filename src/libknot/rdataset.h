/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief API for manipulating RR arrays.
 *
 * \addtogroup rr
 * @{
 */

#pragma once

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "libknot/mm_ctx.h"
#include "libknot/rdata.h"

/*!< \brief Set of RRs. */
typedef struct {
	uint16_t count;      /*!< \brief Count of RRs stored in the structure. */
	knot_rdata_t *rdata; /*!< \brief Serialized rdata, canonically sorted. */
} knot_rdataset_t;

/*!
 * \brief Initializes RRS structure.
 *
 * \param rrs  Structure to be initialized.
 */
inline static void knot_rdataset_init(knot_rdataset_t *rrs)
{
	if (rrs != NULL) {
		rrs->count = 0;
		rrs->rdata = NULL;
	}
}

/*!
 * \brief Advance to the next rdata in a rdataset.
 *
 * Useful for iteration.
 *
 * \note Ensure that this operation makes sense!
 *
 * \param rr  Current RR.
 *
 * \return Next RR.
 */
static inline knot_rdata_t *knot_rdataset_next(knot_rdata_t *rr)
{
	assert(rr);
	return (knot_rdata_t *)((uint8_t *)rr + knot_rdata_size(rr->len));
}

/*!
 * \brief Frees data initialized by RRS structure, but not the structure itself.
 *
 * \param rrs  Structure to be cleared.
 * \param mm   Memory context used to create allocations.
 */
void knot_rdataset_clear(knot_rdataset_t *rrs, knot_mm_t *mm);

/*!
 * \brief Deep copies RRS structure. All data are duplicated.
 *
 * \param dst  Copy destination.
 * \param src  Copy source.
 * \param mm   Memory context.
 *
 * \return KNOT_E*
 */
int knot_rdataset_copy(knot_rdataset_t *dst, const knot_rdataset_t *src, knot_mm_t *mm);

/*!
 * \brief Gets RR from RRS structure, using given position.
 *
 * \param rrs  RRS structure to get RR from.
 * \param pos  Position to use (counted from 0).
 *
 * \return Pointer to RR at \a pos position.
 */
knot_rdata_t *knot_rdataset_at(const knot_rdataset_t *rrs, uint16_t pos);

/*!
 * \brief Returns size of the structures holding the RR set.
 *
 * \param rrs  RR array.
 *
 * \return Array size.
 */
size_t knot_rdataset_size(const knot_rdataset_t *rrs);

/*!
 * \brief Adds single RR into RRS structure. All data are copied.
 *
 * \param rrs  RRS structure to add RR into.
 * \param rr   RR to add.
 * \param mm   Memory context.
 *
 * \return KNOT_E*
 */
int knot_rdataset_add(knot_rdataset_t *rrs, const knot_rdata_t *rr, knot_mm_t *mm);

/*!
 * \brief Reserves space at the end of the RRS structure.
 *
 * \param rrs   RRS structure to reserve space at.
 * \param size  How much space to reserve.
 * \param mm    Memory context.
 *
 * \return KNOT_E*
 */
int knot_rdataset_reserve(knot_rdataset_t *rrs, uint16_t size, knot_mm_t *mm);

/*!
 * \brief Removes the last RR from RRS structure, i.e. does the opposite of _reserve.
 *
 * \param rrs  RRS structure to remove RR from.
 * \param mm   Memory context.
 *
 * \return KNOT_E*
 */
int knot_rdataset_unreserve(knot_rdataset_t *rrs, knot_mm_t *mm);

/*!
 * \brief RRS equality check.
 *
 * \param rrs1  First RRS to be compared.
 * \param rrs2  Second RRS to be compared.
 *
 * \retval true if rrs1 == rrs2.
 * \retval false if rrs1 != rrs2.
 */
bool knot_rdataset_eq(const knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2);

/*!
 * \brief Returns true if \a rr is present in \a rrs, false otherwise.
 *
 * \param rrs  RRS to search in.
 * \param rr   RR to compare with.
 *
 * \retval true if \a rr is present in \a rrs.
 * \retval false if \a rr is not present in \a rrs.
 */
bool knot_rdataset_member(const knot_rdataset_t *rrs, const knot_rdata_t *rr);

/*!
 * \brief Merges two RRS into the first one. Second RRS is left intact.
 *        Canonical order is preserved.
 *
 * \param rrs1  Destination RRS (merge here).
 * \param rrs2  RRS to be merged (merge from).
 * \param mm    Memory context.
 *
 * \return KNOT_E*
 */
int knot_rdataset_merge(knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2,
                        knot_mm_t *mm);

/*!
 * \brief RRS set-like intersection. Full compare is done.
 *
 * \param rrs1  First RRS to intersect.
 * \param rrs2  Second RRS to intersect.
 * \param out   Output RRS with intersection, RDATA are created anew.
 * \param mm    Memory context. Will be used to create new RDATA.
 *
 * \return KNOT_E*
 */
int knot_rdataset_intersect(const knot_rdataset_t *rrs1, const knot_rdataset_t *rrs2,
                            knot_rdataset_t *out, knot_mm_t *mm);

/*!
 * \brief Does set-like RRS subtraction. \a from RRS is changed.
 *
 * \param from  RRS to subtract from.
 * \param what  RRS to subtract.
 * \param mm    Memory context use to reallocated \a from data.
 *
 * \return KNOT_E*
 */
int knot_rdataset_subtract(knot_rdataset_t *from, const knot_rdataset_t *what,
                           knot_mm_t *mm);

/*! @} */
