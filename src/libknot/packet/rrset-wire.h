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
 * \brief RRSet from/to wire conversion functions.
 *
 * \addtogroup wire
 * @{
 */

#pragma once

#include "libknot/rrset.h"
#include "libknot/packet/compr.h"

/*!
 * \brief Write RR Set content to a wire.
 *
 * \param rrset     RRSet to be converted.
 * \param wire      Output wire buffer.
 * \param max_size  Capacity of wire buffer.
 * \param rotate    Rotate the RR order by this count.
 * \param compr     Compression context.
 * \param flags     Flags; currently only KNOT_PF_TTL_ORIG is accepted.
 *
 * \return Output size, negative number on error (KNOT_E*).
 */
int knot_rrset_to_wire_extra(const knot_rrset_t *rrset, uint8_t *wire,
                             uint16_t max_size, uint16_t rotate,
                             knot_compr_t *compr, uint16_t flags);

/* TODO: remove in next major version. */
int knot_rrset_to_wire_rotate(const knot_rrset_t *rrset, uint8_t *wire,
                              uint16_t max_size, uint16_t rotate,
                              knot_compr_t *compr);

/*! \brief Same as knot_rrset_to_wire_extra but without rrset rotation and flags. */
static inline int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire,
                                     uint16_t max_size, knot_compr_t *compr)
{
	return knot_rrset_to_wire_extra(rrset, wire, max_size, 0, compr, 0);
}

/*!
* \brief Creates one RR from wire, stores it into \a rrset.
*
* \param wire       Source wire (the whole packet).
* \param pos        Position in \a wire where to start parsing.
* \param max_size   Total size of data in \a wire (size of the packet).
* \param rrset      Destination RRSet.
* \param mm         Memory context.
* \param canonical  Convert rrset to canonical format indication.
*
* \return KNOT_E*
*/
int knot_rrset_rr_from_wire(const uint8_t *wire, size_t *pos, size_t max_size,
                            knot_rrset_t *rrset, knot_mm_t *mm, bool canonical);

/*! @} */
