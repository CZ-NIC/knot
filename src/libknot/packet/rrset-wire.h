/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/mm_ctx.h"

struct knot_compr;

/*!
 * \brief Write RR Set content to a wire.
 *
 * \param rrset     RRSet to be converted.
 * \param wire      Output wire buffer.
 * \param max_size  Capacity of wire buffer.
 * \param compr     Compression context.
 *
 * \return Output size, negative number on error (KNOT_E*).
 */
int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, uint16_t max_size,
                       struct knot_compr *compr);

/*!
* \brief Creates one RR from wire, stores it into \a rrset.
*
* \param pkt_wire    Source wire (the whole packet).
* \param pos         Position in \a wire where to start parsing.
* \param pkt_size    Total size of data in \a wire (size of the packet).
* \param mm          Memory context.
* \param rrset       Destination RRSet.
* \param canonical   Convert rrset to canonical format indication.
*
* \return KNOT_E*
*/
int knot_rrset_rr_from_wire(const uint8_t *pkt_wire, size_t *pos, size_t pkt_size,
                            knot_mm_t *mm, knot_rrset_t *rrset, bool canonical);

/*! @} */
