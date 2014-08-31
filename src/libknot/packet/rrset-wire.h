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
/*!
 * \file rrset.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief RRSet from/to wire conversion functions.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "libknot/mempattern.h"
#include "libknot/dname.h"
#include "libknot/rrset.h"

struct knot_compr;

/*!
 * \brief Flags controlling RR set from/to wire conversion.
 */
enum knot_rrset_wire_flags {
	KNOT_RRSET_WIRE_NONE = 0,
	KNOT_RRSET_WIRE_CANONICAL = 1 << 0,
};

typedef enum knot_rrset_wire_flags knot_rrset_wire_flags_t;

/*!
 * \brief Write RR Set content to a wire.
 *
 * Function accepts \ref KNOT_RRSET_WIRE_CANONICAL flag, which causes the
 * output to be written in canonical representation.
 *
 * \param rrset     RRSet to be converted.
 * \param wire      Output wire buffer.
 * \param max_size  Capacity of wire buffer.
 * \param compr     Compression context.
 * \param flags     Flags controlling the output.
 *
 * \return Output size, negative number on error (KNOT_E*).
 */
int knot_rrset_to_wire(const knot_rrset_t *rrset, uint8_t *wire, uint16_t max_size,
                       struct knot_compr *compr, knot_rrset_wire_flags_t flags);

/*!
* \brief Creates one RR from wire, stores it into \a rrset.
*
* \param pkt_wire    Source wire (the whole packet).
* \param pos         Position in \a wire where to start parsing.
* \param pkt_size    Total size of data in \a wire (size of the packet).
* \param mm          Memory context.
* \param rrset       Destination RRSet.
*
* \return KNOT_E*
*/
int knot_rrset_rr_from_wire(const uint8_t *pkt_wire, size_t *pos,
                            size_t pkt_size, mm_ctx_t *mm, knot_rrset_t *rrset);
