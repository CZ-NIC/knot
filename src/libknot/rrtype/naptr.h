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

#pragma once

#include <stdint.h>

/*!
 * \brief Counts the size of the NAPTR RDATA before the Replacement domain name.
 *
 * See RFC 2915.
 *
 * \param naptr  Wire format of NAPTR record.
 * \param maxp   Limit of the wire format.
 *
 * \retval KNOT_EMALF if the record is malformed.
 * \retval Size of the RDATA before the Replacement domain name.
 */
int knot_naptr_header_size(const uint8_t *naptr, const uint8_t *maxp);
