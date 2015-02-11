/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Compares two zone serials.
 *
 * \retval < 0 if s1 is less than s2.
 * \retval > 0 if s1 is larger than s2.
 * \retval == 0 if s1 is equal to s2.
 */
int serial_compare(uint32_t s1, uint32_t s2);

/*!
 * \brief Get next serial for given serial update policy.
 *
 * \param current  Current SOA serial.
 * \param policy   CONF_SERIAL_INCREMENT or CONF_SERIAL_UNIXTIME.
 *
 * \return New serial.
 */
int serial_next(uint32_t current, int policy);
