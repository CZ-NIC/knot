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
/*!
 * \file
 *
 * \brief Universal time getter.
 *
 * \addtogroup contrib
 * @{
 */

#pragma once

#include <time.h>

/*!
 * \brief Get current time.
 */
struct timespec time_now(void);

/*!
 * \brief Get time elapsed between two events.
 */
struct timespec time_diff(const struct timespec *begin, const struct timespec *end);

/*!
 * \brief Get time elapsed between two events in miliseconds.
 */
double time_diff_ms(const struct timespec *begin, const struct timespec *end);

/*! @} */
