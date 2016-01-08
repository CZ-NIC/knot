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

#ifdef HAVE_CLOCK_GETTIME
#include <time.h>
#define time_now(x) clock_gettime(CLOCK_MONOTONIC, (x))
typedef struct timespec timev_t;
#elif HAVE_GETTIMEOFDAY
#include <sys/time.h>
#define time_now(x) gettimeofday((x), NULL)
typedef struct timeval timev_t;
#else
#error Neither clock_gettime() nor gettimeofday() found. At least one is required.
#endif

/*! @} */
