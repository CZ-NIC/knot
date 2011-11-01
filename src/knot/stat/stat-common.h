/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file stat-common.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Common macros for stat.
 *
 * \addtogroup statistics
 * @{
 */

#ifndef _KNOTD_STAT_COMMON_H_
#define _KNOTD_STAT_COMMON_H_

#include <stdio.h>

//#define STAT_COMPILE
#define ST_DEBUG

#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed at %s:%d\n", \
				  __FILE__, __LINE__)

#ifdef ST_DEBUG
#define dbg_st(msg...) fprintf(stderr, msg)
#else
#define dbg_st(msg...)
#endif

#endif /* _KNOTD_STAT_COMMON_H_ */

/*! @} */
