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
 * \file alloc-common.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Common macros for alloc.
 *
 * \addtogroup alloc
 * @{
 */

#ifndef _KNOTD_COMMON_ALLOC_COMMON_H_
#define _KNOTD_COMMON_ALLOC_COMMON_H_

#include <stdio.h>

//#define MEM_DEBUG
//#define MEM_NOSLAB
//#define MEM_POISON
#define MEM_SLAB_CAP 5   // Cap slab_cache empty slab count (undefined = inf)
#define MEM_COLORING       // Slab cache coloring
//#define MEM_SLAB_DEPOT     // Use slab depot for slab caching (not thread-safe)

/* Eliminate compiler warning with unused parameters. */
#ifndef UNUSED
#define UNUSED(param) (void)(param)
#endif

/* Optimisation macros. */
#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

#ifdef MEM_DEBUG
#define dbg_mem(msg...) fprintf(stderr, msg)
#else
#define dbg_mem(msg...)
#endif


#endif /* _KNOTD_COMMON_ALLOC_COMMON_H_ */

/*! @} */
