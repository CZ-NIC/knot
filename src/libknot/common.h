/*!
 * \file libknot/common.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Common macros, includes and utilities.
 *
 * \addtogroup libknot
 * @{
 */
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

#include "common/errcode.h"
#include "common/mempattern.h"

#pragma once

#define KNOT_NAME "lib" PACKAGE_NAME // Project name
#define KNOT_VER  PACKAGE_VERSION  // 0xMMIIRR (MAJOR,MINOR,REVISION)

#ifndef UINT_DEFINED
typedef unsigned int uint; /*!< \brief Unsigned. */
#define UINT_DEFINED
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/*! \brief Eliminate compiler warning with unused parameters. */
#define UNUSED(param) (void)(param)

#ifndef MIN
/*! \brief Type-safe minimum macro. */
#define MIN(a, b) \
	({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

/*! \brief Type-safe maximum macro. */
#define MAX(a, b) \
	({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })
#endif

/* Optimisation macros. */
#ifndef knot_likely
/*! \brief Optimize for x to be true value. */
#define knot_likely(x)       __builtin_expect((x),1)
#endif
#ifndef knot_unlikely
/*! \brief Optimize for x to be false value. */
#define knot_unlikely(x)     __builtin_expect((x),0)
#endif

/*! \todo Refactor theese. We should have an allocator function handling this.*/
#ifndef ERR_ALLOC_FAILED
#define ERR_ALLOC_FAILED fprintf(stderr, \
                                 "Allocation failed at %s:%d (%s ver.%s)\n", \
                                 __FILE__, __LINE__, KNOT_NAME, KNOT_VER)
#endif

#ifndef CHECK_ALLOC_LOG
#define CHECK_ALLOC_LOG(var, ret) \
	do { \
		if ((var) == NULL) { \
			ERR_ALLOC_FAILED; \
			return (ret); \
		} \
	} while (0)
#endif

#ifndef CHECK_ALLOC
#define CHECK_ALLOC(var, ret) \
	do { \
		if ((var) == NULL) { \
			return (ret); \
		} \
	} while (0)
#endif

/*! @} */
