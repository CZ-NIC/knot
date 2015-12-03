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
 * \file macros.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Common macros.
 *
 * \addtogroup common_lib
 * @{
 */

#pragma once

/*! \brief Library visibility macros. */
#define _public_ __attribute__((visibility("default")))
#define _hidden_ __attribute__((visibility("hidden")))

/*! \brief GNU C function attributes. */
#if __GNUC__ >= 3
#define _pure_      __attribute__ ((pure))
#define _const_     __attribute__ ((const))
#define _noreturn_  __attribute__ ((noreturn))
#define _malloc_    __attribute__ ((malloc))
#define _mustcheck_ __attribute__ ((warn_unused_result))
#else
#define _pure_
#define _const_
#define _noreturn_
#define _malloc_
#define _mustcheck_
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

#ifndef likely
/*! \brief Optimize for x to be true value. */
#define likely(x) __builtin_expect((x), 1)
#endif

#ifndef unlikely
/*! \brief Optimize for x to be false value. */
#define unlikely(x) __builtin_expect((x), 0)
#endif

/*! @} */
