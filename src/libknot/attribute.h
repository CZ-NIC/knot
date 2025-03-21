/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \file
 *
 * \brief Function and variable attributes.
 *
 * \addtogroup libknot
 * @{
 */

#pragma once

/*! \brief Library visibility macros. */
#define _public_ __attribute__((visibility("default")))
#define _hidden_ __attribute__((visibility("hidden")))

#define _unused_ __attribute__((unused))

#define _cleanup_(var) __attribute__((cleanup(var)))

/*! \brief GNU C function attributes. */
#if __GNUC__ >= 3
#define _pure_         __attribute__ ((pure))
#define _const_        __attribute__ ((const))
#define _noreturn_     __attribute__ ((noreturn))
#define _malloc_       __attribute__ ((malloc))
#define _mustcheck_    __attribute__ ((warn_unused_result))
#define _nonnull_(...) __attribute__ ((nonnull(__VA_ARGS__)))
#else
#define _pure_
#define _const_
#define _noreturn_
#define _malloc_
#define _mustcheck_
#define _nonnull_
#endif

/*! @} */
