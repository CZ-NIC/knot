/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \brief C11 atomic operations with fallbacks.
 */

#pragma once

#if 0
//#if (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)    /* C11 */
 #include <stdatomic.h>

 #define ATOMIC_SET(dst, val) atomic_store_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_GET(src)      atomic_load_explicit(&(src), memory_order_relaxed)
 #define ATOMIC_ADD(dst, val) (void)atomic_fetch_add_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_SUB(dst, val) (void)atomic_fetch_sub_explicit(&(dst), (val), memory_order_relaxed)

 typedef atomic_size_t knot_atomic_size_t;
 typedef atomic_uint_fast16_t knot_atomic_uint16_t;
 typedef atomic_uint_fast64_t knot_atomic_uint64_t;
//#elif HAVE_ATOMIC                    /* GCC */
 #include <stdint.h>

 #define ATOMIC_SET(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_GET(src)      __atomic_load_n(&(src), __ATOMIC_RELAXED)
 #define ATOMIC_ADD(dst, val) __atomic_add_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_SUB(dst, val) __atomic_sub_fetch(&(dst), (val), __ATOMIC_RELAXED)

 typedef size_t knot_atomic_size_t;
 typedef uint16_t knot_atomic_uint16_t;
 typedef uint64_t knot_atomic_uint64_t;
#else                                /* Fallback, non-atomic. */
// #warning "Atomic operations not availabe, using unreliable replacement."

 #include <stdint.h>

 #define ATOMIC_SET(dst, val) ((dst) = (val))
 #define ATOMIC_GET(src)      (src)
 #define ATOMIC_ADD(dst, val) ((dst) += (val))
 #define ATOMIC_SUB(dst, val) ((dst) -= (val))

 typedef size_t knot_atomic_size_t;
 typedef uint16_t knot_atomic_uint16_t;
 typedef uint64_t knot_atomic_uint64_t;
#endif
