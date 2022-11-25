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

#if (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
 #include <stdatomic.h>              /* C11 */

 #define ATOMIC_SET(dst, val) atomic_store_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_GET(src)      atomic_load_explicit(&(src), memory_order_relaxed)
 #define ATOMIC_ADD(dst, val) (void)atomic_fetch_add_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_SUB(dst, val) (void)atomic_fetch_sub_explicit(&(dst), (val), memory_order_relaxed)
#elif HAVE_ATOMIC                    /* GCC */
 #define ATOMIC_SET(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_GET(src)      __atomic_load_n(&(src), __ATOMIC_RELAXED)
 #define ATOMIC_ADD(dst, val) __atomic_add_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_SUB(dst, val) __atomic_sub_fetch(&(dst), (val), __ATOMIC_RELAXED)
#elif HAVE_SYNC_ATOMIC               /* obsolete GCC, partial support only. */
 #warning "Full atomic operations not availabe, using partially unreliable replacement."
 #define ATOMIC_SET(dst, val) ((dst) = (val))
 #define ATOMIC_GET(src)      __sync_fetch_and_or(&(src), 0)
 #define ATOMIC_ADD(dst, val) __sync_add_and_fetch(&(dst), (val))
 #define ATOMIC_SUB(dst, val) __sync_sub_and_fetch(&(dst), (val))
#else                                /* Fallback, non-atomic. */
 #warning "Atomic operations not availabe, using unreliable replacement."
 #define ATOMIC_SET(dst, val) ((dst) = (val))
 #define ATOMIC_GET(src)      (src)
 #define ATOMIC_ADD(dst, val) ((dst) += (val))
 #define ATOMIC_SUB(dst, val) ((dst) -= (val))
#endif
