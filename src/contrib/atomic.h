/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifdef HAVE_C11_ATOMIC           /* C11 */
 #define KNOT_HAVE_ATOMIC

 #include <stdatomic.h>

 #define ATOMIC_INIT(dst, val) atomic_store_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_DEINIT(dst)
 #define ATOMIC_SET(dst, val)  atomic_store_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_GET(src)       atomic_load_explicit(&(src), memory_order_relaxed)
 #define ATOMIC_ADD(dst, val)  (void)atomic_fetch_add_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_SUB(dst, val)  (void)atomic_fetch_sub_explicit(&(dst), (val), memory_order_relaxed)
 #define ATOMIC_XCHG(dst, val) atomic_exchange_explicit(&(dst), (val), memory_order_relaxed)

 typedef atomic_uint_fast16_t knot_atomic_uint16_t;
 typedef atomic_uint_fast64_t knot_atomic_uint64_t;
 typedef atomic_size_t knot_atomic_size_t;
 typedef _Atomic (void *) knot_atomic_ptr_t;
 typedef atomic_bool knot_atomic_bool;
#elif defined(HAVE_GCC_ATOMIC)   /* GCC __atomic */
 #define KNOT_HAVE_ATOMIC

 #include <stdint.h>
 #include <stdbool.h>
 #include <stddef.h>

 #define ATOMIC_INIT(dst, val) __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_DEINIT(dst)
 #define ATOMIC_SET(dst, val)  __atomic_store_n(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_GET(src)       __atomic_load_n(&(src), __ATOMIC_RELAXED)
 #define ATOMIC_ADD(dst, val)  __atomic_add_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_SUB(dst, val)  __atomic_sub_fetch(&(dst), (val), __ATOMIC_RELAXED)
 #define ATOMIC_XCHG(dst, val) __atomic_exchange_n(&(dst), (val), __ATOMIC_RELAXED)

 typedef uint16_t knot_atomic_uint16_t;
 typedef uint64_t knot_atomic_uint64_t;
 typedef size_t knot_atomic_size_t;
 typedef void* knot_atomic_ptr_t;
 typedef bool knot_atomic_bool;
#else                            /* Fallback using spinlocks. Much slower. */
 #define KNOT_HAVE_ATOMIC

 #include <stdint.h>
 #include <stdbool.h>
 #include <stddef.h>

 #include "contrib/spinlock.h"

 #define ATOMIC_SET(dst, val) ({ \
	knot_spin_lock((knot_spin_t *)&(dst).lock); \
	(dst).value.vol = (val); \
	knot_spin_unlock((knot_spin_t *)&(dst).lock); \
 })

 #define ATOMIC_INIT(dst, val) ({ \
	knot_spin_init((knot_spin_t *)&(dst).lock); \
	ATOMIC_SET(dst, val); \
 })

 #define ATOMIC_DEINIT(dst) ({ \
	knot_spin_destroy((knot_spin_t *)&(dst).lock); \
 })

 #define ATOMIC_GET(src) ({ \
	knot_spin_lock((knot_spin_t *)&(src).lock); \
	typeof((src).value.non_vol) _z = (typeof((src).value.non_vol))(src).value.vol; \
	knot_spin_unlock((knot_spin_t *)&(src).lock); \
	_z; \
 })

 #define ATOMIC_ADD(dst, val) ({ \
	knot_spin_lock((knot_spin_t *)&(dst).lock); \
	(dst).value.vol += (val); \
	knot_spin_unlock((knot_spin_t *)&(dst).lock); \
 })

 #define ATOMIC_SUB(dst, val) ({ \
	knot_spin_lock((knot_spin_t *)&(dst).lock); \
	(dst).value.vol -= (val); \
	knot_spin_unlock((knot_spin_t *)&(dst).lock); \
 })

 #define ATOMIC_XCHG(dst, val) ({ \
	knot_spin_lock((knot_spin_t *)&(dst).lock); \
	typeof((dst).value.non_vol) _z = (typeof((dst).value.non_vol))(dst).value.vol; \
	(dst).value.vol = (val); \
	knot_spin_unlock((knot_spin_t *)&(dst).lock); \
	_z; \
 })

 #define ATOMIC_T(x) struct { \
	knot_spin_t lock; \
	union { \
		volatile x vol; \
		x non_vol; \
	} value; \
 }

 typedef ATOMIC_T(uint16_t) knot_atomic_uint16_t;
 typedef ATOMIC_T(uint64_t) knot_atomic_uint64_t;
 typedef ATOMIC_T(size_t) knot_atomic_size_t;
 typedef ATOMIC_T(void*) knot_atomic_ptr_t;
 typedef ATOMIC_T(bool) knot_atomic_bool;
#endif
