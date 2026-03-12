/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief C11 atomic operations with fallbacks.
 */

#pragma once

#ifdef HAVE_C11_ATOMIC           /* C11 */
 #include <stdatomic.h>

 #define MO_RELAXED memory_order_relaxed
 #define MO_CONSUME memory_order_consume
 #define MO_ACQUIRE memory_order_acquire
 #define MO_RELEASE memory_order_release
 #define MO_ACQ_REL memory_order_acq_rel
 #define MO_SEQ_CST memory_order_seq_cst

 #define ATOMIC_INIT_MO(dst, val, memorder)                       atomic_store_explicit(&(dst), (val), (memorder))
 #define ATOMIC_SET_MO(dst, val, memorder)                        atomic_store_explicit(&(dst), (val), (memorder))
 #define ATOMIC_GET_MO(src, memorder)                             atomic_load_explicit(&(src), (memorder))
 #define ATOMIC_ADD_MO(dst, val, memorder)                        (void)atomic_fetch_add_explicit(&(dst), (val), (memorder))
 #define ATOMIC_SUB_MO(dst, val, memorder)                        (void)atomic_fetch_sub_explicit(&(dst), (val), (memorder))
 #define ATOMIC_XCHG_MO(dst, val, memorder)                       atomic_exchange_explicit(&(dst), (val), (memorder))
 #define ATOMIC_CMPXCHG_MO(dst, exp, des, success_mo, failure_mo) atomic_compare_exchange_weak_explicit(&(dst), &(exp), (des), (success_mo), (failure_mo))

 #define ATOMIC_INIT(dst, val)         ATOMIC_INIT_MO(dst, val, MO_RELAXED)
 #define ATOMIC_DEINIT(dst)
 #define ATOMIC_SET(dst, val)          ATOMIC_SET_MO(dst, val, MO_RELAXED)
 #define ATOMIC_GET(src)               ATOMIC_GET_MO(src, MO_RELAXED)
 #define ATOMIC_ADD(dst, val)          ATOMIC_ADD_MO(dst, val, MO_RELAXED)
 #define ATOMIC_SUB(dst, val)          ATOMIC_SUB_MO(dst, val, MO_RELAXED)
 #define ATOMIC_XCHG(dst, val)         ATOMIC_XCHG_MO(dst, val, MO_RELAXED)
 #define ATOMIC_CMPXCHG(dst, exp, des) ATOMIC_CMPXCHG_MO(dst, exp, des, MO_SEQ_CST, MO_SEQ_CST)

 typedef atomic_uint_fast16_t knot_atomic_uint16_t;
 typedef atomic_uint_fast64_t knot_atomic_uint64_t;
 typedef atomic_ullong knot_atomic_millis_t;
 typedef atomic_size_t knot_atomic_size_t;
 typedef _Atomic (void *) knot_atomic_ptr_t;
 typedef atomic_bool knot_atomic_bool;
#elif defined(HAVE_GCC_ATOMIC)   /* GCC __atomic */
 #include <stdint.h>
 #include <stdbool.h>
 #include <stddef.h>

 #define MO_RELAXED __ATOMIC_RELAXED
 #define MO_CONSUME __ATOMIC_CONSUME
 #define MO_ACQUIRE __ATOMIC_ACQUIRE
 #define MO_RELEASE __ATOMIC_RELEASE
 #define MO_ACQ_REL __ATOMIC_ACQ_REL
 #define MO_SEQ_CST __ATOMIC_SEQ_CST

 #define ATOMIC_INIT_MO(dst, val, memorder)                       __atomic_store_n(&(dst), (val), (memorder))
 #define ATOMIC_SET_MO(dst, val, memorder)                        __atomic_store_n(&(dst), (val), (memorder))
 #define ATOMIC_GET_MO(src, memorder)                             __atomic_load_n(&(src), (memorder))
 #define ATOMIC_ADD_MO(dst, val, memorder)                        __atomic_add_fetch(&(dst), (val), (memorder))
 #define ATOMIC_SUB_MO(dst, val, memorder)                        __atomic_sub_fetch(&(dst), (val), (memorder))
 #define ATOMIC_XCHG_MO(dst, val, memorder)                       __atomic_exchange_n(&(dst), (val), (memorder))
 #define ATOMIC_CMPXCHG_MO(dst, exp, des, success_mo, failure_mo) __atomic_compare_exchange_n(&(dst), &(exp), (des), (success_mo), (failure_mo))

 #define ATOMIC_INIT(dst, val)         ATOMIC_INIT_MO(dst, val, MO_RELAXED)
 #define ATOMIC_DEINIT(dst)
 #define ATOMIC_SET(dst, val)          ATOMIC_SET_MO(dst, val, MO_RELAXED)
 #define ATOMIC_GET(src)               ATOMIC_GET_MO(src, MO_RELAXED)
 #define ATOMIC_ADD(dst, val)          ATOMIC_ADD_MO(dst, val, MO_RELAXED)
 #define ATOMIC_SUB(dst, val)          ATOMIC_SUB_MO(dst, val, MO_RELAXED)
 #define ATOMIC_XCHG(dst, val)         ATOMIC_XCHG_MO(dst, val, MO_RELAXED)
 #define ATOMIC_CMPXCHG(dst, exp, des) ATOMIC_CMPXCHG_MO(dst, exp, des, MO_SEQ_CST, MO_SEQ_CST)

 typedef uint16_t knot_atomic_uint16_t;
 typedef uint64_t knot_atomic_uint64_t;
 typedef knot_millis_t knot_atomic_millis_t;
 typedef size_t knot_atomic_size_t;
 typedef void* knot_atomic_ptr_t;
 typedef bool knot_atomic_bool;
#else                            /* Fallback using spinlocks. Much slower. */
 #include <stdint.h>
 #include <stdbool.h>
 #include <stddef.h>

 #include "contrib/spinlock.h"

#define MO_RELAXED
#define MO_CONSUME
#define MO_ACQUIRE
#define MO_RELEASE
#define MO_ACQ_REL
#define MO_SEQ_CST

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

#define ATOMIC_CMPXCHG(dst, exp, des) ({ \
	bool _z; \
	knot_spin_lock((knot_spin_t *)&(dst).lock); \
	if ((dst).value.vol == (exp)) { \
		(dst).value.vol = (des); \
		_z = true; \
	} else { \
		(exp) = (dst).value.vol; \
		_z = false; \
	} \
	knot_spin_unlock((knot_spin_t *)&(dst).lock); \
	_z; \
 })

 #define ATOMIC_INIT_MO(dst, val, memorder)                        ATOMIC_INIT(dst, val)
 #define ATOMIC_SET_MO(dst, val, memorder)                         ATOMIC_SET(dst, val)
 #define ATOMIC_GET_MO(src, memorder)                              ATOMIC_GET(src)
 #define ATOMIC_ADD_MO(dst, val, memorder)                         ATOMIC_ADD(dst, val)
 #define ATOMIC_SUB_MO(dst, val, memorder)                         ATOMIC_SUB(dst, val)
 #define ATOMIC_XCHG_MO(dst, val, memorder)                        ATOMIC_XCHG(dst, val)
 #define ATOMIC_CMPXCHG_MO(dst, val, dest, success_mo, failure_mo) ATOMIC_CMPXCHG(dst, val, dest)

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
 typedef ATOMIC_T(knot_millis_t) knot_atomic_millis_t;
 typedef ATOMIC_T(void*) knot_atomic_ptr_t;
 typedef ATOMIC_T(bool) knot_atomic_bool;
#endif
