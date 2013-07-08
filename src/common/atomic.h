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
 * \file atomic.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Compatibility layer for atomic operations.
 *
 * Supports both __atomic and __sync legacy code.
 * Based on the code bits from queue by Rusty Russel <rusty@rustcorp.com.au>.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_ATOMIC_H_
#define _KNOTD_ATOMIC_H_

#include <stdbool.h>
#if defined(__ATOMIC_SEQ_CST)  /* GCC4.7+ supports C11 atomics. */

static inline unsigned int read_once(unsigned int *ptr, int memmodel)
{
	return __atomic_load_n(ptr, memmodel);
}

static inline void *read_ptr(void **ptr, int memmodel)
{
	return __atomic_load_n(ptr, memmodel);
}

static inline void store_once(unsigned int *ptr, unsigned int val, int memmodel)
{
	__atomic_store_n(ptr, val, memmodel);
}

static inline void store_ptr(void **ptr, void *val, int memmodel)
{
	__atomic_store_n(ptr, val, memmodel);
}

static inline void atomic_inc(unsigned int *val, int memmodel)
{
	__atomic_add_fetch(val, 1, memmodel);
}

static inline void atomic_dec(unsigned int *val, int memmodel)
{
	__atomic_sub_fetch(val, 1, memmodel);
}

static inline bool compare_and_swap(unsigned int *ptr,
	                            unsigned int old, unsigned int nval, int memmodel)
{
	return __atomic_compare_exchange_n(ptr, &old, nval, false,
					   memmodel, memmodel);
}

#else /* Legacy __sync interface */

#if defined(__i386__) || defined(__i686__) || defined(__amd64__)
static inline void mb(void) /* mfence compatible */
{
	asm volatile ("mfence" : : : "memory");
}
#else                       /* last resort for other architectures */
static inline void mb(void)
{
	__sync_synchronize();
}
#endif

/* Define as full barrier. */
#undef __ATOMIC_SEQ_CST
#undef __ATOMIC_RELAXED
#undef __ATOMIC_ACQUIRE
#undef __ATOMIC_RELEASE
#define __ATOMIC_SEQ_CST 1
#define __ATOMIC_RELAXED 1
#define __ATOMIC_ACQUIRE 1
#define __ATOMIC_RELEASE 0

static inline unsigned int read_once(unsigned int *ptr, int memmodel)
{
	return __sync_fetch_and_add(ptr, 0);
}

static inline void *read_ptr(void **ptr, int memmodel)
{
	return __sync_fetch_and_add(ptr, 0);
}

static inline void store_once(unsigned int *ptr, unsigned int val, int memmodel)
{
	*(volatile unsigned int *)ptr = val;
	if (memmodel)
		mb();
}

static inline void store_ptr(void **ptr, void *val, int memmodel)
{
	*(void * volatile *)ptr = val;
	if (memmodel)
		mb();
}

static inline void atomic_inc(unsigned int *val, int memmodel)
{
	__sync_fetch_and_add(val, 1);
}

static inline void atomic_dec(unsigned int *val, int memmodel)
{
	__sync_fetch_and_sub(val, 1);
}

static inline bool compare_and_swap(unsigned int *ptr,
                                    unsigned int old, unsigned int nval, int memmodel)
{
	return __sync_bool_compare_and_swap(ptr, old, nval);
}

#endif

#endif /* _KNOTD_ATOMIC_H_ */

/*! @} */
