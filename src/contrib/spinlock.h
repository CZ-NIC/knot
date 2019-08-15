/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Multiplatform spinlock.
 */

#pragma once


/*
 * This spinlock set contains the following macros:
 *
 *  KNOT_SPIN_T                  Spinlock lock variable type.
 *  KNOT_SPIN_INIT(lock)         Initialize the spinlock pointed to by the parameter "lock".
 *  KNOT_SPIN_DESTROY(lock)      Destroy the spinlock pointed to by the parameter "lock".
 *  KNOT_SPIN_LOCK(lock)         Lock the spinlock pointed to by the parameter "lock".
 *  KNOT_SPIN_UNLOCK(lock)       Unlock the spinlock pointed to by the parameter "lock".
 *
 */


#if defined(HAVE_SYNC_ATOMIC)

/*******************/
/* Simple & fast atomic spinlock. Preferred. */
/* This version uses the older '__sync' builtins. */

#define KNOT_SPIN_T		bool
#define KNOT_SPIN_INIT(lock)	*lock = false
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	while (__sync_lock_test_and_set(lock, 1)) {}
#define KNOT_SPIN_UNLOCK(lock)	(__sync_lock_release(lock))


#elif defined(HAVE_ATOMIC)

/*******************/
/* Simple & fast atomic spinlock by newer specs. */
/* This version uses the newer '__atomic' builtins. It is more expensive and ugly. */

#define KNOT_SPIN_T		bool
#define KNOT_SPIN_INIT(lock)	*lock = false
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	\
	int expected = 0; \
	while (!__atomic_compare_exchange_n(lock, &expected, 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) { \
		expected = 0; \
	}
#define KNOT_SPIN_UNLOCK(lock)	(__atomic_clear(lock, __ATOMIC_RELAXED))


#elif 0  /* if (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__) */

/*******************/
/* Simple & fast atomic spinlock by newer specs. */
/* This version uses the newer C11 <stdatomic.h> builtins. It is more expensive and ugly too. */

/* XXX Not supported yet, not tested yet. */

#include <stdatomic.h>

#define KNOT_SPIN_T		atomic_bool
#define KNOT_SPIN_INIT(lock)	atomic_init(lock, false)
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	\
	int expected = 0; \
	while (!atomic_compare_exchange_strong(lock, &expected, false)) { \
		expected = 0; \
	}
#define KNOT_SPIN_UNLOCK(lock)	(atomic_store(lock, false))


#elif defined(__APPLE__) && (defined(MAC_OS_X_VERSION_10_12) || \
	MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_12)

/*******************/
/* A new macOS (version 10.12+) spinlock, as a fallback. */

/* XXX The macOS version autodetection not tested yet. */
/* XXX It is needed to detect the run OS platform, not the compile platform! */

#include <os/lock.h>

#define KNOT_SPIN_T		os_unfair_lock
#define KNOT_SPIN_INIT(lock)	*lock = OS_UNFAIR_LOCK_INIT
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	(os_unfair_lock_lock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(os_unfair_lock_unlock(lock))


#elif defined(__APPLE__)

/*******************/
/* An older macOS spinlock, as a fallback. */

#include <libkern/OSAtomic.h>

#define KNOT_SPIN_T		OSSpinLock
#define KNOT_SPIN_INIT(lock)	*lock = OS_SPINLOCK_INIT
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	(OSSpinLockLock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(OSSpinLockUnlock(lock))


#else

/*******************/
/* A POSIX pthread spinlock, as a fallback. */

#include <pthread.h>

#define KNOT_SPIN_T		pthread_spinlock_t
#define KNOT_SPIN_INIT(lock)	(pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE))
#define KNOT_SPIN_DESTROY(lock)	(pthread_spin_destroy(lock))
#define KNOT_SPIN_LOCK(lock)	(pthread_spin_lock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(pthread_spin_unlock(lock))


#endif

