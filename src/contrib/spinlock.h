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

/*************/
/* Simple & fast atomic spinlock. Preferred. */
/* This version uses the older '__sync' builtins. */

#if defined(HAVE_SYNC_ATOMIC)

/*! \brief Spinlock lock type. */
#define KNOT_SPIN_T		bool

/*! \brief Initialize the spinlock. */
#define KNOT_SPIN_INIT(lock)	*lock = false

/*! \brief Destroy the spinlock. */
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */

/*! \brief Lock the spinlock. */
#define KNOT_SPIN_LOCK(lock)	while (__sync_lock_test_and_set(lock, 1)) {}

/*! \brief Unlock the spinlock. */
#define KNOT_SPIN_UNLOCK(lock)	(__sync_lock_release(lock))


/*************/
/* Simple & fast atomic spinlock by newer specs. */
/* This version uses the newer '__atomic' builtins. It is more expensive and ugly. */

#elif defined(HAVE_ATOMIC)

#define KNOT_SPIN_T		bool
#define KNOT_SPIN_INIT(lock)	*lock = false
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	\
	int expected = 0; \
	while (!__atomic_compare_exchange_n(lock, &expected, 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) { \
		expected = 0; \
	}
#define KNOT_SPIN_UNLOCK(lock)	(__atomic_clear(lock, __ATOMIC_RELAXED))


/*************/
/* A macOS spinlock, as a fallback. */

#elif defined(__APPLE__)

#include <libkern/OSAtomic.h>

#define KNOT_SPIN_T		OSSpinLock
#define KNOT_SPIN_INIT(lock)	*lock = OS_SPINLOCK_INIT
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	(OSSpinLockLock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(OSSpinLockUnlock(lock))


/*************/
/* A new macOS (version 10.12+) spinlock, as a fallback. */

/* XXX The exact macOS version needs to be autodetected. */
/* XXX Not used so far. */
#elif defined(__APPLE__) && !defined(__APPLE__)

#include <os/lock.h>

#define KNOT_SPIN_T		os_unfair_lock
#define KNOT_SPIN_INIT(lock)	*lock = 0
#define KNOT_SPIN_DESTROY(lock)	/* Nothing. */
#define KNOT_SPIN_LOCK(lock)	(os_unfair_lock_lock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(os_unfair_lock_unlock(lock))


/*************/
/* A POSIX pthread spinlock, as a fallback. */

#else

#include <pthread.h>

#define KNOT_SPIN_T		pthread_spinlock_t
#define KNOT_SPIN_INIT(lock)	(pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE))
#define KNOT_SPIN_DESTROY(lock)	(pthread_spin_destroy(lock))
#define KNOT_SPIN_LOCK(lock)	(pthread_spin_lock(lock))
#define KNOT_SPIN_UNLOCK(lock)	(pthread_spin_unlock(lock))

#endif

