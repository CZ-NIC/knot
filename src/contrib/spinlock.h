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

#if (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
/* XXX Not tested and activated yet. */
/* #define STDATOMIC_LIB */
#endif

#if defined(__APPLE__)
#if defined(MAC_OS_X_VERSION_10_12) ||
    MAC_OS_X_VERSION_MAX_ALLOWED >= MAC_OS_X_VERSION_10_12
#define APPLE_NEW
#else
#define APPLE_OLD
#endif	/* MAC_OS_X_VERSION_10_12 ... */
#endif	/* __APPLE__ */

#if defined(STDATOMIC_LIB)
#include <stdatomic.h>
#elif defined(APPLE_NEW)
#include <os/lock.h>
#elif defined(APPLE_OLD)
#include <libkern/OSAtomic.h>
#else	/* POSIX pthread spinlock. */
#include <pthread.h>
#endif

/*! \brief Spinlock lock variable type. */
typedef
#if defined(HAVE_SYNC_ATOMIC) || defined(HAVE_ATOMIC)
	bool			/*!< Spinlock lock - a simple & fast atomic version. */
#elif defined(STDATOMIC_LIB)
	atomic_bool		/*!< Spinlock lock - a simple & fast atomic version, C11 */
#elif defined(APPLE_NEW)
	os_unfair_lock		/*!< Spinlock lock - a newer macOS version (macOS >= 10.12). */
#elif defined(APPLE_OLD)
	OSSpinLock		/*!< Spinlock lock - an older macOS version (macOS < 10.12). */
#else	/* POSIX */
	pthread_spinlock_t	/*!< Spinlock lock - a POSIX pthread version. */
#endif
	knot_spin_t;

/*! \brief Initialize the spinlock pointed to by the parameter "lock". */
void static inline knot_spin_init(knot_spin_t *lock)
{
#if defined(HAVE_SYNC_ATOMIC) || defined(HAVE_ATOMIC)
	*lock = false;
#elif defined(STDATOMIC_LIB)
	atomic_init(lock, false);
#elif defined(APPLE_NEW)
	*lock = OS_UNFAIR_LOCK_INIT;
#elif defined(APPLE_OLD)
	*lock = OS_SPINLOCK_INIT;
#else	/* POSIX */
	pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
#endif
}

/*! \brief Destroy the spinlock pointed to by the parameter "lock". */
void static inline knot_spin_destroy(knot_spin_t *lock)
{
#if defined(HAVE_SYNC_ATOMIC) || defined(HAVE_ATOMIC) || defined(STDATOMIC_LIB) || \
    defined(APPLE_NEW) || defined(APPLE_OLD)
	/* Nothing needed here. */
#else	/* POSIX */
	pthread_spin_destroy(lock);
#endif
}

/*! \brief Lock the spinlock pointed to by the parameter "lock". */
void static inline knot_spin_lock(knot_spin_t *lock)
{
#if defined(HAVE_SYNC_ATOMIC)
	while (__sync_lock_test_and_set(lock, 1)) {
	}
#elif defined(HAVE_ATOMIC)
	int expected = 0;
        while (!__atomic_compare_exchange_n(lock, &expected, 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		expected = 0;
	}
#elif defined(STDATOMIC_LIB)
	int expected = 0;
	while (!atomic_compare_exchange_strong(lock, &expected, false)) {
		expected = 0;
	}
#elif defined(APPLE_NEW)
	os_unfair_lock_lock(lock);
#elif defined(APPLE_OLD)
	OSSpinLockLock(lock);
#else	/* POSIX */
	pthread_spin_lock(lock);
#endif
}

/*! \brief Unlock the spinlock pointed to by the parameter "lock". */
void static inline knot_spin_unlock(knot_spin_t *lock)
{
#if defined(HAVE_SYNC_ATOMIC)
	__sync_lock_release(lock);
#elif defined(HAVE_ATOMIC)
	__atomic_clear(lock, __ATOMIC_RELAXED);
#elif defined(STDATOMIC_LIB)
	atomic_store(lock, false);
#elif defined(APPLE_NEW)
	os_unfair_lock_unlock(lock);
#elif defined(APPLE_OLD)
	OSSpinLockUnlock(lock);
#else	/* POSIX */
	pthread_spin_unlock(lock);
#endif
}

