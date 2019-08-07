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

#include <pthread.h>
#ifdef __APPLE__
#include <libkern/OSAtomic.h>
#endif /* __APPLE__ */

/*! \brief Portable spinlock lock type. */
typedef
#if defined (HAVE_ATOMIC) || defined (HAVE_SYNC_ATOMIC)
	bool			/*!< Spinlock lock - a simple & fast atomic version. */
#elif defined (__APPLE__)
	OSSpinLock		/*!< Spinlock lock - an OS X version. */
#else
	pthread_spinlock_t	/*!< Spinlock lock - a pthread version. */
#endif
	knot_spinlock_t;

/*! \brief Initialize the spinlock. */
void inline knot_spin_init(knot_spinlock_t *lock)
{
#if defined(HAVE_ATOMIC) || defined (HAVE_SYNC_ATOMIC)
	lock = false;
#elif defined (__APPLE__)
	lock = 0;
#else	/* POSIX pthread spinlock. */
	pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
#endif
}

/*! \brief Destroy the spinlock. */
void inline knot_spin_destroy(knot_spinlock_t *lock)
{
#if defined(HAVE_ATOMIC) || defined (HAVE_SYNC_ATOMIC)
	/* Nothing needed here. */
#elif defined (__APPLE__)
	/* Nothing needed here. */
#else   /* POSIX pthread spinlock. */
	pthread_spin_destroy(lock);
#endif
}

/*! \brief Lock the spinlock. */
void inline knot_spin_lock(knot_spinlock_t *lock)
{
#if defined (HAVE_SYNC_ATOMIC)
	while (__sync_lock_test_and_set(lock, 1)) {
	}
#elif defined (HAVE_ATOMIC)
	/* This version uses the newer '__atomic' builtins and it is expensive and ugly. */
	int expected = 0;
	while (!__atomic_compare_exchange_n(lock, &expected, 1, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		expected = 0;
	}
#elif defined (__APPLE__)
	OSSpinLockLock(lock);
#else	/* POSIX pthread spinlock. */
	pthread_spin_lock(lock);
#endif
}

/*! \brief Unlock the spinlock. */
void inline knot_spin_unlock(knot_spinlock_t *lock)
{
#if defined (HAVE_SYNC_ATOMIC)
	__sync_lock_release(lock);
#elif defined (HAVE_ATOMIC)
	__atomic_clear(lock, __ATOMIC_RELAXED);
#elif defined (__APPLE__)
	OSSpinLockUnlock(lock);
#else	/* POSIX pthread spinlock. */
	pthread_spin_unlock(lock);
#endif
}

