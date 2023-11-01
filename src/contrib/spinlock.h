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
 * \brief A C11 spinlock (POSIX pthread spinlock as a fallback).
 */

#pragma once

#if (__STDC_VERSION__ >= 201112L) && !defined(__STDC_NO_ATOMICS__)
  #define HAVE_STDATOMIC
  #include <stdatomic.h>
  #include <stdbool.h>
#else	/* POSIX pthread spinlock. */
  #include <pthread.h>
#endif

/*! \brief Spinlock lock variable type. */
typedef
#if defined(HAVE_STDATOMIC)
	atomic_bool		/*!< Spinlock lock - a simple & fast atomic version, C11 */
#else	/* POSIX */
	pthread_spinlock_t	/*!< Spinlock lock - a POSIX pthread version. */
#endif
	knot_spin_t;

/*! \brief Initialize the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_init(knot_spin_t *lock)
{
#if defined(HAVE_STDATOMIC)
	atomic_init(lock, false);
#else	/* POSIX */
	pthread_spin_init(lock, PTHREAD_PROCESS_PRIVATE);
#endif
}

/*! \brief Destroy the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_destroy(knot_spin_t *lock)
{
#if defined(HAVE_STDATOMIC)
	/* Nothing needed here. */
#else	/* POSIX */
	pthread_spin_destroy(lock);
#endif
}

/*! \brief Lock the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_lock(knot_spin_t *lock)
{
#if defined(HAVE_STDATOMIC)
	bool expected = false;
	while (!atomic_compare_exchange_strong(lock, &expected, true)) {
		expected = false;
	}
#else	/* POSIX */
	pthread_spin_lock(lock);
#endif
}

/*! \brief Unlock the spinlock pointed to by the parameter "lock". */
static inline void knot_spin_unlock(knot_spin_t *lock)
{
#if defined(HAVE_STDATOMIC)
	atomic_store(lock, false);
#else	/* POSIX */
	pthread_spin_unlock(lock);
#endif
}
