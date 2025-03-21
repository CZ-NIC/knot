/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
