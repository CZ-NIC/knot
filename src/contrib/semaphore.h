/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
} knot_sem_nonposix_t;

typedef struct {
	int status;
	union {
		sem_t semaphore;
		knot_sem_nonposix_t *status_lock;
	};
} knot_sem_t;

/*!
 * \brief Initialize semaphore by using POSIX sem_t if possible, custom value/mutex/cond structure otherwise.
 */
void knot_sem_init(knot_sem_t *sem, int value);

/*!
 * \brief Initialize semaphore, force using nonposix variant.
 */
void knot_sem_init_nonposix(knot_sem_t *sem, int value);

/*!
 * \brief Set semaphore value to specified value.
 * \note This can be only used with nonposix semaphore.
 */
void knot_sem_reset(knot_sem_t *sem, int value);

/*!
 * \brief Lock the semaphore (decrement), block until it's non-negative.
 */
void knot_sem_wait(knot_sem_t *sem);

/*!
 * \brief Lock the semaphore (decrement), block until it's non-negative but only for a maximum of given number of milliseconds.
 *
 * \param sem      Semapthore.
 * \param millis   Timeout in milliseconds or 0 for infinity (same as knot_sem_wait).
 *
 * \return True if semaphore acquired, false if timeout passed.
 */
bool knot_sem_timedwait(knot_sem_t *sem, unsigned long millis);

/*!
 * \brief Block until the semaphore could decrement, but keep the value unchanged.
 * \note This can be only used with nonposix semaphore.
 */
void knot_sem_wait_post(knot_sem_t *sem);

/*!
 * \brief Force-lock the semaphore without blocking, it might get negative.
 * \note This can be only used with nonposix semaphore.
 */
void knot_sem_get_ahead(knot_sem_t *sem);

/*!
 * \brief Lock the semaphore, abort() if it would block.
 * \note This can be only used with nonposix semaphore.
 */
void knot_sem_get_assert(knot_sem_t *sem);

/*!
 * \brief Unlock the semaphore (increment).
 */
void knot_sem_post(knot_sem_t *sem);

/*!
 * \brief Uninitialize the semaphore. Calls knot_sem_wait once at the beginning.
 */
void knot_sem_destroy(knot_sem_t *sem);
