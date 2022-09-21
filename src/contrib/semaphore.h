/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <pthread.h>
#include <semaphore.h>

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
