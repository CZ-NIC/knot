/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/worker/queue.h"

struct worker_pool;
typedef struct worker_pool worker_pool_t;

/*!
 * \brief Initialize worker pool.
 *
 * \param threads  Number of threads to be created.
 *
 * \return Thread pool or NULL in case of error.
 */
worker_pool_t *worker_pool_create(unsigned threads);

/*!
 * \brief Destroy the worker pool.
 */
void worker_pool_destroy(worker_pool_t *pool);

/*!
 * \brief Start all threads in the worker pool.
 */
void worker_pool_start(worker_pool_t *pool);

/*!
 * \brief Stop processing of new tasks, start stopping worker threads when possible.
 */
void worker_pool_stop(worker_pool_t *pool);

/*!
 * \brief Temporarily suspend the execution of worker pool.
 */
void worker_pool_suspend(worker_pool_t *pool);

/*!
 * \brief Resume the execution of worker pool.
 */
void worker_pool_resume(worker_pool_t *pool);

/*!
 * \brief Wait for all threads to terminate.
 */
void worker_pool_join(worker_pool_t *pool);

/*!
 * \brief Wait till the number of pending tasks is zero.
 *
 */
void worker_pool_wait(worker_pool_t *pool);

/*!
 * \brief Assign a task to be performed by a worker in the pool.
 */
void worker_pool_assign(worker_pool_t *pool, struct task *task);

/*!
 * \brief Clear all tasks enqueued in pool processing queue.
 */
void worker_pool_clear(worker_pool_t *pool);

/*!
 * \brief Obtain info regarding how the pool is busy.
 */
void worker_pool_status(worker_pool_t *pool, int *running, int *queued);
