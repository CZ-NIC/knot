/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>

#include "knot/worker/queue.h"

struct worker_pool;
typedef struct worker_pool worker_pool_t;

typedef void(*wait_callback_t)(worker_pool_t *);

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
 */
void worker_pool_wait(worker_pool_t *pool);

/*!
 * \brief Wait till the number of pending tasks is zero. Callback emitted on
 *  thread wakeup can be specified.
 */
void worker_pool_wait_cb(worker_pool_t *pool, wait_callback_t cb);

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
 *
 * \note Locked means if the mutex `pool->lock` is locked.
 */
void worker_pool_status(worker_pool_t *pool, bool locked, int *running, int *queued);
