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

#include <assert.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/libknot.h"
#include "knot/server/dthreads.h"
#include "knot/worker/pool.h"

/*!
 * \brief Worker pool state.
 */
struct worker_pool {
	dt_unit_t *threads;

	pthread_mutex_t lock;
	pthread_cond_t wake;

	bool terminating;	/*!< Is the pool terminating? .*/
	bool suspended;		/*!< Is execution temporarily suspended? .*/
	int running;		/*!< Number of running threads. */
	worker_queue_t tasks;
};

/*!
 * \brief Worker thread.
 *
 * The thread takes a task from the tasks queue and runs it, while checking
 * if the dispatching of new tasks is allowed by the thread pool.
 *
 * An execution of a running thread cannot be enforced.
 *
 */
static int worker_main(dthread_t *thread)
{
	assert(thread);

	worker_pool_t *pool = thread->data;

	pthread_mutex_lock(&pool->lock);

	for (;;) {
		if (pool->terminating) {
			break;
		}

		task_t *task = NULL;
		if (!pool->suspended) {
			task = worker_queue_dequeue(&pool->tasks);
		}

		if (task == NULL) {
			pthread_cond_wait(&pool->wake, &pool->lock);
			continue;
		}

		assert(task->run);
		pool->running += 1;

		pthread_mutex_unlock(&pool->lock);
		task->run(task);
		pthread_mutex_lock(&pool->lock);

		pool->running -= 1;
		pthread_cond_broadcast(&pool->wake);
	}

	pthread_mutex_unlock(&pool->lock);

	return KNOT_EOK;
}

/* -- public API ------------------------------------------------------------ */

worker_pool_t *worker_pool_create(unsigned threads)
{
	worker_pool_t *pool = malloc(sizeof(worker_pool_t));
	if (pool == NULL) {
		return NULL;
	}

	memset(pool, 0, sizeof(worker_pool_t));
	pool->threads = dt_create(threads, worker_main, NULL, pool);
	if (pool->threads == NULL) {
		goto fail;
	}

	if (pthread_mutex_init(&pool->lock, NULL) != 0) {
		goto fail;
	}

	if (pthread_cond_init(&pool->wake, NULL) != 0) {
		goto fail;
	}

	worker_queue_init(&pool->tasks);

	return pool;

fail:
	dt_delete(&pool->threads);
	free(pool);
	return NULL;
}

void worker_pool_destroy(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	dt_delete(&pool->threads);

	pthread_mutex_destroy(&pool->lock);
	pthread_cond_destroy(&pool->wake);

	worker_queue_deinit(&pool->tasks);

	free(pool);
}

void worker_pool_start(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	dt_start(pool->threads);
}

void worker_pool_stop(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	pthread_mutex_lock(&pool->lock);
	pool->terminating = true;
	pthread_cond_broadcast(&pool->wake);
	pthread_mutex_unlock(&pool->lock);

	dt_stop(pool->threads);
}

void worker_pool_suspend(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	pthread_mutex_lock(&pool->lock);
	pool->suspended = true;
	pthread_mutex_unlock(&pool->lock);
}

void worker_pool_resume(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	pthread_mutex_lock(&pool->lock);
	pool->suspended = false;
	pthread_cond_broadcast(&pool->wake);
	pthread_mutex_unlock(&pool->lock);
}

void worker_pool_join(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	dt_join(pool->threads);
}

void worker_pool_wait(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	pthread_mutex_lock(&pool->lock);
	while (!EMPTY_LIST(pool->tasks.list) || pool->running > 0) {
		pthread_cond_wait(&pool->wake, &pool->lock);
	}
	pthread_mutex_unlock(&pool->lock);
}

void worker_pool_assign(worker_pool_t *pool, struct task *task)
{
	if (!pool || !task) {
		return;
	}

	pthread_mutex_lock(&pool->lock);
	worker_queue_enqueue(&pool->tasks, task);
	pthread_cond_signal(&pool->wake);
	pthread_mutex_unlock(&pool->lock);
}

void worker_pool_clear(worker_pool_t *pool)
{
	if (!pool) {
		return;
	}

	pthread_mutex_lock(&pool->lock);
	worker_queue_deinit(&pool->tasks);
	worker_queue_init(&pool->tasks);
	pthread_mutex_unlock(&pool->lock);
}

void worker_pool_status(worker_pool_t *pool, int *running, int *queued)
{
	if (!pool) {
		*running = *queued = 0;
		return;
	}

	pthread_mutex_lock(&pool->lock);
	*running = pool->running;
	*queued = worker_queue_length(&pool->tasks);
	pthread_mutex_unlock(&pool->lock);
}
