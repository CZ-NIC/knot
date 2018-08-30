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

#include <tap/basic.h>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <time.h>

#include "knot/worker/pool.h"
#include "knot/worker/queue.h"

#define THREADS 4
#define TASKS_BATCH 40

/*!
 * Task execution log.
 */
typedef struct task_log {
	pthread_mutex_t mx;
	unsigned executed;
} task_log_t;

/*!
 * Get number of executed tasks and clear.
 */
static unsigned executed_reset(task_log_t *log)
{
	pthread_mutex_lock(&log->mx);
	unsigned result = log->executed;
	log->executed = 0;
	pthread_mutex_unlock(&log->mx);

	return result;
}

/*!
 * Simple task, just increases the counter in the log.
 */
static void task_counting(task_t *task)
{
	task_log_t *log = task->ctx;

	pthread_mutex_lock(&log->mx);
	log->executed += 1;
	pthread_mutex_unlock(&log->mx);
}

static void interrupt_handle(int s)
{
}

int main(void)
{
	plan_lazy();

	struct sigaction sa;
	sa.sa_handler = interrupt_handle;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL); // Interrupt

	// create pool

	worker_pool_t *pool = worker_pool_create(THREADS);
	ok(pool != NULL, "create worker pool");
	if (!pool) {
		return 1;
	}

	task_log_t log = {
		.mx = PTHREAD_MUTEX_INITIALIZER,
	};

	// schedule jobs while pool is stopped

	task_t task = { .run = task_counting, .ctx = &log };
	for (int i = 0; i < TASKS_BATCH; i++) {
		worker_pool_assign(pool, &task);
	}

	sched_yield();
	ok(executed_reset(&log) == 0, "executed count before start");

	// start and wait for finish

	worker_pool_start(pool);
	worker_pool_wait(pool);
	ok(executed_reset(&log) == TASKS_BATCH, "executed count after start");

	// add additional jobs while pool is running

	for (int i = 0; i < TASKS_BATCH; i++) {
		worker_pool_assign(pool, &task);
	}

	worker_pool_wait(pool);
	ok(executed_reset(&log) == TASKS_BATCH, "executed count after add");

	// temporary suspension

	worker_pool_suspend(pool);

	for (int i = 0; i < TASKS_BATCH; i++) {
		worker_pool_assign(pool, &task);
	}

	sched_yield();
	ok(executed_reset(&log) == 0, "executed count after suspend");

	worker_pool_resume(pool);
	worker_pool_wait(pool);
	ok(executed_reset(&log) == TASKS_BATCH, "executed count after resume");

	// try clean

	pthread_mutex_lock(&log.mx);
	for (int i = 0; i < THREADS + TASKS_BATCH; i++) {
		worker_pool_assign(pool, &task);
	}
	sched_yield();
	worker_pool_clear(pool);
	pthread_mutex_unlock(&log.mx);

	worker_pool_wait(pool);
	ok(executed_reset(&log) <= THREADS, "executed count after clear");

	// cleanup

	worker_pool_stop(pool);
	worker_pool_join(pool);
	worker_pool_destroy(pool);

	pthread_mutex_destroy(&log.mx);

	return 0;
}
