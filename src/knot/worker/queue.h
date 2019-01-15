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

#include "contrib/ucw/lists.h"

struct task;
typedef void (*task_cb)(struct task *);

/*!
 * \brief Task executable by a worker.
 */
typedef struct task {
	void *ctx;
	task_cb run;
} task_t;

/*!
 * \brief Worker queue.
 */
typedef struct worker_queue {
	knot_mm_t mm_ctx;
	list_t list;
} worker_queue_t;

/*!
 * \brief Initialize worker queue.
 */
void worker_queue_init(worker_queue_t *queue);

/*!
 * \brief Deinitialize worker queue.
 */
void worker_queue_deinit(worker_queue_t *queue);

/*!
 * \brief Insert new item into the queue.
 */
void worker_queue_enqueue(worker_queue_t *queue, task_t *task);

/*!
 * \brief Remove item from the queue.
 *
 * \return Task or NULL if the queue is empty.
 */
task_t *worker_queue_dequeue(worker_queue_t *queue);

/*!
 * \brief Return number of tasks in worker queue.
 */
size_t worker_queue_length(worker_queue_t *queue);
