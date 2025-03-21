/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
} worker_task_t;

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
void worker_queue_enqueue(worker_queue_t *queue, worker_task_t *task);

/*!
 * \brief Remove item from the queue.
 *
 * \return Task or NULL if the queue is empty.
 */
worker_task_t *worker_queue_dequeue(worker_queue_t *queue);

/*!
 * \brief Return number of tasks in worker queue.
 */
size_t worker_queue_length(worker_queue_t *queue);
