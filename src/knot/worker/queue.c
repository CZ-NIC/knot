/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "knot/worker/queue.h"
#include "contrib/mempattern.h"

void worker_queue_init(worker_queue_t *queue)
{
	if (!queue) {
		return;
	}

	memset(queue, 0, sizeof(worker_queue_t));

	init_list(&queue->list);
	mm_ctx_init(&queue->mm_ctx);
}

void worker_queue_deinit(worker_queue_t *queue)
{
	ptrlist_free(&queue->list, &queue->mm_ctx);
}

void worker_queue_enqueue(worker_queue_t *queue, worker_task_t *task)
{
	if (!queue || !task) {
		return;
	}

	ptrlist_add(&queue->list, task, &queue->mm_ctx);
}

worker_task_t *worker_queue_dequeue(worker_queue_t *queue)
{
	if (!queue) {
		return NULL;
	}

	worker_task_t *task = NULL;

	if (!EMPTY_LIST(queue->list)) {
		ptrnode_t *node = HEAD(queue->list);
		task = (void *)node->d;
		rem_node(&node->n);
		queue->mm_ctx.free(&node->n);
	}

	return task;
}

size_t worker_queue_length(worker_queue_t *queue)
{
	return queue ? list_size(&queue->list) : 0;
}
