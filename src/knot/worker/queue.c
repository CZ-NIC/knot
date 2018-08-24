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

void worker_queue_enqueue(worker_queue_t *queue, task_t *task)
{
	if (!queue || !task) {
		return;
	}

	ptrlist_add(&queue->list, task, &queue->mm_ctx);
}

task_t *worker_queue_dequeue(worker_queue_t *queue)
{
	if (!queue) {
		return NULL;
	}

	task_t *task = NULL;

	if (!EMPTY_LIST(queue->list)) {
		ptrnode_t *node = HEAD(queue->list);
		task = (void *)node->d;
		rem_node(&node->n);
		queue->mm_ctx.free(&node->n);
	}

	return task;
}
