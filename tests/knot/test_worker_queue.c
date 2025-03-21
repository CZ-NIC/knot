/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <tap/basic.h>

#include "knot/worker/queue.h"

int main(void)
{
	plan_lazy();

	worker_task_t task_one = { 0 };
	worker_task_t task_two = { 0 };
	worker_task_t task_three = { 0 };

	// init

	worker_queue_t queue;
	worker_queue_init(&queue);
	ok(1, "queue init");

	// enqueue

	worker_queue_enqueue(&queue, &task_one);
	ok(1, "enqueue first");
	worker_queue_enqueue(&queue, &task_two);
	ok(1, "enqueue second");

	// dequeue

	ok(worker_queue_dequeue(&queue) == &task_one, "dequeue first");
	ok(worker_queue_dequeue(&queue) == &task_two, "dequeue second");
	ok(worker_queue_dequeue(&queue) == NULL, "dequeue from empty");

	// deinit

	worker_queue_enqueue(&queue, &task_three);
	ok(1, "enqueue third");

	worker_queue_deinit(&queue);
	ok(1, "queue deinit");

	return 0;
}
