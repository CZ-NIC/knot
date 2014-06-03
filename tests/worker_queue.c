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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <tap/basic.h>

#include "knot/worker/queue.h"

int main(void)
{
	plan_lazy();

	task_t task_one = { 0 };
	task_t task_two = { 0 };
	task_t task_three = { 0 };

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
