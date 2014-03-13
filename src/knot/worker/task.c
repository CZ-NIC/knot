/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@task.nic.cz>

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

#include <config.h>
#include <stdlib.h>
#include <string.h>

#include "knot/worker/task.h"

task_t *task_create(void *ctx, task_cb run)
{
	if (!ctx || !run) {
		return NULL;
	}

	task_t *task = malloc(sizeof(task_t *));
	if (!task) {
		return NULL;
	}

	memset(task, 0, sizeof(task_t));

	task->ctx = ctx;
	task->run = run;

	return task;
}

void task_free(task_t *task)
{
	if (!task) {
		return;
	}

	free(task);
}
