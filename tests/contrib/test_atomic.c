/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <signal.h>
#include <tap/basic.h>

#include "contrib/atomic.h"
#include "knot/server/dthreads.h"

#define THREADS 16
#define CYCLES 100000

static volatile long int counter_add = 0;
static volatile long int counter_sub = 0;

static int thread(struct dthread *thread)
{
	int i;

	for (i = 0; i < CYCLES; i++) {
		ATOMIC_ADD(counter_add, 7);
		ATOMIC_SUB(counter_sub, 7);
	}

	return 0;
}

// Signal handler
static void interrupt_handle(int s)
{
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// Register service and signal handler
	struct sigaction sa;
	sa.sa_handler = interrupt_handle;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL); // Interrupt

	dt_unit_t *unit = dt_create(THREADS, thread, NULL, NULL);
	dt_start(unit);
	dt_join(unit);
	dt_delete(&unit);

	is_int(THREADS * CYCLES * 7,  counter_add, "atomicity of ATOMIC_ADD");
	is_int(THREADS * CYCLES * 7, -counter_sub, "atomicity of ATOMIC_SUB");

	return 0;
}
