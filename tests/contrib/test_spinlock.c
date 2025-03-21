/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <signal.h>
#include <tap/basic.h>

#include "knot/server/dthreads.h"
#include "contrib/spinlock.h"

#define THREADS 8
#define CYCLES 100000

static volatile int counter = 0;
static volatile int tens_counter = 0;
static knot_spin_t spinlock;

static int thread(struct dthread *thread)
{
	volatile int i, j, k;

	for (i = 0; i < CYCLES; i++) {
		knot_spin_lock(&spinlock);
		j = counter;
		k = tens_counter;
		if (++j % 10 == 0) {
			k++;
		}
		tens_counter = k;
		counter = j;
		knot_spin_unlock(&spinlock);
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
	
	knot_spin_init(&spinlock);

	dt_unit_t *unit = dt_create(THREADS, thread, NULL, NULL);
	dt_start(unit);
	dt_join(unit);
	dt_delete(&unit);

	knot_spin_destroy(&spinlock);

	is_int(THREADS * CYCLES, counter, "spinlock: protected counter one");
	is_int(THREADS * CYCLES / 10, tens_counter, "spinlock: protected counter two");

	return 0;
}
