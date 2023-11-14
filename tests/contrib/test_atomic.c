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
#define CYCLES1 100000
#define CYCLES2 2000000
#define UPPER 0xffffffff00000000
#define LOWER 0x00000000ffffffff

static volatile knot_atomic_uint64_t counter_add = 0;
static volatile knot_atomic_uint64_t counter_sub = 0;
static volatile knot_atomic_uint64_t atomic_var;
static int errors_set_get = 0;

static int thread_add(struct dthread *thread)
{
	for (int i = 0; i < CYCLES1; i++) {
		ATOMIC_ADD(counter_add, 7);
		ATOMIC_SUB(counter_sub, 7);
	}

	return 0;
}

static int thread_set(struct dthread *thread)
{
	u_int64_t val = (dt_get_id(thread) % 2) ? UPPER : LOWER;

	for (int i = 0; i < CYCLES2; i++) {
		ATOMIC_SET(atomic_var, val);
		volatile u_int64_t read = ATOMIC_GET(atomic_var);
		if (read != UPPER && read != LOWER) {
			// Non-atomic counter, won't be accurate!
			// However, it's sufficient for fault detection.
			errors_set_get++;
		}
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

	// Test for atomicity of ATOMIC_ADD and ATOMIC_SUB.
	dt_unit_t *unit = dt_create(THREADS, thread_add, NULL, NULL);
	dt_start(unit);
	dt_join(unit);
	dt_delete(&unit);

	is_int(THREADS * CYCLES1 * 7,  counter_add, "atomicity of ATOMIC_ADD");
	is_int(THREADS * CYCLES1 * 7, -counter_sub, "atomicity of ATOMIC_SUB");

	// Test for atomicity of ATOMIC_SET and ATOMIC_GET.
	unit = dt_create(THREADS, thread_set, NULL, NULL);
	dt_start(unit);
	dt_join(unit);
	dt_delete(&unit);

	is_int(0, errors_set_get, "atomicity of ATOMIC_SET / ATOMIC_GET");

	return 0;
}
