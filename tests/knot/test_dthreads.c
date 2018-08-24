/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <tap/basic.h>

#include "knot/server/dthreads.h"

/* Unit runnable data. */
static pthread_mutex_t _runnable_mx;
static volatile int _runnable_i = 0;
static const int _runnable_cycles = 10000;

/*! \brief Unit runnable. */
int runnable(struct dthread *thread)
{
	for (int i = 0; i < _runnable_cycles; ++i) {

		// Increase counter
		pthread_mutex_lock(&_runnable_mx);
		++_runnable_i;
		pthread_mutex_unlock(&_runnable_mx);

		// Cancellation point
		if (dt_is_cancelled(thread)) {
			break;
		}

		// Yield
		sched_yield();
	}

	return 0;
}

/* Destructor data. */
static volatile int _destructor_data = 0;
static pthread_mutex_t _destructor_mx;

/*! \brief Thread destructor. */
int destruct(struct dthread *thread)
{
	pthread_mutex_lock(&_destructor_mx);
	_destructor_data += 1;
	pthread_mutex_unlock(&_destructor_mx);

	return 0;
}

// Signal handler
static void interrupt_handle(int s)
{
}

/*! API: run tests. */
int main(int argc, char *argv[])
{
	plan(8);

	// Register service and signal handler
	struct sigaction sa;
	sa.sa_handler = interrupt_handle;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL); // Interrupt

	/* Initialize */
	srand(time(NULL));
	pthread_mutex_init(&_runnable_mx, NULL);
	pthread_mutex_init(&_destructor_mx, NULL);

	/* Test 1: Create unit */
	int size = 2;
	dt_unit_t *unit = dt_create(size, &runnable, NULL, NULL);
	ok(unit != NULL, "dthreads: create unit (size %d)", size);
	if (unit == NULL) {
		skip_block(7, "No dthreads unit");
		goto skip_all;
	}

	/* Test 2: Start tasks. */
	_runnable_i = 0;
	ok(dt_start(unit) == 0, "dthreads: start single task");

	/* Test 3: Wait for tasks. */
	ok(dt_join(unit) == 0, "dthreads: join threads");

	/* Test 4: Compare counter. */
	int expected = _runnable_cycles * 2;
	is_int(expected, _runnable_i, "dthreads: result ok");

	/* Test 5: Deinitialize */
	dt_delete(&unit);
	ok(unit == NULL, "dthreads: delete unit");

	/* Test 6: Wrong values. */
	unit = dt_create(-1, NULL, NULL, NULL);
	ok(unit == NULL, "dthreads: create with negative count");

	/* Test 7: NULL operations crashing. */
	int ret = 0;
	ret += dt_activate(0);
	ret += dt_cancel(0);
	ret += dt_compact(0);
	dt_delete(0);
	ret += dt_is_cancelled(0);
	ret += dt_join(0);
	ret += dt_signalize(0, SIGALRM);
	ret += dt_start(0);
	ret += dt_stop(0);
	ret += dt_unit_lock(0);
	ret += dt_unit_unlock(0);
	is_int(-198, ret, "dthreads: correct values when passed NULL context");

	/* Test 8: Thread destructor. */
	_destructor_data = 0;
	unit = dt_create(2, 0, destruct, 0);
	dt_start(unit);
	dt_stop(unit);
	dt_join(unit);
	is_int(2, _destructor_data, "dthreads: destructor with dt_create_coherent()");
	dt_delete(&unit);

skip_all:

	pthread_mutex_destroy(&_runnable_mx);
	pthread_mutex_destroy(&_destructor_mx);
	return 0;
}
