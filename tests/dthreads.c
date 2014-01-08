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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <pthread.h>
#include <sched.h>
#include <sys/select.h>
#include <signal.h>
#include <stdlib.h>
#include <tap/basic.h>

#include "knot/server/dthreads.h"

/* Unit runnable data. */
static pthread_mutex_t _runnable_mx;
static volatile int _runnable_i = 0;
static const int _runnable_cycles = 10000;

/*! \brief Unit runnable. */
int runnable(struct dthread_t *thread)
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
static volatile int _destructor_data;
static pthread_mutex_t _destructor_mx;

/*! \brief Thread destructor. */
int destruct(struct dthread_t *thread)
{
	pthread_mutex_lock(&_destructor_mx);
	_destructor_data += 1;
	pthread_mutex_unlock(&_destructor_mx);

	return 0;
}

/*! \brief Create unit. */
static inline dt_unit_t *dt_test_create(int size)
{
	return dt_create(size);
}

/*! \brief Assign a task. */
static inline int dt_test_single(dt_unit_t *unit)
{
	return dt_repurpose(unit->threads[0], &runnable, NULL) == 0;
}

/*! \brief Assign task to all unit threads. */
static inline int dt_test_coherent(dt_unit_t *unit)
{
	int ret = 0;
	for (int i = 0; i < unit->size; ++i) {
		ret += dt_repurpose(unit->threads[i], &runnable, NULL);
	}

	return ret == 0;
}

/*! \brief Start unit. */
static inline int dt_test_start(dt_unit_t *unit)
{
	return dt_start(unit) == 0;
}

/*! \brief Stop unit. */
static inline int dt_test_stop(dt_unit_t *unit)
{
	return dt_stop(unit);
}

/*! \brief Join unit. */
static inline int dt_test_join(dt_unit_t *unit)
{
	return dt_join(unit) == 0;
}

// Signal handler
static void interrupt_handle(int s)
{
}

/*! API: run tests. */
int main(int argc, char *argv[])
{
	plan(15);

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
	dt_unit_t *unit = dt_test_create(2);
	ok(unit != 0, "dthreads: create unit (optimal size %d)", unit->size);
	if (unit == 0) {
		skip_block(17, "No dthreads unit");
		goto skip_all;
	}

	/* Test 2: Assign a single task. */
	ok(dt_test_single(unit), "dthreads: assign single task");

	/* Test 3: Start tasks. */
	_runnable_i = 0;
	ok(dt_test_start(unit), "dthreads: start single task");

	/* Test 4: Wait for tasks. */
	ok(dt_test_join(unit), "dthreads: join threads");

	/* Test 5: Compare counter. */
	int expected = _runnable_cycles * 1;
	is_int(expected, _runnable_i, "dthreads: result ok");

	/* Test 6: Repurpose threads. */
	_runnable_i = 0;
	ok(dt_test_coherent(unit), "dthreads: repurpose to coherent");

	/* Test 7: Restart threads. */
	ok(dt_test_start(unit), "dthreads: start coherent unit");

	/* Test 8: Wait for tasks. */
	ok(dt_test_join(unit), "dthreads: join threads");
	
	/* Test 9: Deinitialize */
	dt_delete(&unit);
	ok(unit == NULL, "dthreads: delete unit");

	/* Test 10: Wrong values. */
	unit = dt_create(-1);
	ok(unit == NULL, "dthreads: create with negative count");
	unit = dt_create_coherent(dt_optimal_size(), 0, 0, 0);

	/* Test 11: NULL runnable. */
	is_int(0, dt_start(unit), "dthreads: start with NULL runnable");

	/* Test 12: NULL operations crashing. */
	int op_count = 14;
	int expected_min = op_count * -1;
	// All functions must return -1 at least
	int ret = 0;
	ret += dt_activate(0);              // -1
	ret += dt_cancel(0);                // -1
	ret += dt_compact(0);               // -1
	dt_delete(0);                //
	ret += dt_is_cancelled(0);          // 0
	ret += dt_join(0);                  // -1
	ret += dt_repurpose(0, 0, 0);       // -1
	ret += dt_signalize(0, SIGALRM);    // -1
	ret += dt_start(0);                 // -1
	ret += dt_start_id(0);              // -1
	ret += dt_stop(0);                  // -1
	ret += dt_stop_id(0);               // -1
	ret += dt_unit_lock(0);             // -1
	ret += dt_unit_unlock(0);           // -1
	is_int(-1464, ret, "dthreads: not crashed while executing functions on NULL context");

	/* Test 13: expected results. */
	ok(ret <= expected_min,
	       "dthreads: correct values when passed NULL context "
	       "(%d, min: %d)", ret, expected_min);

	/* Test 14: Thread destructor. */
	_destructor_data = 0;
	unit = dt_create_coherent(2, 0, destruct, 0);
	dt_start(unit);
	dt_stop(unit);
	dt_join(unit);
	is_int(2, _destructor_data, "dthreads: destructor with dt_create_coherent()");
	dt_delete(&unit);

	/* Test 15: Thread destructor setter. */
	unit = dt_create(1);
	dt_set_desctructor(unit->threads[0], destruct);
	dt_start(unit);
	dt_stop(unit);
	dt_join(unit);
	is_int(3, _destructor_data, "dthreads: destructor with dt_set_desctructor()");
	dt_delete(&unit);

skip_all:

	pthread_mutex_destroy(&_runnable_mx);
	pthread_mutex_destroy(&_destructor_mx);
	return 0;
}
