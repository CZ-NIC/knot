/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <pthread.h>
#include <signal.h>
#include <tap/basic.h>

#include "contrib/atomic.h"
#include "knot/server/dthreads.h"

#define THREADS 16
#if defined(HAVE_C11_ATOMIC) || defined(HAVE_GCC_ATOMIC)
  #define CYCLES1 100000
  #define CYCLES2 2000000
  #define CYCLES3 100000
#else
  // Spinlock-emulated atomics. Locking is much slower, enough collisions occur,
  #define CYCLES1 50000
  #define CYCLES2 100000
  #define CYCLES3 100000
#endif
#define UPPER 0xffffffff00000000
#define LOWER 0x00000000ffffffff
#define UPPER_PTR ((void *) UPPER)
#define LOWER_PTR ((void *) LOWER)

static knot_atomic_uint64_t counter_add;
static knot_atomic_uint64_t counter_sub;
static knot_atomic_uint64_t atomic_var;
static knot_atomic_ptr_t atomic_var2;
static int errors = 0;
static int uppers;
static int lowers;
static int uppers_count = 0;
static int lowers_count = 0;
static pthread_mutex_t mx;

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
			errors++;
		}
	}

	return 0;
}

static int thread_xchg(struct dthread *thread)
{
	void *val = (dt_get_id(thread) % 2) ? UPPER_PTR : LOWER_PTR;

	pthread_mutex_lock(&mx);
	if (val == UPPER_PTR) {
		uppers++;
	} else {
		lowers++;
	};
	pthread_mutex_unlock(&mx);

	for (int i = 0; i < CYCLES3; i++) {
		val = ATOMIC_XCHG(atomic_var2, val);
		if (val != UPPER_PTR && val != LOWER_PTR) {
			// Non-atomic counter, won't be accurate!
			// However, it's sufficient for fault detection.
			errors++;
			return 0;
		}
	}

	pthread_mutex_lock(&mx);
	if (val == UPPER_PTR) {
		uppers_count++;
	} else if (val == LOWER_PTR) {
		lowers_count++;
	};
	pthread_mutex_unlock(&mx);

	return 0;
}

// Signal handler
static void interrupt_handle(int s)
{
}

int main(int argc, char *argv[])
{
	plan_lazy();

	ATOMIC_INIT(counter_add, 0);
	ATOMIC_INIT(counter_sub, 0);
	ATOMIC_INIT(atomic_var, 0);
	ATOMIC_INIT(atomic_var2, NULL);

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

	is_int(THREADS * CYCLES1 * 7,  ATOMIC_GET(counter_add), "atomicity of ATOMIC_ADD");
	is_int(THREADS * CYCLES1 * 7, -ATOMIC_GET(counter_sub), "atomicity of ATOMIC_SUB");

	// Test for atomicity of ATOMIC_SET and ATOMIC_GET.
	unit = dt_create(THREADS, thread_set, NULL, NULL);
	dt_start(unit);
	dt_join(unit);
	dt_delete(&unit);

	is_int(0, errors, "atomicity of ATOMIC_SET / ATOMIC_GET");

	// Test for atomicity of ATOMIC_XCHG.
	errors = 0;
	uppers = 0; // Initialize in code so as to calm down Coverity.
	lowers = 0; // Idem.

	ATOMIC_SET(atomic_var2, UPPER_PTR);
	uppers++;

	pthread_mutex_init(&mx, NULL);
	unit = dt_create(THREADS, thread_xchg, NULL, NULL);
	dt_start(unit);
	dt_join(unit);
	dt_delete(&unit);
	pthread_mutex_destroy(&mx);

	if (ATOMIC_GET(atomic_var2) == UPPER_PTR) {
		uppers_count++;
	} else if (ATOMIC_GET(atomic_var2) == LOWER_PTR) {
		lowers_count++;
	} else {
		errors++;
	}

	is_int(0, errors, "set/get atomicity of ATOMIC_XCHG");
	is_int(uppers, uppers_count, "atomicity of ATOMIC_XCHG");
	is_int(lowers, lowers_count, "atomicity of ATOMIC_XCHG");

	ATOMIC_DEINIT(counter_add);
	ATOMIC_DEINIT(counter_sub);
	ATOMIC_DEINIT(atomic_var);
	ATOMIC_DEINIT(atomic_var2);

	return 0;
}
