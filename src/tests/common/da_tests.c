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

#include "tests/common/da_tests.h"
#include "common/dynamic-array.h"
#include <unistd.h>
#include <urcu.h>

static int da_tests_count(int argc, char *argv[]);
static int da_tests_run(int argc, char *argv[]);

/*
 * Unit API.
 */
unit_api da_tests_api = {
	"Dynamic array",
	&da_tests_count,
	&da_tests_run
};

/*
 * Unit implementation.
 */

static const int DA_TEST_COUNT = 5;
static const int RCU_THREADS   = 3;
static const int DA_FRAGMENT = 10;
static const int DA_DEF_SIZE = 1000;
static const int DA_OPERATIONS = 1000;
enum Operations {
	DA_RESERVE = 0,
	DA_OCCUPY  = 1,
	DA_RELEASE = 2,
	DA_OPCOUNT = 3
};

static int da_tests_count(int argc, char *argv[])
{
	return DA_TEST_COUNT;
}

static void do_something(int loops)
{
	int i;
	int res = 1;

	static const int LOOPS = 10000;

	for (int j = 1; j <= LOOPS; ++j) {
		for (i = 1; i <= loops; ++i) {
			res *= i;
		}
	}
}

static void *test_rcu_routine(void *obj)
{
	rcu_register_thread();
	rcu_read_lock();

	do_something(1000);

	rcu_read_unlock();
	rcu_unregister_thread();

	return NULL;
}

static int test_rcu_threads()
{
	// Create threads
	pthread_t *threads = malloc(RCU_THREADS * sizeof(pthread_t));
	for (int i = 0; i < RCU_THREADS; ++i) {
		if (pthread_create(&threads[i], NULL, test_rcu_routine, NULL)) {
			diag("rcu: failed to create thread %d", i);
			free(threads);
			return 0;
		}
	}

	// Join threads
	void *pret = NULL;
	for (int i = 0; i < RCU_THREADS; ++i) {
		if (pthread_join(threads[i], &pret)) {
			diag("rcu: failed to join thread %d", i);
			free(threads);
			return 0;
		}
	}

	synchronize_rcu();
	free(threads);

	return 1;
}

static int test_da_init(da_array_t *arr)
{
	return da_initialize(arr, DA_DEF_SIZE, sizeof(uint)) == 0;
}

static int test_da_random_op(da_array_t *arr)
{
	unsigned seed = (unsigned)time(0);
	uint allocated = DA_DEF_SIZE;
	uint size = 0;

	for (int i = 0; i < DA_OPERATIONS; ++i) {
		int r = rand_r(&seed) % DA_OPCOUNT;
		int count = rand_r(&seed) % DA_FRAGMENT + 1;

		switch (r) {

			// Perform reserve operation
		case DA_RESERVE:
			if (da_reserve(arr, count) >= 0 &&
			                size <= allocated) {
				if ((allocated - size) < count) {
					allocated *= 2;
				}
			} else {
				diag("dynamic-array: da_reserve(%p, %d) failed"
				     " (size %d, alloc'd %d)", 
				     arr, count, size, allocated);
				return 0;
			}
			break;

			// Perform occupy operation
		case DA_OCCUPY:
			if (da_occupy(arr, count) == 0) {
				uint *items = (uint *) da_get_items(arr);
				for (int j = 0; j < da_get_count(arr); ++j) {
					items[j] = rand_r(&seed);
				}
				if (size <= allocated && 
				    (allocated - size) >= count) {
					size += count;
				} else {
					return 0;
				}
			} else {
				diag("dynamic-array: da_occupy(%p, %d) failed"
				     " (size %d, alloc'd %d)",
				     arr, count, size, allocated);
				return 0;
			}
			break;

			// Perform release operation
		case DA_RELEASE:
			if (arr->count > 0) {
				count = (rand_r(&seed) % DA_FRAGMENT) % arr->count;
				da_release(arr, count);

				if (size <= allocated && size >= count) {
					size -= count;
				} else {
					return 0;
				}
			}
			break;

		default:
			break;
		}

		// Check allocated / size
		if (allocated != arr->allocated || size != arr->count) {
			diag("dynamic-array: allocated memory %d (expected %d)"
			     " size %d (expected %d) mismatch",
			     arr->allocated, allocated, arr->count, size);
			return 0;
		}
	}

	return 1;
}

void *test_da_read(void *obj)
{
	rcu_register_thread();
	rcu_read_lock();

	unsigned seed = (unsigned)time(0);
	da_array_t *arr = (da_array_t *) obj;
	int index = rand_r(&seed) % da_get_count(arr);

	note("  dynamic-array: read thread");
	note("    read thread: saving pointer to %d. item", index);
	uint *item = &((uint *) da_get_items(arr))[index];
	note("    read thread: before: pointer: %p item: %u", item, *item);

	do_something(100000);

	note("    read thread after: pointer: %p item: %u", item, *item);
	rcu_read_unlock();
	note("    read thread unlocked: pointer: %p item: %u", item, *item);

	do_something(10000);

	note("    read thread: now the item should be deallocated");
	//note("    read thread: pointer: %p item: %u", item, *item);

	rcu_unregister_thread();

	return NULL;
}

static int test_da_resize_holding(da_array_t *arr)
{
	int ret = 1;
	rcu_register_thread();
	pthread_t reader;

	// Create thread for reading
	note("dynamic-array: creating read threads");
	if (pthread_create(&reader, NULL, test_da_read, (void *)arr)) {
		diag("dynamic-array: failed to create reading thread",
		     __func__);
		rcu_unregister_thread();
		return 0;
	}

	// Wait some time, so the other thread gets the item for reading
	do_something(5000);

	// Force resize
	note("  dynamic-array: array resized");
	if (da_reserve(arr, arr->allocated - arr->count + 1) == -1) {
		diag("dynamic-array: da_reserve(%p, %d) failed", arr,
		     arr->allocated - arr->count + 1);
		ret = 0;
	}

	//Wait for the thread to finish
	void *pret = NULL;
	if (pthread_join(reader, &pret)) {
		diag("dynamic-array: failed to join reading thread",
		     __func__);
		ret = 0;
	}

	rcu_unregister_thread();
	return ret;
}

static int test_da_resize(da_array_t *arr)
{
	unsigned seed = (unsigned)time(0);
	int orig_count = da_get_count(arr);
	note("dynamic-array: allocated: %d, items: %d", arr->allocated,
	     orig_count);
	// store the items currently in the array
	int *items = (int *)malloc(orig_count * sizeof(int));
	for (int i = 0; i < orig_count; ++i) {
		items[i] = ((int *)da_get_items(arr))[i];
	}

	// force resize
	int res = 0;
	while ((res = da_reserve(arr, 10)) == 0) {
		int i = da_get_count(arr);
		da_occupy(arr, 10);
		for (; i < da_get_count(arr); ++i) {
			((int *)da_get_items(arr))[i] = rand_r(&seed);
		}
	}

	if (res < 0) {
		diag("dynamic-array: failed to reserve space");
		return 0;
	}

	int errors = 0;
	for (int i = 0; i < orig_count; ++i) {
		if (items[i] != ((int *)da_get_items(arr))[i]) {
			diag("dynamic-array: Wrong item on position %d."
			     "Should be: %d, "
			     "present value: %d", i, items[i],
			     ((int *)da_get_items(arr))[i]);
			++errors;
		}
	}

	free(items);

	return errors == 0;
}

static int da_tests_run(int argc, char *argv[])
{
	// Init
	rcu_init();
	da_array_t array;

	// Test 1: test rcu
	ok(test_rcu_threads(), "dynamic-array: rcu tests");

	// Test 2: init
	ok(test_da_init(&array), "dynamic-array: init");

	// Test 3: reserve/occupy random operations
	ok(test_da_random_op(&array),
	   "dynamic-array: randomized reserve/occupy/release");

	// Test 4: resizing array while holding an item
	ok(test_da_resize_holding(&array),
	   "dynamic-array: resize array while holding an item");

	// Test 5: resize
	ok(test_da_resize(&array), "dynamic-array: resize array");

	// Cleanup
	da_destroy(&array);
	return 0;
}
