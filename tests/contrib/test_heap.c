/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <tap/basic.h>

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/ucw/heap.h"

static void seed_random(void)
{
	unsigned short int seed[3] = { 0 };

	FILE *f = fopen("/dev/urandom", "r");
	if (f) {
		if (fread(seed, sizeof(seed), 1, f) != 1) {
			diag("failed to seed random source");
		}
		fclose(f);
	}

	diag("seed %hu %hu %hu", seed[0], seed[1], seed[2]);
	seed48(seed);
}

struct value {
	heap_val_t _heap;
	int data;
};

static int value_cmp(void *_a, void *_b)
{
	const struct value *a = _a;
	const struct value *b = _b;
	return (a->data - b->data);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	seed_random();

	static const int VALUE_COUNT = 1000;
	static const int VALUE_RANGE = 950;
	static const int VALUE_REPLACE = 300;
	static const int VALUE_DELETE = 100;

	struct heap heap;
	heap_init(&heap, value_cmp, 0);

	ok(EMPTY_HEAP(&heap), "heap is empty");

	// fill the heap with random values (with duplicates)

	struct value *values = calloc(VALUE_COUNT, sizeof(struct value));
	assert(values);
	assert(VALUE_RANGE < VALUE_COUNT);

	bool valid = true;
	for (int i = 0; i < VALUE_COUNT; i++) {
		values[i].data = lrand48() % VALUE_RANGE;
		if (heap_insert(&heap, &values[i]._heap) == 0) {
			valid = false;
		}
	}
	ok(valid, "heap_insert");
	ok(!EMPTY_HEAP(&heap), "heap is non-empty");

	// exercise heap_insert

	valid = true;
	for (int i = 0; i < VALUE_COUNT; i++) {
		int pos = heap_find(&heap, &values[i]._heap);
		if (*HELEMENT(&heap, pos) != &values[i]._heap) {
			valid = false;
		}
	}
	ok(valid, "heap_find");

	// exercise heap_replace

	assert(VALUE_REPLACE <= VALUE_COUNT);
	struct value *replaced = calloc(VALUE_REPLACE, sizeof(struct value));
	assert(replaced);

	valid = true;
	for (int i = 0; i < VALUE_REPLACE; i++) {
		replaced[i].data = lrand48() % VALUE_RANGE;
		int pos = heap_find(&heap, &values[i]._heap);
		if (pos < 1) {
			valid = false;
			continue;
		}

		heap_replace(&heap, pos, &replaced[i]._heap);
		int newpos = heap_find(&heap, &replaced[i]._heap);
		if (newpos < 1) {
			valid = false;
		}
	}
	ok(valid, "heap_replace");

	// exercise heap_delete

	assert(VALUE_REPLACE + VALUE_DELETE < VALUE_COUNT);

	valid = true;
	for (int i = 0; i < VALUE_DELETE; i++) {
		heap_val_t *value = &values[i + VALUE_REPLACE]._heap;
		int pos = heap_find(&heap, value);
		if (pos < 1) {
			valid = false;
			continue;

		}
		heap_delete(&heap, pos);
		pos = heap_find(&heap, value);
		if (pos != 0) {
			valid = false;
		}
	}
	ok(valid, "heap_delete");

	// exercise item retrieval

	assert(VALUE_COUNT > VALUE_DELETE);

	valid = true;
	int current = -1;
	for (int i = 0; i < VALUE_COUNT - VALUE_DELETE; i++) {
		struct value *val = (struct value *)*HHEAD(&heap);
		heap_delmin(&heap);
		if (current <= val->data) {
			current = val->data;
		} else {
			valid = false;
		}
	}

	ok(valid, "heap ordering");
	ok(EMPTY_HEAP(&heap), "heap_delmin");

	free(replaced);
	free(values);
	heap_deinit(&heap);

	return 0;
}
