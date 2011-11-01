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

#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

#include "tests/common/slab_tests.h"
#include "common/slab/slab.h"
#include "knot/common.h"

/* Explicitly ask for symbols,
 * as the constructor and destructor
 * aren't created for test modules.
 */
extern void slab_init();
extern void slab_deinit();

static int slab_tests_count(int argc, char *argv[]);
static int slab_tests_run(int argc, char *argv[]);

/*! Exported unit API.
 */
unit_api slab_tests_api = {
	"SLAB allocator",   //! Unit name
	&slab_tests_count,  //! Count scheduled tests
	&slab_tests_run     //! Run scheduled tests
};

static int slab_tests_count(int argc, char *argv[])
{
	return 7;
}

static int slab_tests_run(int argc, char *argv[])
{
	// 1. Create slab cache
	srand(time(0));
	const unsigned pattern = 0xdeadbeef;
	slab_cache_t cache;
	int ret = slab_cache_init(&cache, sizeof(int));
	ok(ret == 0, "slab: created empty cache");

	// 2. Couple alloc/free
	bool valid_free = true;
	lives_ok({
	for(int i = 0; i < 100; ++i) {
		int* data = (int*)slab_cache_alloc(&cache);
		*data = pattern;
		slab_free(data);
		if (*data == pattern)
			valid_free = false;
	}
	}, "slab: couple alloc/free");

	// 5. Verify freed block
	ok(valid_free, "slab: freed memory is correctly invalidated");

	// 4. Reap memory
	slab_t* slab = cache.slabs_free;
	int free_count = 0;
	while (slab) {
		slab_t* next = slab->next;
		if (slab_isempty(slab)) {
			++free_count;
		}
		slab = next;
	}

	int reaped = slab_cache_reap(&cache);
	cmp_ok(reaped, "==", free_count, "slab: cache reaping works");

	// Stress cache
	int alloc_count = 73521;
	void** ptrs = alloca(alloc_count * sizeof(void*));
	int ptrs_i = 0;
	for(int i = 0; i < alloc_count; ++i) {
		double roll = rand() / (double) RAND_MAX;
		if ((ptrs_i == 0) || (roll < 0.6)) {
			int id = ptrs_i++;
			ptrs[id] = slab_cache_alloc(&cache);
			if (ptrs[id] == 0) {
				ptrs_i--;
			} else {
				int* data = (int*)ptrs[id];
				*data = pattern;
			}
		} else {
			slab_free(ptrs[--ptrs_i]);
		}
	}

	// 5. Delete cache
	slab_cache_destroy(&cache);
	ok(cache.bufsize == 0, "slab: freed cache");

	// 6. Greate GP allocator
	slab_alloc_t alloc;
	ret = slab_alloc_init(&alloc);
	ok(ret == 0, "slab: created GP allocator");

	// 7. Stress allocator
	unsigned ncount = 0;
	ptrs_i = 0;
	for(int i = 0; i < alloc_count; ++i) {
		double roll = rand() / (double) RAND_MAX;
		size_t bsize = roll * 2048;
		bsize = MAX(bsize, 8);
		if ((ptrs_i == 0) || (roll < 0.6)) {
			void* m = slab_alloc_alloc(&alloc, bsize);
			if (m == 0) {
				++ncount;
			} else {
				ptrs[ptrs_i++] = m;
			}
		} else {
			slab_free(ptrs[--ptrs_i]);
		}
	}

	cmp_ok(ncount, "==", 0, "slab: GP allocator alloc/free working");

	// 7. Destroy allocator
	slab_alloc_destroy(&alloc);

	return 0;
}
