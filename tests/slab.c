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
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <tap/basic.h>

#include "common/slab/slab.h"

/*! \brief Type-safe maximum macro. */
#define SLAB_MAX(a, b) \
	({ typeof (a) _a = (a); typeof (b) _b = (b); _a > _b ? _a : _b; })


/* Explicitly ask for symbols,
 * as the constructor and destructor
 * aren't created for test modules.
 */
extern void slab_init();
extern void slab_deinit();

int main(int argc, char *argv[])
{
	plan(4);

	// 1. Create slab cache
	srand(time(0));
	const unsigned pattern = 0xdeadbeef;
	slab_cache_t cache;
	int ret = slab_cache_init(&cache, sizeof(int));
	is_int(0, ret, "slab: created empty cache");

	// 2. Couple alloc/free
	bool valid_free = true;
	for(int i = 0; i < 100; ++i) {
		int* data = (int*)slab_cache_alloc(&cache);
		*data = pattern;
		slab_free(data);
		if (*data == pattern)
			valid_free = false;
	}

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
	is_int(reaped, free_count, "slab: cache reaping works");

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
	is_int(0, cache.bufsize, "slab: freed cache");

	return 0;
}
