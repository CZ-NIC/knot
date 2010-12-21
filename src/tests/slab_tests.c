#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#include "tap_unit.h"
#include "slab.h"

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
	}}, "slab: couple alloc/free");

	// 5. Verify freed block
	ok(valid_free, "slab: freed memory is correctly invalidated");

	// 4. Reap memory
	int reaped = slab_cache_reap(&cache) > 0 &&
	             cache.slabs_empty == 0;
	ok(reaped, "slab: cache reaping works");

	// Stress cache
	int alloc_count = 73561;
	void** ptrs = malloc(alloc_count * sizeof(void*));
	int ptrs_i = 0;
	for(int i = 0; i < alloc_count; ++i) {
		double roll = rand() / (double) RAND_MAX;
		if ((ptrs_i == 0) || (roll < 0.6)) {
			int id = ptrs_i++;
			ptrs[id] = slab_cache_alloc(&cache);
			int* data = (int*)ptrs[id];
			*data = pattern;
		} else {
			slab_free(ptrs[--ptrs_i]);
		}
	}
	free(ptrs);

	// 5. Delete cache
	slab_cache_destroy(&cache);
	ok(cache.bufsize == 0, "slab: freed cache");

	// 6. Greate GP allocator
	slab_alloc_t alloc;
	ret = slab_alloc_init(&alloc);
	ok(ret == 0, "slab: created GP allocator");

	// 7. Stress allocator
	unsigned ncount = 0;
	alloc_count = 73561;
	ptrs = malloc(alloc_count * sizeof(void*));
	ptrs_i = 0;
	for(int i = 0; i < alloc_count; ++i) {
		double roll = rand() / (double) RAND_MAX;
		size_t bsize = roll * 2048;
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
	free(ptrs);
	cmp_ok(ncount, "==", 0, "slab: GP allocator alloc/free working");

	// Dump allocator stats
	slab_alloc_stats(&alloc);

	// 7. Destroy allocator
	slab_alloc_destroy(&alloc);

	return 0;
}
