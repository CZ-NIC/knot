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
	return 5;
}

static int slab_tests_run(int argc, char *argv[])
{
	// 1. Create slab cache
	srand(time(0));
	const unsigned pattern = 0xdeadbeef;
	slab_cache_t* cache = slab_cache_create(sizeof(int));
	ok(cache != 0, "slab: created empty cache");

	// 2. Couple alloc/free
	bool valid_free = true;
	lives_ok({
	for(int i = 0; i < 100; ++i) {
		int* data = (int*)slab_cache_alloc(cache);
		*data = pattern;
		slab_free(data);
		if (*data == pattern)
			valid_free = false;
	}}, "slab: couple alloc/free");

	// 5. Verify freed block
	ok(valid_free, "slab: freed memory is correctly invalidated");

	// 4. Reap memory
	int reaped = slab_cache_reap(cache) > 0 &&
	             cache->slabs_empty == 0;
	ok(reaped, "slab: cache reaping works");

	// Stress cache
	int alloc_count = 73561;
	void** ptrs = malloc(alloc_count * sizeof(void*));
	int ptrs_i = 0;
	for(int i = 0; i < alloc_count; ++i) {
		double roll = rand() / (double) RAND_MAX;
		if ((ptrs_i == 0) || (roll < 0.6)) {
			int id = ptrs_i++;
			ptrs[id] = slab_cache_alloc(cache);
			int* data = (int*)ptrs[id];
			*data = pattern;
		} else {
			slab_free(ptrs[--ptrs_i]);
		}
	}
	free(ptrs);

	// 5. Delete cache
	slab_cache_destroy(&cache);
	ok(cache == 0, "slab: freed cache");

	return 0;
}
