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
	"SLAB allocator",      //! Unit name
	&slab_tests_count,  //! Count scheduled tests
	&slab_tests_run     //! Run scheduled tests
};

static int slab_tests_count(int argc, char *argv[])
{
	return 3;
}

static int slab_tests_run(int argc, char *argv[])
{
	// 1. Create empty slab
	srand(time(NULL));
	slab_cache_t cache;
	cache.item_size = sizeof(int);
	cache.next_color = rand();
	cache.next_color = cache.next_color - (cache.next_color%8);
	cache.free = cache.partial = 0;
	slab_t* slab = slab_create(&cache, (size_t)sysconf(_SC_PAGESIZE));
	ok(slab != 0, "slab: created empty slab");

	// 2. Couple alloc/free
	lives_ok({
	for(int i = 0; i < 10; ++i) {
		int* data = (int*)slab_alloc(slab);
		*data = 0xdeadbeef;
		slab_free(data);
	}}, "slab: couple alloc/free");

	// 3. Delete slab
	slab_delete(&slab);
	ok(slab == 0, "slab: freed slab");
	return 0;
}
