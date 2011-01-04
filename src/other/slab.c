#include <stdio.h>
#include <malloc.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include "slab.h"

#undef malloc
#undef free
#undef realloc
#include <stdlib.h>

/*
 * Custom caches LUT.
 */
#define SLAB_CACHE_LUT_SIZE 1024
static const unsigned char SLAB_CACHE_LUT[SLAB_CACHE_LUT_SIZE] = {
        [24]  = SLAB_GP_COUNT + 1,
        [800] = SLAB_GP_COUNT + 2
};

/*
 * Find the next highest power of 2.
 */
static inline unsigned get_next_pow2(unsigned v)
{
	// Next highest power of 2
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;

	return v;
}

/*
 * Return binary logarithm of a number, which is a power of 2.
 */
static inline unsigned fastlog2(unsigned v)
{
	// Binary logarithm.
	// Works well when we know size is a power of 2
	register unsigned int r = (v & 0xAAAAAAAA) != 0;
	r |= ((v & 0xFFFF0000) != 0) << 4;
	r |= ((v & 0xFF00FF00) != 0) << 3;
	r |= ((v & 0xF0F0F0F0) != 0) << 2;
	r |= ((v & 0xCCCCCCCC) != 0) << 1;
	return r;
}

/*
 * Fast hashing function.
 * Finds the next highest power of 2 and returns binary logarithm.
 */
static unsigned slab_cache_id(unsigned size)
{
	// Assert cache id is at least SLAB_MIN_BUFLEN
	if(size < SLAB_MIN_BUFLEN)
		size = SLAB_MIN_BUFLEN;

	// Check LUT
	unsigned id = 0;
	if ((size < SLAB_CACHE_LUT_SIZE) && (id = SLAB_CACHE_LUT[size])) {
		/*fprintf(stderr, "%s: LUT hit %u has cache_id=%u\n",
		        __func__, size, id); */
		return id;
	}

	// Next highest power of 2
	size = get_next_pow2(size);

	// Compute binary logarithm
	id = fastlog2(size);

	// Shift cacheid of SLAB_MIN_BUFLEN to 0
	id -= SLAB_EXP_OFFSET;
	return id;
}

/*
 * Slab pages directory.
 * Provides O(1) lookup with quite low
 * memory overhead (~124kB for 4GiB memory).
 */
size_t SLAB_SIZE = 0;
static unsigned SLAB_SIZE_EXP = 0;
static int* _slab_dir = 0;

/* Division or modulo by  2^n gets
 * optimised to k >> n and k & (n-1) respectively
 * even with -O0.
 */
#define slab_page_hash(addr)  (((uint64_t)addr ^ (uint64_t)_slab_dir) / SLAB_SIZE)
#define slab_dir_index(id)  ((id) / (8 * sizeof(int)))
#define slab_dir_offset(id) ((id) % (8 * sizeof(int)))

static void slab_dir_mark(void* addr)
{
	unsigned id = slab_page_hash(addr);
	/*fprintf(stderr, "%s: addr %p -> index 0x%x (0x%lx, 0x%lx)\n",
	        __func__, addr, id, slab_dir_index(id), slab_dir_offset(id));*/
	_slab_dir[slab_dir_index(id)] |= slab_dir_offset(id);

}

static void slab_dir_clear(void* addr)
{
	unsigned id = slab_page_hash(addr);
	/*fprintf(stderr, "%s: addr %p -> index 0x%x (0x%lx, 0x%lx)\n",
	        __func__, addr, id, slab_dir_index(id), slab_dir_offset(id));*/
	_slab_dir[slab_dir_index(id)] &= ~slab_dir_offset(id);
}

static int slab_dir_exists(void* addr)
{
	unsigned id = slab_page_hash(addr);
	/*fprintf(stderr, "%s: addr %p -> index 0x%x (0x%lx, 0x%lx)\n",
	        __func__, addr, id, slab_dir_index(id), slab_dir_offset(id));*/
	return _slab_dir[slab_dir_index(id)] & slab_dir_offset(id);
}

/*
 * Initializers.
 */
static slab_alloc_t _allocator_g;

void __attribute__ ((constructor)) slab_init()
{
	// Fetch page size
	SLAB_SIZE = sysconf(_SC_PAGESIZE);
	SLAB_SIZE_EXP = fastlog2(SLAB_SIZE);
	assert(SLAB_SIZE < ~(unsigned int)(0));

	// Initialize directory of allocd pages
	// Bitfield is approx. 20% slower, but still very good (~2ms for 1M ops)
	// It is far more space effective (1/8 of the bytemap).
	long pages = sysconf(_SC_PHYS_PAGES);
	_slab_dir = mmap(0, pages / 8, PROT_READ|PROT_WRITE,
	                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	memset(_slab_dir, 0, pages / 8);

	// Initialize global allocator
	slab_alloc_init(&_allocator_g);
}

void __attribute__ ((destructor)) slab_deinit()
{
	// Deinitialize global allocator
	slab_alloc_stats(&_allocator_g);
	slab_alloc_destroy(&_allocator_g);

	// Unmap page directory
	long pages = sysconf(_SC_PHYS_PAGES);
	munmap(_slab_dir, pages / 8);
}

/*
 * Cache helper functions.
 */
static inline int slab_alloc_lock(slab_alloc_t* alloc)
{
	return pthread_spin_lock(&alloc->lock);
}

static inline int slab_alloc_unlock(slab_alloc_t* alloc)
{
	return pthread_spin_unlock(&alloc->lock);
}

static inline int slab_cache_lock(slab_cache_t* cache)
{
	return pthread_spin_lock(&cache->lock);
}

static inline int slab_cache_unlock(slab_cache_t* cache)
{
	return pthread_spin_unlock(&cache->lock);
}

static inline int slab_cache_free_slabs(slab_t* slab)
{
	int count = 0;
	while (slab) {
		slab_t* next = slab->next;
		slab_destroy(&slab);
		slab = next;
		++count;
	}
	return count;
}

/*
 * Slab helper functions.
 */
static inline unsigned slab_list_walk(slab_t* slab)
{
	unsigned count = 0;
	while(slab) {
		slab = slab->next;
		++count;
	}
	return count;
}

static inline void slab_list_remove(slab_t* slab)
{
	// Disconnect from list
	if (slab->prev) {
		slab->prev->next = slab->next;
	}
	if(slab->next) {
		slab->next->prev = slab->prev;
	}

	// Disconnect from cache
	slab_cache_t* cache = slab->cache;
	slab_cache_lock(cache);
	{
		if (cache->slabs_empty == slab) {
			/*fprintf(stderr, "%s: deleted %p from slabs_empty\n",
			        __func__, slab);*/
			cache->slabs_empty = slab->next;
		}
		if (cache->slabs_partial == slab) {
			/*fprintf(stderr, "%s: deleted %p from slabs_partial\n",
			        __func__, slab);*/
			cache->slabs_partial = slab->next;
		}
		if (cache->slabs_full == slab) {
			/*fprintf(stderr, "%s: deleted %p from slabs_full\n",
			        __func__, slab);*/
			cache->slabs_full = slab->next;
		}
	}
	slab_cache_unlock(cache);
}
static inline void slab_list_insert(slab_t** list, slab_t* item)
{
	// If list exists, push to the top
	slab_cache_lock(item->cache);
	item->prev = 0;
	item->next = *list;
	if (*list) {
		(*list)->prev = item;
	}

	*list = item;
	slab_cache_unlock(item->cache);

	const char* ln = "slabs_empty";
	if(*list == item->cache->slabs_partial)
		ln = "slabs_partial";
	if(*list == item->cache->slabs_full)
		ln = "slabs_full";
	/*fprintf(stderr, "%s: inserted %p to %s (L:%p R:%p)\n",
	        __func__, item, ln, item->prev, item->next);*/
}
static inline void slab_list_move(slab_t** target, slab_t* slab)
{
	slab_list_remove(slab);
	slab_list_insert(target, slab);
}

/*
 * API functions.
 */

slab_t* slab_create(slab_cache_t* cache)
{
	const size_t size = SLAB_SIZE;

	slab_t* slab = mmap(0, size, PROT_READ|PROT_WRITE,
	                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (slab < 0) {
		fprintf(stderr, "%s: failed to allocate aligned memory block\n",
		        __func__);
		return 0;
	}

	/* Mark in directory. */
	slab_dir_mark(slab);

	/* Initialize slab. */
	slab->cache = cache;
	slab_list_insert(&cache->slabs_empty, slab);

	/* Ensure the item size can hold at least a size of ptr. */
	size_t item_size = cache->bufsize;
	if (item_size < SLAB_MIN_BUFLEN) {
		item_size = SLAB_MIN_BUFLEN;
	}

	/* Ensure at least some space for coloring */
	size_t data_size = size - sizeof(slab_t);
	size_t free_space = (data_size % item_size);
	if(free_space < 64) {
		free_space = 64;
	}

	unsigned short color = __sync_fetch_and_add(&cache->color, 1);
	color = (1 << color) % free_space;
	color = color - ((color + sizeof(slab_t)) % sizeof(void*));

	/* Calculate useable data size */
	data_size -= color;
	slab->bufs_count = data_size / item_size;
	slab->bufs_free = slab->bufs_count;

	// Save first item as next free
	slab->base = (char*)slab + sizeof(slab_t) + color;
	slab->head = (void**)slab->base;

	// Create freelist
	char* item = (char*)slab->head;
	for(unsigned i = 0; i < slab->bufs_count - 1; ++i) {
		*((void**)item) = item + item_size;
		item += item_size;
	}
	*((void**)item) = (void*)0;

	// Ensure the last item has a NULL next
	/*fprintf(stderr, "%s: created slab (%p, %p) (%u B)\n",
	        __func__, slab, slab + size, (unsigned)size);
	fprintf(stderr, "%s: parent = %p, next slab = %p\n",
	        __func__, cache, slab->next);*/
	/*fprintf(stderr, "%s: item_size = %u\n",
	        __func__, (unsigned)item_size);
	fprintf(stderr, "%s: color = %hu\n",
	        __func__, color);
	fprintf(stderr, "%s: data_size = %u\n",
	        __func__, (unsigned)data_size);
	fprintf(stderr, "%s: bufs_count = %u\n",
	        __func__, slab->bufs_count);
	fprintf(stderr, "%s: return = %p\n",
	        __func__, slab);*/
	return slab;
}

void slab_destroy(slab_t** slab)
{
	/* Disconnect from the list */
	slab_list_remove(*slab);

	/* Free slab */
	munmap(*slab, SLAB_SIZE);

	/* Clear directory. */
	slab_dir_clear(*slab);

	/* Invalidate pointer. */
	/*fprintf(stderr, "%s: deleted slab %p\n",
	        __func__, *slab);*/
	*slab = 0;
}

void* slab_alloc(slab_t* slab)
{
	// Fetch first free item
	// Critial section -->
	void** item =  slab->head;
	if (item == 0) {
		return 0;
	}

	slab->head = (void**)*item;
	--slab->bufs_free;
	// <-- Critial section

	// Move to partial?
	if (slab->bufs_free == slab->bufs_count - 1) {
		slab_list_move(&slab->cache->slabs_partial, slab);
	} else if (slab->bufs_free == 0){
		slab_list_move(&slab->cache->slabs_full, slab);
	}

	// Increment statistics
	__sync_add_and_fetch(&slab->cache->stat_allocs, 1);

	return item;
}

void slab_free(void* ptr)
{
	// Null pointer check
	if (ptr == 0) {
		fprintf(stderr, "%s: attempted to free null ptr\n", __func__);
		return;
	}

	// Get slab start address
	slab_t* slab = slab_from_ptr(ptr);

	// Check if it exists in directory
	if (slab_dir_exists(slab)) {

		// Return buf to slab
		*((void**)ptr) = slab->head;
		slab->head = (void**)ptr;
		++slab->bufs_free;

		// Return to partial
		if(slab->bufs_free == 1) {
			slab_list_move(&slab->cache->slabs_partial, slab);
		} else if(slab->bufs_free == slab->bufs_count) {
			slab_list_move(&slab->cache->slabs_empty, slab);
		}

		// Increment statistics
		__sync_add_and_fetch(&slab->cache->stat_frees, 1);
	} else {

		// Pointer is not a slab
		// Presuming it's a large block
		size_t* bs = ((size_t*)ptr) - 1;

		// Unmap
		fprintf(stderr, "%s: unmapping large block of %zu bytes at %p\n",
		        __func__, *bs, ptr);
		munmap(bs, *bs);
	}



}

int slab_cache_init(slab_cache_t* cache, size_t bufsize)
{
	/*fprintf(stderr, "%s: created cache of size %u\n",
	        __func__, (unsigned)bufsize);*/
	cache->bufsize = bufsize;
	cache->slabs_empty = cache->slabs_partial = cache->slabs_full = 0;
	cache->color = 0;

	/* Initialize synchronisation */
	pthread_spin_init(&cache->lock, PTHREAD_PROCESS_SHARED);

	/* Initialize stats */
	cache->stat_allocs = cache->stat_frees = 0;

	return 0;
}

void slab_cache_destroy(slab_cache_t* cache) {

	// Free slabs
	unsigned empty = slab_cache_free_slabs(cache->slabs_empty);
	unsigned partial = slab_cache_free_slabs(cache->slabs_partial);
	unsigned full = slab_cache_free_slabs(cache->slabs_full);
	fprintf(stderr, "%s: %u empty, %u partial, %u full caches\n",
	        __func__, empty, partial, full);

	// Destroy synchronisation
	pthread_spin_destroy(&cache->lock);

	// Invalidate cache
	cache->bufsize = 0;
	cache->slabs_empty = cache->slabs_partial = cache->slabs_full = 0;
}

void* slab_cache_alloc(slab_cache_t* cache)
{
	slab_t* slab = cache->slabs_partial;
	if(cache->slabs_partial) {
		slab = cache->slabs_partial;
	} else {
		if(cache->slabs_empty) {
			slab = cache->slabs_empty;
		} else {
			slab = slab_create(cache);
		}
	}


	return slab_alloc(slab);
}

int slab_cache_reap(slab_cache_t* cache)
{
	// For now, just free empty slabs
	return slab_cache_free_slabs(cache->slabs_empty);
}

int slab_alloc_init(slab_alloc_t* alloc)
{
	// Invalidate
	memset(alloc, 0, sizeof(slab_alloc_t));

	// Initialize descriptors cache
	slab_cache_init(&alloc->descriptors, sizeof(slab_cache_t));

	// Initialize synchronisation
	pthread_spin_init(&alloc->lock, PTHREAD_PROCESS_SHARED);

	return 0;
}

void slab_alloc_destroy(slab_alloc_t* alloc)
{
	// Destroy all caches
	for (unsigned i = 0; i < SLAB_CACHE_COUNT; ++i) {
		if (alloc->caches[i] != 0) {
			slab_cache_destroy(alloc->caches[i]);
		}
	}

	// Destroy cache for descriptors
	slab_cache_destroy(&alloc->descriptors);

	// Destroy synchronisation
	pthread_spin_destroy(&alloc->lock);
}

void* slab_alloc_alloc(slab_alloc_t* alloc, size_t size)
{
	// Directly map large block
	if (size > SLAB_SIZE * 0.5) {

		// Map block
		size_t* p = mmap(0, size + sizeof(size_t), PROT_READ|PROT_WRITE,
		                 MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

		// Prepend size tag
		fprintf(stderr, "%s: mapping large block of %zu bytes at %p\n",
		        __func__, size, p + 1);

		*p = size;
		return p + 1;
	}

	// Get cache id from size
	unsigned cache_id = slab_cache_id(size);

	// Check if associated cache exists
	slab_alloc_lock(alloc);
	if (alloc->caches[cache_id] == 0) {

		// Assert minimum cache size
		if (size < SLAB_MIN_BUFLEN) {
			size = SLAB_MIN_BUFLEN;
		}

		// Calculate cache bufsize
		size_t bufsize = size;
		if (cache_id < SLAB_GP_COUNT) {
			bufsize = get_next_pow2(size);
		}

		// Create cache
		fprintf(stderr, "%s: creating cache of %uB for size %uB (id=%u)\n",
		        __func__, (unsigned)bufsize, (unsigned)size, cache_id);

		slab_cache_t* cache = slab_cache_alloc(&alloc->descriptors);
		slab_cache_init(cache, bufsize);
		alloc->caches[cache_id] = cache;
	}
	slab_alloc_unlock(alloc);

	// Allocate from cache
	void *ret = slab_cache_alloc(alloc->caches[cache_id]);
	if (ret == 0) {
		fprintf(stderr, "%s: returned NULL for size=%u,cacheid=%u\n",
		        __func__, (unsigned)size, (unsigned)cache_id);
	}
	return ret;
}

void *slab_alloc_realloc(slab_alloc_t* alloc, void *ptr, size_t size)
{
    // Allocate new buf
    void *nptr = slab_alloc_alloc(alloc, size);

    // Copy memory
    slab_t* slab = slab_from_ptr(ptr);
    memcpy(nptr, ptr, slab->cache->bufsize);

    // Free old buf and return
    slab_free(ptr);
    return nptr;
}

void slab_alloc_stats(slab_alloc_t* alloc)
{
	printf("Caches usage:\n");
	for (int i = 0; i < SLAB_CACHE_COUNT; ++i) {
		if (!alloc->caches[i])
			continue;
		slab_cache_t* cache = alloc->caches[i];
		unsigned empty = slab_list_walk(cache->slabs_empty);
		unsigned partial = slab_list_walk(cache->slabs_partial);
		unsigned full = slab_list_walk(cache->slabs_full);
		printf("%4u: allocs=%5lu frees=%5lu (%u empty, %u partial, %u full)\n",
		       (unsigned)cache->bufsize, cache->stat_allocs, cache->stat_frees,
		       empty, partial, full);
	}
}

void *slab_alloc_g(size_t size)
{
	return slab_alloc_alloc(&_allocator_g, size);
}

void *slab_realloc_g(void *ptr, size_t size)
{
	return slab_alloc_realloc(&_allocator_g, ptr, size);
}
