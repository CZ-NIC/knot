/*!
 * \file slab.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief Multithreaded SLAB allocator.
 *
 * Multithreaded SLAB cache works with both
 * custom SLAB sizes and Next-Highest-Power-Of-2 sizes.
 *
 * Each thread has it's own thread cache to mitigate
 * the synchronisation costs.
 *
 * Slab size is a multiple of PAGE_SIZE and uses
 * system allocator for larger blocks.
 *
 * Allocated SLABs are PAGE_SIZE aligned for a fast O(1)
 * address-from-item lookup.
 *
 * Cache uses spinlocks as a locking scheme for a very short
 * critical sections. Spinlocks have at least order of magnited
 * lower complexity than mutexes.
 *
 * Slab implements simple coloring mechanism to improve
 * cache line utilisation.
 *
 * \addtogroup data_structures
 * @{
 */

#ifndef _CUTEDNS_SLAB_H_
#define _CUTEDNS_SLAB_H_

#include <pthread.h>

/* Constants. */
struct slab_cache_t;

typedef struct slab_t {
	struct slab_cache_t *cache;
	struct slab_t *prev, *next;
	unsigned bufs_count;
	unsigned bufs_free;
	void **head;
	char* base;
} slab_t;

typedef struct slab_cache_t {
	unsigned short next_color;
	size_t item_size;
	slab_t* slabs_empty;
	slab_t* slabs_partial;
	slab_t* slabs_full;
	pthread_spinlock_t lock;
} slab_cache_t;

slab_t* slab_create(slab_cache_t* cache, size_t size);
void slab_delete(slab_t** slab);
void* slab_alloc(slab_t* slab);
void slab_free(void* ptr);

/* predat
    flags? alignment?
    void ctor(void*); void dtor(void*) */
slab_cache_t* slab_cache_create(size_t item_size);
void slab_cache_delete(slab_cache_t** cache);
void* slab_cache_alloc(slab_cache_t* cache);
int slab_cache_reap(slab_cache_t* cache);

#endif /* _CUTEDNS_SLAB_H_ */

/*! \} */
