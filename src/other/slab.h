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

/*!
 * \brief Slab descriptor.
 *
 * Slab is a block of memory used for an allocation of
 * smaller objects (bufs) later on.
 * Each slab is currently aligned to page size to easily
 * determine slab address from buf pointer.
 */
typedef struct slab_t {
	struct slab_cache_t *cache; /*!< Owner cache. */
	struct slab_t *prev, *next; /*!< Neighbours in slab lists. */
	unsigned bufs_count;        /*!< Number of bufs in slab. */
	unsigned bufs_free;         /*!< Number of available bufs. */
	void **head;                /*!< Pointer to first available buf. */
	char* base;                 /*!< Base address for bufs. */
} slab_t;

/*!
 * \brief Slab cache descriptor.
 *
 * Slab cache is a list of 0..n slabs with the same buf size.
 * It is responsible for slab state keeping.
 *
 * Once a slab is created, it is moved to empty list.
 * Then it is moved to partial list with a first allocation.
 * Full slabs go to full list.
 *
 * Allocation of new slabs is on-demand,empty slabs are reused if possible.
 */
typedef struct slab_cache_t {
	unsigned short color;    /*!< Current cache color. */
	size_t bufsize;          /*!< Cache object (buf) size. */
	slab_t *slabs_empty;     /*!< List of empty slabs. */
	slab_t *slabs_partial;   /*!< List of partially full slabs. */
	slab_t *slabs_full;      /*!< List of full slabs. */
	pthread_spinlock_t lock; /*!< Synchronisation lock. */
} slab_cache_t;

/*!
 * \brief Create a slab of predefined size.
 *
 * At the moment, slabs are equal to page size and page size aligned.
 * This enables quick and efficient buf to slab lookup by pointer arithmetic.
 *
 * Slab uses simple coloring scheme with a minimum of 64B overhead and
 * the memory block is always sizeof(void*) aligned.
 *
 * \param cache Parent cache.
 * \retval Slab instance on success.
 * \retval NULL on error.
 */
slab_t* slab_create(slab_cache_t* cache);

/*!
 * \brief Destroy slab instance.
 *
 * Slab is disconnected from any list and freed.
 * Dereferenced slab parameter is set to NULL.
 *
 * \param slab Pointer to given slab.
 */
void slab_destroy(slab_t** slab);

/*!
 * \brief Allocate a buf from slab.
 *
 * Returns a pointer to allocated memory or NULL on error.
 *
 * \param slab Given slab instance.
 * \retval Pointer to allocated memory.
 * \retval NULL on error.
 */
void* slab_alloc(slab_t* slab);

/*!
 * \brief Recycle memory.
 *
 * Given memory is returned to owner slab.
 * Memory content may be rewritten.
 *
 * \param ptr Returned memory.
 */
void slab_free(void* ptr);

/*!
 * \brief Create a slab cache.
 *
 * Create a slab cache with no allocated slabs.
 * Slabs are allocated on-demand.
 *
 * \param bufsize Single item size for later allocs.
 * \retval New slab cache instance.
 * \retval NULL on error.
 */
slab_cache_t* slab_cache_create(size_t bufsize);

/*!
 * \brief Destroy a slab cache.
 *
 * Destroy a slab cache and all associated slabs.
 * Dereferenced cache param is set to NULL.
 *
 * \param cache Pointer to slab cache.
 */
void slab_cache_destroy(slab_cache_t** cache);

/*!
 * \brief Allocate from the cache.
 *
 * It tries to use partially free caches first,
 * empty caches second and allocates a new cache
 * as a last resort.
 *
 * \param cache Given slab cache.
 * \retval Pointer to allocated memory.
 * \retval NULL on error.
 */
void* slab_cache_alloc(slab_cache_t* cache);

/*!
 * \brief Free unused slabs from cache.
 *
 * \param cache Given slab cache.
 * \return Number of freed slabs.
 */
int slab_cache_reap(slab_cache_t* cache);

#endif /* _CUTEDNS_SLAB_H_ */

/*! \} */
