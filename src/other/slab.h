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
#include <stdint.h>

/* Constants. */
#define SLAB_MIN_BUFLEN 8 // Minimal allocation block size is 8B.
#define SLAB_EXP_OFFSET 3 // Minimal allocation size is 8B = 2^3, exp is 3.
#define SLAB_GP_COUNT  10 // General-purpose caches count.
#define SLAB_US_COUNT  10 // User-specified caches count.
#define SLAB_CACHE_COUNT (SLAB_GP_COUNT + SLAB_US_COUNT)
extern size_t SLAB_SIZE;
struct slab_cache_t;

/* Macros. */
#define slab_from_ptr(p) ((slab_t*)((char*)(p) - ((uint64_t)(p) % SLAB_SIZE)))

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

	/* Statistics. */
	uint64_t stat_allocs;    /*!< Allocation count. */
	uint64_t stat_frees;     /*!< Free count. */
} slab_cache_t;

/*!
 * \brief Slab allocator descriptor.
 *
 * \note For a number of slab caches, consult SLAB_GP_COUNT
 *       and a number of specific records in SLAB_CACHE_LUT lookup table.
 */
typedef struct slab_alloc_t {
	pthread_spinlock_t lock;  /*!< Synchronisation lock. */
	slab_cache_t descriptors; /*!< Slab cache for cache descriptors. */
	slab_cache_t* caches[SLAB_CACHE_COUNT]; /*!< Number of slab caches. */
} slab_alloc_t;

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
 * \param cache Pointer to uninitialized cache.
 * \param bufsize Single item size for later allocs.
 * \retval 0 on success.
 * \retval -1 on error;
 */
int slab_cache_init(slab_cache_t* cache, size_t bufsize);

/*!
 * \brief Destroy a slab cache.
 *
 * Destroy a slab cache and all associated slabs.
 *
 * \param cache Pointer to slab cache.
 */
void slab_cache_destroy(slab_cache_t* cache);

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

/*!
 * \brief Create a slab allocator.
 *
 * \retval 0 on success.
 * \retval -1 on error.
 */
int slab_alloc_init(slab_alloc_t* alloc);

/*!
 * \brief Delete slab allocator.
 *
 * This destroys all associated caches and frees memory.
 *
 * \param alloc Given allocator instance.
 */
void slab_alloc_destroy(slab_alloc_t* alloc);

/*!
 * \brief Allocate a block of memory.
 *
 * Returns a block of allocated memory.
 *
 * \note At least SLAB_MIN_BUFSIZE bytes is allocated.
 *
 * \param alloc Allocator instance.
 * \param size Requested block size.
 * \retval Pointer to allocated memory.
 * \retval NULL on error.
 */
void* slab_alloc_alloc(slab_alloc_t* alloc, size_t size);

/*!
 * \brief Reallocate data from one slab to another.
 *
 * \param alloc Allocator instance.
 * \param ptr Pointer to allocated memory.
 * \param size Requested memory block size.
 * \retval Pointer to newly allocated memory.
 * \retval NULL on error.
 *
 * \todo Realloc could be probably implement more effectively.
 */
void *slab_alloc_realloc(slab_alloc_t* alloc, void *ptr, size_t size);

/*!
 *
 * \brief Dump allocator stats.
 *
 * \param alloc Allocator instance.
 */
void slab_alloc_stats(slab_alloc_t* alloc);

/*!
 * \brief Allocate data from shared global slab allocator.
 *
 * Slab is initialized with default constructor without priority.
 * Drop-in replacement for malloc().
 *
 * \see slab_alloc_alloc()
 *
 * \param size Requested block size.
 * \retval Pointer to allocated memory.
 * \retval NULL on error.
 */
void* slab_alloc_g(size_t size);

/*!
 * \brief Reallocate data from one slab to another.
 *
 * Drop-in replacement for realloc().
 *
 * \see slab_alloc_realloc()
 *
 * \param ptr Pointer to allocated memory.
 * \param size Requested memory block size.
 * \retval Pointer to newly allocated memory.
 * \retval NULL on error.
 */
void *slab_realloc_g(void *ptr, size_t size);

#endif /* _CUTEDNS_SLAB_H_ */

/*! \} */
