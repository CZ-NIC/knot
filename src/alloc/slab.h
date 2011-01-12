/*!
 * \file slab.h
 *
 * \author Marek Vavrusa <marek.vavusa@nic.cz>
 *
 * \brief SLAB allocator.
 *
 * SLAB cache works with either custom SLAB sizes and
 * Next-Highest-Power-Of-2 sizes.
 *
 * Slab size is a multiple of PAGE_SIZE and uses
 * system allocator for larger blocks.
 *
 * Allocated SLABs are PAGE_SIZE aligned for a fast O(1)
 * address-from-item lookup. This results in nearly none memory
 * overhead for a very small blocks (<64B), but it requires the
 * underlying allocator to be effective in allocating page size aligned memory
 * as well. The major disadvantage is that each Slab must be aligned to it's
 * size as opposed to boundary tags.
 *
 * Slab implements simple coloring mechanism to improve
 * cache line utilisation.
 *
 *
 * Optimal usage for a specific behavior (similar allocation sizes):
 * \code
 * slab_cache_t cache;
 * slab_cache_init(&cache, N); // Initialize, N means cache chunk size
 * ...
 * void* mem = slab_cache_alloc(&cache); // Allocate N bytes
 * ...
 * slab_free(mem); // Recycle memory
 * ...
 * slab_cache_destroy(&cache); // Deinitialize cache
 * \endcode
 *
 * \todo Evaluate non-aligned and bigger slabs, tweak settings for server.
 *
 * \todo Allocate slab headers elsewhere and use just first sizeof(void*) bytes
 *       in each slab as a pointer to slab header. This could improve the
 *       performance.
 *
 * \note Slab allocation is not thread safe for performance reasons.
 *
 * \addtogroup alloc
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
#define SLAB_DEPOT_COUNT 16 // 16 slabs cached = 16*4kB
extern size_t SLAB_MASK;
struct slab_cache_t;

/* Macros. */
#define slab_from_ptr(p) ((void*)((size_t)(p) & SLAB_MASK))
#define slab_isempty(s) ((s)->bufs_free == (s)->bufs_count)

/*!
 * \brief Slab descriptor.
 *
 * Slab is a block of memory used for an allocation of
 * smaller objects (bufs) later on.
 * Each slab is currently aligned to page size to easily
 * determine slab address from buf pointer.
 *
 * \warning Do not use slab_t directly as it cannot grow, see slab_cache_t.
 */
typedef struct slab_t {
	char magic;                 /*!< Identifies memory block type. */
	struct slab_cache_t *cache; /*!< Owner cache. */
	struct slab_t *prev, *next; /*!< Neighbours in slab lists. */
	unsigned bufs_count;        /*!< Number of bufs in slab. */
	unsigned bufs_free;         /*!< Number of available bufs. */
	void **head;                /*!< Pointer to first available buf. */
	char* base;                 /*!< Base address for bufs. */
} slab_t;

/*!
 * \brief Slab depot.
 *
 * To mitigate slab initialization costs, depot keeps a finite number of
 * stacked slabs before returning them to the system.
 *
 * \todo Implement hierarchy to return ready-to-use, same block size pages.
 */
typedef struct slab_depot_t {
	size_t available;             /*!< Number of available pages. */
	void* page[SLAB_DEPOT_COUNT]; /*!< Stack of free slabs. */
} slab_depot_t;

/*!
 * \brief Large object descriptor.
 *
 * Large object differs from slab with magic byte and
 * contains object size.
 *
 * Magic needs to be first to overlap with slab_t magic byte.
 */
typedef struct slab_obj_t {
	char magic;  /*!< Identifies memory block type. */
	size_t size; /*!< Object size. */
} slab_obj_t;

/*!
 * \brief Slab cache descriptor.
 *
 * Slab cache is a list of 0..n slabs with the same buf size.
 * It is responsible for slab state keeping.
 *
 * Once a slab is created, it is moved to free list.
 * When it is full, it is moved to full list.
 * Once a buf from full slab is freed, the slab is moved to
 * free list again (there may be some hysteresis for mitigating
 * a sequential alloc/free).
 *
 * \note Slab implementation is different from Bonwick (Usenix 2001)
 *       http://www.usenix.org/event/usenix01/bonwick.html
 *       as it doesn't feature empty and partial list.
 *       This is due to fact, that user space allocator rarely
 *       needs to count free slabs. There is no way the OS could
 *       notify the application, that the memory is scarce.
 *       A slight performance increased is measured in benchmark.
 *
 * Allocation of new slabs is on-demand, empty slabs are reused if possible.
 *
 * \note Statistics are only available if MEM_DEBUG is enabled.
 */
typedef struct slab_cache_t {
	unsigned short color;    /*!< Current cache color. */
	size_t bufsize;          /*!< Cache object (buf) size. */
	slab_t *slabs_free;      /*!< List of free slabs. */
	slab_t *slabs_full;      /*!< List of full slabs. */

	/* Statistics. */
	uint64_t stat_allocs;    /*!< Allocation count. */
	uint64_t stat_frees;     /*!< Free count. */
} slab_cache_t;

/*!
 * \brief Slab allocator descriptor.
 *
 * \note For a number of slab caches, consult SLAB_GP_COUNT
 *       and a number of specific records in SLAB_CACHE_LUT lookup table.
 *
 * \warning It is currently not advised to use this general purpose allocator,
 *          as it usually doesn't yield an expected performance for higher
 *          bookkeeping costs and it also depends on the allocation behavior
 *          as well. Look for slab_cache for a specialized use in most cases.
 */
typedef struct slab_alloc_t {
	slab_cache_t descriptors; /*!< Slab cache for cache descriptors. */
	slab_cache_t* caches[SLAB_CACHE_COUNT]; /*!< Number of slab caches. */
} slab_alloc_t;

/*!
 * \brief Create a slab of predefined size.
 *
 * At the moment, slabs are equal to page size and page size aligned.
 * This enables quick and efficient buf to slab lookup by pointer arithmetic.
 *
 * Slab uses simple coloring scheme with and the memory block is always
 * sizeof(void*) aligned.
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
 * \brief Create a general purpose slab allocator.
 *
 * \note Please consult struct slab_alloc_t for performance hints.
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
 * \note Please consult struct slab_alloc_t for performance hints.
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

#endif /* _CUTEDNS_SLAB_H_ */

/*! \} */
