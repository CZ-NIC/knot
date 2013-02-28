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
 * \ref SLAB_SIZE is a fixed size of a slab. As a rule of thumb, the slab is
 * effective when the maximum allocated block size is below 1/4 of a SLAB_SIZE.
 * f.e. 16kB SLAB is most effective up to 4kB block size.
 *
 * \ref MEM_POISON flag enables checking read/writes after the allocated memory
 * and segmentation fault. This poses a significant time and space overhead.
 * Enable only when debugging.
 *
 * \ref MEM_SLAB_CAP defines a maximum limit of a number of empty slabs that a cache
 * can keep at a time. This results in a slight performance regression,
 * but actively recycles unuse memory.
 *
 * \ref MEM_DEPOT_COUNT defines how many recycled slabs will be cached for a later
 * use instead of returning them immediately to the OS. This significantly
 * reduces a number of syscalls in some cases.
 * f.e. 16 means 16 * SLAB_SIZE cache, for 16kB slabs = 256kB cache
 *
 * \ref MEM_COLORING enables simple cache coloring. This is generally a useful
 *      feature since all slabs are page size aligned and
 *      (depending on architecture) this slightly improves performance
 *      and cacheline usage at the cost of a minimum of 64 bytes per slab of
 *      overhead. Undefine MEM_COLORING in common.h to disable coloring.
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
 *
 * \todo Allocate slab headers elsewhere and use just first sizeof(void*) bytes
 *       in each slab as a pointer to slab header. This could improve the
 *       performance (issue #1583).
 *
 * \note Slab allocation is not thread safe for performance reasons.
 *
 * \addtogroup alloc
 * @{
 */

#ifndef _KNOTD_COMMON_SLAB_H_
#define _KNOTD_COMMON_SLAB_H_

#include <pthread.h>
#include <stdint.h>

/* Constants. */
#define SLAB_MINSIZE 4096  //!< Slab minimal size (4K blocks)
#define SLAB_MIN_BUFLEN 8  //!< Minimal allocation block size is 8B.
#define SLAB_DEPOT_SIZE 16 //!< N slabs cached = N*SLAB_SIZE kB cap
struct slab_cache_t;
extern size_t SLAB_MASK;

/* Macros. */

/*! \brief Return slab base address from pointer. */
#define slab_from_ptr(p) ((void*)((size_t)(p) & SLAB_MASK))

/*! \brief Return true if slab is empty. */
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
	unsigned short bufsize;     /*!< Slab bufsize. */
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
 */
typedef struct slab_depot_t {
	size_t available;               /*!< Number of available pages. */
	slab_t* cache[SLAB_DEPOT_SIZE]; /*!< Stack of free slabs. */
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
 * Allocation of new slabs is on-demand, empty slabs are reused if possible.
 *
 * \note Slab implementation is different from Bonwick (Usenix 2001)
 *       http://www.usenix.org/event/usenix01/bonwick.html
 *       as it doesn't feature empty and partial list.
 *       This is due to fact, that user space allocator rarely
 *       needs to count free slabs. There is no way the OS could
 *       notify the application, that the memory is scarce.
 *       A slight performance increased is measured in benchmark.
 *
 * \note Statistics are only available if MEM_DEBUG is enabled.
 */
typedef struct slab_cache_t {
	unsigned short color;    /*!< Current cache color. */
	unsigned short empty;    /*!< Number of empty slabs. */
	size_t bufsize;          /*!< Cache object (buf) size. */
	slab_t *slabs_free;      /*!< List of free slabs. */
	slab_t *slabs_full;      /*!< List of full slabs. */

	/* Statistics. */
	unsigned long stat_allocs; /*!< Allocation count. */
	unsigned long stat_frees;  /*!< Free count. */
} slab_cache_t;

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

#endif /* _KNOTD_COMMON_SLAB_H_ */

/*! @} */
