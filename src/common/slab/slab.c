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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "common/slab/alloc-common.h"
#include "common/slab/slab.h"

/*
 * Magic constants.
 */
#define SLAB_MAGIC    0x51  /*!< "Sl" magic byte (slab type). */
#define POISON_DWORD  0xdeadbeef /*!< Memory boundary guard magic. */
#define SLAB_MINCOLOR 64 /*!< Minimum space reserved for cache coloring. */


/*! \brief Return binary logarithm of a number, which is a power of 2. */
static inline unsigned fastlog2(unsigned v)
{
	// Works if we know the size is a power of 2
	register unsigned int r = (v & 0xAAAAAAAA) != 0;
	r |= ((v & 0xFFFF0000) != 0) << 4;
	r |= ((v & 0xFF00FF00) != 0) << 3;
	r |= ((v & 0xF0F0F0F0) != 0) << 2;
	r |= ((v & 0xCCCCCCCC) != 0) << 1;
	return r;
}

/*
 * Slab run-time constants.
 */

size_t SLAB_SZ = 0; /*!< Slab size. */
size_t SLAB_MASK = 0; /*!< \brief Slab address mask (for computing offsets). */

/*!
 * Depot is a caching sub-allocator of slabs.
 * It mitigates performance impact of sequentially allocating and freeing
 * from a slab with just a few slab items by caching N slabs before returning
 * them to the system.
 *
 */
#ifdef MEM_SLAB_DEPOT
static slab_depot_t _depot_g; /*! \brief Global slab depot. */
#endif // MEM_SLAB_DEPOT

/*!
 * \brief Allocate a slab of given bufsize from depot.
 *
 * \retval Reserved memory for slab on success.
 * \retval NULL on errors.
 */
static void* slab_depot_alloc(size_t bufsize)
{
	void *page = 0;
#ifdef MEM_SLAB_DEPOT
	if (_depot_g.available) {
		for (int i = _depot_g.available - 1; i > -1 ; --i) {
			if(_depot_g.cache[i]->bufsize == bufsize) {
				page = _depot_g.cache[i];
				_depot_g.cache[i] = _depot_g.cache[--_depot_g.available];
				return page;
			}
		}
		page = _depot_g.cache[--_depot_g.available];
	} else {
		if(posix_memalign(&page, SLAB_SIZE, SLAB_SIZE) == 0) {
			((slab_t*)page)->bufsize = 0;
		} else {
			page = 0;
		}

	}
#else // MEM_SLAB_DEPOT
	UNUSED(bufsize);
	if(posix_memalign(&page, SLAB_SZ, SLAB_SZ) == 0) {
		((slab_t*)page)->bufsize = 0;
	} else {
		page = 0;
	}
#endif // MEM_SLAB_DEPOT
	UNUSED(bufsize);

	return page;
}

/*!
 * \brief Return a slab to the depot.
 *
 * \note If the depot is full, slab gets immediately freed.
 */
static inline void slab_depot_free(void* slab)
{
#ifdef MEM_SLAB_DEPOT
	if (_depot_g.available < SLAB_DEPOT_SIZE) {
		_depot_g.cache[_depot_g.available++] = slab;
	} else {
		free(slab);
	}
#else // MEM_SLAB_DEPOT
    free(slab);
#endif // MEM_SLAB_DEPOT
}

/*! \brief Initialize slab depot. */
static void slab_depot_init()
{
#ifdef MEM_SLAB_DEPOT
	_depot_g.available = 0;
#endif // MEM_SLAB_DEPOT
}

/*! \brief Destroy slab depot. */
static void slab_depot_destroy()
{
#ifdef MEM_SLAB_DEPOT
	while(_depot_g.available) {
		free(_depot_g.cache[--_depot_g.available]);
	}
#endif // MEM_SLAB_DEPOT
}

/*
 * Initializers.
 */

/*! \brief Initializes slab subsystem (it is called automatically). */
void __attribute__ ((constructor)) slab_init()
{
	long slab_size = sysconf(_SC_PAGESIZE);
	if (slab_size < 0) {
		slab_size = SLAB_MINSIZE;
	}

	// Fetch page size
	SLAB_SZ = (size_t)slab_size;
	unsigned slab_logsz = fastlog2(SLAB_SZ);

	// Compute slab page mask
	SLAB_MASK = 0;
	for (unsigned i = 0; i < slab_logsz; ++i) {
		SLAB_MASK |= 1 << i;
	}
	SLAB_MASK = ~SLAB_MASK;

	// Initialize depot
	slab_depot_init();
}

/*! \brief Deinitializes slab subsystem (it is called automatically). */
void __attribute__ ((destructor)) slab_deinit()
{
	// Deinitialize depot
	if (SLAB_MASK) {
		slab_depot_destroy();
	}
}

/*
 * Cache helper functions.
 */

/* \note Not used right now.
static void slab_dump(slab_t* slab) {

	printf("%s: buffers (bufsize=%zuB, %u/%u free): \n",
	       __func__, slab->cache->bufsize, slab->bufs_free,
	       slab->bufs_count);

	void** buf = slab->head;
	int i = 0, n = 0;
	while(buf != 0) {
		size_t diff = (size_t)((char*)buf - (char*)slab->base);
		printf("-> %lu", diff / slab->cache->bufsize);
		buf = (void**)(*buf);
		if (++i == 10) {
			printf("\n");
			i = 0;
		}
		++n;
	}

	printf("\n");
}
*/

/*!
 * \brief Free all slabs from a slab cache.
 * \return Number of freed slabs.
 */
static inline int slab_cache_free_slabs(slab_t* slab)
{
	int count = 0;
	while (slab) {
		slab_t* next = slab->next;
		slab_destroy(&slab);
		++count;
		slab = next;

	}
	return count;
}

/*
 * Slab helper functions.
 */

/*! \brief Return number of slabs in a linked list. */
static inline unsigned slab_list_walk(slab_t* slab)
{
	unsigned count = 0;
	while(slab) {
		slab = slab->next;
		++count;
	}
	return count;
}

/*! \brief Remove slab from a linked list. */
static void slab_list_remove(slab_t* slab)
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
	{
		if (cache->slabs_free == slab) {
			cache->slabs_free = slab->next;
		} else if (cache->slabs_full == slab) {
			cache->slabs_full = slab->next;
		}
	}
}

/*! \brief Insert slab into a linked list. */
static void slab_list_insert(slab_t** list, slab_t* item)
{
	// If list exists, push to the top
	item->prev = 0;
	item->next = *list;
	if(*list) {
		(*list)->prev = item;
	}
	*list = item;
}

/*! \brief Move slab from one linked list to another. */
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
	const size_t size = SLAB_SZ;

	slab_t* slab = slab_depot_alloc(cache->bufsize);

	if (knot_unlikely(slab == 0)) {
		dbg_mem("%s: failed to allocate aligned memory block\n",
		          __func__);
		return 0;
	}

	/* Initialize slab. */
	slab->magic = SLAB_MAGIC;
	slab->cache = cache;
	slab_list_insert(&cache->slabs_free, slab);
#ifdef MEM_SLAB_CAP
	++cache->empty;
#endif

	/* Already initialized? */
	if (slab->bufsize == cache->bufsize) {
		return slab;
	} else {
		slab->bufsize = cache->bufsize;
	}

	/* Ensure the item size can hold at least a size of ptr. */
	size_t item_size = slab->bufsize;
	if (knot_unlikely(item_size < SLAB_MIN_BUFLEN)) {
		item_size = SLAB_MIN_BUFLEN;
	}

	/* Ensure at least some space for coloring */
	size_t data_size = size - sizeof(slab_t);
#ifdef MEM_COLORING
	size_t free_space = data_size % item_size;
	if (knot_unlikely(free_space < SLAB_MINCOLOR)) {
		free_space = SLAB_MINCOLOR;
	}


	/// unsigned short color = __sync_fetch_and_add(&cache->color, 1);
	unsigned short color = (cache->color += sizeof(void*));
	color = color % free_space;
#else
	const unsigned short color = 0;
#endif

	/* Calculate useable data size */
	data_size -= color;
	slab->bufs_count = data_size / item_size;
	slab->bufs_free = slab->bufs_count;

	// Save first item as next free
	slab->base = (char*)slab + sizeof(slab_t) + color;
	slab->head = (void**)slab->base;

	// Create freelist, skip last member, which is set to NULL
	char* item = (char*)slab->head;
	for(unsigned i = 0; i < slab->bufs_count - 1; ++i) {
		*((void**)item) = item + item_size;
		item += item_size;
	}

	// Set last buf to NULL (tail)
	*((void**)item) = (void*)0;

	// Ensure the last item has a NULL next
	dbg_mem("%s: created slab (%p, %p) (%zu B)\n",
	          __func__, slab, slab + size, size);
	return slab;
}

void slab_destroy(slab_t** slab)
{
	/* Disconnect from the list */
	slab_list_remove(*slab);

	/* Free slab */
	slab_depot_free(*slab);

	/* Invalidate pointer. */
	dbg_mem("%s: deleted slab %p\n", __func__, *slab);
	*slab = 0;
}

void* slab_alloc(slab_t* slab)
{
	// Fetch first free item
	void **item = 0;
	{
		if((item = slab->head)) {
			slab->head = (void**)*item;
			--slab->bufs_free;
		} else {
			// No more free items
			return 0;
		}
	}

#ifdef MEM_DEBUG
	// Increment statistics
	__sync_add_and_fetch(&slab->cache->stat_allocs, 1);
#endif

	// Move to full?
	if (knot_unlikely(slab->bufs_free == 0)) {
		slab_list_move(&slab->cache->slabs_full, slab);
	} else {
#ifdef MEM_SLAB_CAP
		// Mark not empty?
		if (knot_unlikely(slab->bufs_free == slab->bufs_count - 1)) {
			--slab->cache->empty;
		}
#endif
	}

	return item;
}

void slab_free(void* ptr)
{
	// Null pointer check
	if (knot_unlikely(!ptr)) {
		return;
	}

	// Get slab start address
	slab_t* slab = slab_from_ptr(ptr);
	assert(slab);

	// Check if it exists in directory
	if (slab->magic == SLAB_MAGIC) {

		// Return buf to slab
		*((void**)ptr) = (void*)slab->head;
		slab->head = (void**)ptr;
		++slab->bufs_free;

#ifdef MEM_DEBUG
		// Increment statistics
		__sync_add_and_fetch(&slab->cache->stat_frees, 1);
#endif

		// Return to partial
		if(knot_unlikely(slab->bufs_free == 1)) {
			slab_list_move(&slab->cache->slabs_free, slab);
		} else {
#ifdef MEM_SLAB_CAP
		// Recycle if empty
			if(knot_unlikely(slab_isempty(slab))) {
				if(slab->cache->empty == MEM_SLAB_CAP) {
					slab_destroy(&slab);
				} else {
					++slab->cache->empty;
				}
			}
#endif
		}

	} else {

		// Pointer is not a slab
		// Presuming it's a large block
		slab_obj_t* bs = (slab_obj_t*)ptr - 1;

#ifdef MEM_POISON
		// Remove memory barrier
		mprotect(ptr + bs->size, sizeof(int), PROT_READ|PROT_WRITE);
#endif

		// Unmap
		dbg_mem("%s: unmapping large block of %zu bytes at %p\n",
		          __func__, bs->size, ptr);
		free(bs);
	}
}

int slab_cache_init(slab_cache_t* cache, size_t bufsize)
{
	if (knot_unlikely(!bufsize)) {
		return -1;
	}

	memset(cache, 0, sizeof(slab_cache_t));
	cache->bufsize = bufsize;
	dbg_mem("%s: created cache of size %zu\n",
	          __func__, bufsize);

	return 0;
}

void slab_cache_destroy(slab_cache_t* cache) {

	// Free slabs
	unsigned free_s = slab_cache_free_slabs(cache->slabs_free);
	unsigned full_s = slab_cache_free_slabs(cache->slabs_full);
#ifndef MEM_DEBUG
	UNUSED(free_s);
	UNUSED(full_s);
#else
	dbg_mem("%s: %u empty/partial, %u full caches\n",
	          __func__, free_s, full_s);
#endif

	// Invalidate cache
	cache->bufsize = 0;
	cache->slabs_free = cache->slabs_full = 0;
}

void* slab_cache_alloc(slab_cache_t* cache)
{
	slab_t* slab = cache->slabs_free;
	if(!cache->slabs_free) {
		slab = slab_create(cache);
		if (slab == NULL) {
			return NULL;
		}
	}


	return slab_alloc(slab);
}

int slab_cache_reap(slab_cache_t* cache)
{
	// For now, just free empty slabs
	slab_t* slab = cache->slabs_free;
	int count = 0;
	while (slab) {
		slab_t* next = slab->next;
		if (slab_isempty(slab)) {
			slab_destroy(&slab);
			++count;
		}
		slab = next;

	}

	cache->empty = 0;
	return count;
}
