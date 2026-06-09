/*
 *  UCW Library -- Memory Pools
 *
 *  (c) 1997--2015 Martin Mares <mj@ucw.cz>
 *  (c) 2007 Pavel Charvat <pchar@ucw.cz>
 *  (c) 2015, 2017, 2026 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *  SPDX-License-Identifier: LGPL-2.1-or-later
 *  Source: https://www.ucw.cz/libucw/
 */

#pragma once

#include <string.h>
#include <stdint.h>

#define CPU_STRUCT_ALIGN (sizeof(void*))

/***
 * [[defs]]
 * Definitions
 * -----------
 ***/

/**
 * Memory pool state (see mp_push(), ...).
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool_state {
	size_t free[2];
	void *last[2];
};

/**
 * Memory pool.
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool {
	struct mempool_state state;
	void *unused, *last_big;
	size_t chunk_size, threshold;
	unsigned idx;
};

struct mempool_stats {          /** Mempool statistics. See mp_stats(). **/
	uint64_t total_size;            /** Real allocated size in bytes. */
	uint64_t used_size;             /** Estimated size allocated from mempool to application. */
	unsigned chain_count[3];        /** Number of allocated chunks in small/big/unused chains. */
	uint64_t chain_size[3];         /** Size of allocated chunks in small/big/unused chains. */
};

/***
 * [[basic]]
 * Basic manipulation
 * ------------------
 ***/

/**
 * Initialize a given mempool structure.
 * \p chunk_size must be in the interval `[1, SIZE_MAX / 2]`.
 * It will allocate memory by this large chunks and take
 * memory to satisfy requests from them.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
void mp_init(struct mempool *pool, size_t chunk_size);

/**
 * Allocate and initialize a new memory pool.
 * See \ref mp_init() for \p chunk_size limitations.
 *
 * The new mempool structure is allocated on the new mempool.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
struct mempool *mp_new(size_t chunk_size);

/**
 * Cleanup mempool initialized by mp_init or mp_new.
 * Frees all the memory allocated by this mempool and,
 * if created by \ref mp_new(), the \p pool itself.
 **/
void mp_delete(struct mempool *pool);

/**
 * Frees all data on a memory pool, but leaves it working.
 * It can keep some of the chunks allocated to serve
 * further allocation requests. Leaves the \p pool alive,
 * even if it was created with \ref mp_new().
 **/
void mp_flush(struct mempool *pool);

/**
 * Compute some statistics for debug purposes.
 * See the definition of the <<struct_mempool_stats,mempool_stats structure>>.
 * This function scans the chunk list, so it can be slow.
 **/
void mp_stats(struct mempool *pool, struct mempool_stats *stats);

/**
 * Return how many bytes were allocated by the pool, including unused parts
 * of chunks. This function scans the chunk list, so it can be slow
 * (upstream contains constant-time version).
 **/
uint64_t mp_total_size(struct mempool *pool);

/**
 * Release unused chunks of memory reserved for further allocation
 * requests, but stop if \ref mp_total_size() would drop below \p min_total_size.
 * It calls \ref mp_total_size(), so all chunks are scanned (in upstream version only released ones).
 **/
void mp_shrink(struct mempool *pool, uint64_t min_total_size);

/***
 * [[alloc]]
 * Allocation routines
 * -------------------
 ***/

/**
 * The function allocates new \p size bytes on a given memory pool.
 * If the \p size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations.
 **/
void *mp_alloc(struct mempool *pool, size_t size);

/**
 * The same as \ref mp_alloc(), but the result may be unaligned.
 **/
void *mp_alloc_noalign(struct mempool *pool, size_t size);

/*
 * Some parts of mempools were removed in Knot DNS,
 * see upstream if you need:
     * variants of methods returning zeroed memory,
     * restoring previous state of allocations,
     * concatenating and duplicating memory/strings on mempools,
     * generic allocator interface spanning both malloc and mempools,
     * growing buffers,
     * printf-like functions using growing buffers as output,
     * constant-time version of mp_total_size and mp_shrink scanning only deallocated chunks.
*/
