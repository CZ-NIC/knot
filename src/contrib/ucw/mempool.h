/*
 *	UCW Library -- Memory Pools
 *
 *	(c) 1997--2005 Martin Mares <mj@ucw.cz>
 *	(c) 2007 Pavel Charvat <pchar@ucw.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

#pragma once

#include <string.h>
#include <stdint.h>

#if __GNUC__ >= 4
#define LIKE_MALLOC __attribute__((malloc))                             /** Function returns a "new" pointer **/
#define SENTINEL_CHECK __attribute__((sentinel))                        /** The last argument must be NULL **/
#else
#define LIKE_MALLOC
#define SENTINEL_CHECK
#endif

#define CPU_STRUCT_ALIGN (sizeof(void*))

/***
 * [[defs]]
 * Definitions
 * -----------
 ***/

/**
 * Memory pool state (see @mp_push(), ...).
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool_state {
  unsigned free[2];
  void *last[2];
  struct mempool_state *next;
};

/**
 * Memory pool.
 * You should use this one as an opaque handle only, the insides are internal.
 **/
struct mempool {
  struct mempool_state state;
  void *unused, *last_big;
  unsigned chunk_size, threshold, idx;
};

struct mempool_stats {			/** Mempool statistics. See @mp_stats(). **/
  uint64_t total_size;			/* Real allocated size in bytes */
  unsigned chain_count[3];			/* Number of allocated chunks in small/big/unused chains */
  unsigned chain_size[3];			/* Size of allocated chunks in small/big/unused chains */
};

/***
 * [[basic]]
 * Basic manipulation
 * ------------------
 ***/

/**
 * Initialize a given mempool structure.
 * @chunk_size must be in the interval `[1, UINT_MAX / 2]`.
 * It will allocate memory by this large chunks and take
 * memory to satisfy requests from them.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
void mp_init(struct mempool *pool, unsigned chunk_size);

/**
 * Allocate and initialize a new memory pool.
 * See @mp_init() for @chunk_size limitations.
 *
 * The new mempool structure is allocated on the new mempool.
 *
 * Memory pools can be treated as <<trans:respools,resources>>, see <<trans:res_mempool()>>.
 **/
struct mempool *mp_new(unsigned chunk_size);

/**
 * Cleanup mempool initialized by mp_init or mp_new.
 * Frees all the memory allocated by this mempool and,
 * if created by @mp_new(), the @pool itself.
 **/
void mp_delete(struct mempool *pool);

/**
 * Frees all data on a memory pool, but leaves it working.
 * It can keep some of the chunks allocated to serve
 * further allocation requests. Leaves the @pool alive,
 * even if it was created with @mp_new().
 **/
void mp_flush(struct mempool *pool);

/**
 * Compute some statistics for debug purposes.
 * See the definition of the <<struct_mempool_stats,mempool_stats structure>>.
 **/
void mp_stats(struct mempool *pool, struct mempool_stats *stats);
uint64_t mp_total_size(struct mempool *pool);	/** How many bytes were allocated by the pool. **/

/***
 * [[alloc]]
 * Allocation routines
 * -------------------
 ***/

/* For internal use only, do not call directly */
void *mp_alloc_internal(struct mempool *pool, unsigned size) LIKE_MALLOC;

/**
 * The function allocates new @size bytes on a given memory pool.
 * If the @size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations.
 **/
void *mp_alloc(struct mempool *pool, unsigned size);

/**
 * The same as @mp_alloc(), but the result may be unaligned.
 **/
void *mp_alloc_noalign(struct mempool *pool, unsigned size);

/**
 * The same as @mp_alloc(), but fills the newly allocated memory with zeroes.
 **/
void *mp_alloc_zero(struct mempool *pool, unsigned size);

/***
 * [[gbuf]]
 * Growing buffers
 * ---------------
 *
 * You do not need to know, how a buffer will need to be large,
 * you can grow it incrementally to needed size. You can grow only
 * one buffer at a time on a given mempool.
 *
 * Similar functionality is provided by <<growbuf:,growing buffes>> module.
 ***/

/* For internal use only, do not call directly */
void *mp_start_internal(struct mempool *pool, unsigned size) LIKE_MALLOC;
void *mp_grow_internal(struct mempool *pool, unsigned size);
void *mp_spread_internal(struct mempool *pool, void *p, unsigned size);

static inline unsigned
mp_idx(struct mempool *pool, void *ptr)
{
  return ptr == pool->last_big;
}

/**
 * Open a new growing buffer (at least @size bytes long).
 * If the @size is zero, the resulting pointer is undefined,
 * but it may be safely reallocated or used as the parameter
 * to other functions below.
 *
 * The resulting pointer is always aligned to a multiple of
 * `CPU_STRUCT_ALIGN` bytes and this condition remains true also
 * after future reallocations. There is an unaligned version as well.
 *
 * Keep in mind that you can't make any other pool allocations
 * before you "close" the growing buffer with @mp_end().
 */
void *mp_start(struct mempool *pool, unsigned size);
void *mp_start_noalign(struct mempool *pool, unsigned size);

/**
 * Inlined version of @mp_start().
 **/
static inline void *mp_start_fast(struct mempool *pool, unsigned size)
{
  unsigned avail = pool->state.free[0] & ~(CPU_STRUCT_ALIGN - 1);
  if (size <= avail)
    {
      pool->idx = 0;
      pool->state.free[0] = avail;
      return (uint8_t*)pool->state.last[0] - avail;
    }
  else
    return mp_start_internal(pool, size);
}

/**
 * Inlined version of @mp_start_noalign().
 **/
static inline void *mp_start_fast_noalign(struct mempool *pool, unsigned size)
{
  if (size <= pool->state.free[0])
    {
      pool->idx = 0;
      return (uint8_t*)pool->state.last[0] - pool->state.free[0];
    }
  else
    return mp_start_internal(pool, size);
}

/**
 * Return start pointer of the growing buffer allocated by latest @mp_start() or a similar function.
 **/
static inline void *mp_ptr(struct mempool *pool)
{
  return (uint8_t*)pool->state.last[pool->idx] - pool->state.free[pool->idx];
}

/**
 * Return the number of bytes available for extending the growing buffer.
 * (Before a reallocation will be needed).
 **/
static inline unsigned mp_avail(struct mempool *pool)
{
  return pool->state.free[pool->idx];
}

/**
 * Grow the buffer allocated by @mp_start() to be at least @size bytes long
 * (@size may be less than @mp_avail(), even zero). Reallocated buffer may
 * change its starting position. The content will be unchanged to the minimum
 * of the old and new sizes; newly allocated memory will be uninitialized.
 * Multiple calls to mp_grow() have amortized linear cost wrt. the maximum value of @size. */
static inline void *mp_grow(struct mempool *pool, unsigned size)
{
  return (size <= mp_avail(pool)) ? mp_ptr(pool) : mp_grow_internal(pool, size);
}

/**
 * Grow the buffer by at least one uint8_t-- equivalent to <<mp_grow(),`mp_grow`>>`(@pool, @mp_avail(pool) + 1)`.
 **/
static inline void *mp_expand(struct mempool *pool)
{
  return mp_grow_internal(pool, mp_avail(pool) + 1);
}

/**
 * Ensure that there is at least @size bytes free after @p,
 * if not, reallocate and adjust @p.
 **/
static inline void *mp_spread(struct mempool *pool, void *p, unsigned size)
{
  return (((unsigned)((uint8_t*)pool->state.last[pool->idx] - (uint8_t*)p) >= size) ? p : mp_spread_internal(pool, p, size));
}

/**
 * Close the growing buffer. The @end must point just behind the data, you want to keep
 * allocated (so it can be in the interval `[@mp_ptr(@pool), @mp_ptr(@pool) + @mp_avail(@pool)]`).
 * Returns a pointer to the beginning of the just closed block.
 **/
static inline void *mp_end(struct mempool *pool, void *end)
{
  void *p = mp_ptr(pool);
  pool->state.free[pool->idx] = (uint8_t*)pool->state.last[pool->idx] - (uint8_t*)end;
  return p;
}

/**
 * Return size in bytes of the last allocated memory block (with @mp_alloc() or @mp_end()).
 **/
static inline unsigned mp_size(struct mempool *pool, void *ptr)
{
  unsigned idx = mp_idx(pool, ptr);
  return ((uint8_t*)pool->state.last[idx] - (uint8_t*)ptr) - pool->state.free[idx];
}

/**
 * Open the last memory block (allocated with @mp_alloc() or @mp_end())
 * for growing and return its size in bytes. The contents and the start pointer
 * remain unchanged. Do not forget to call @mp_end() to close it.
 **/
unsigned mp_open(struct mempool *pool, void *ptr);

/**
 * Inlined version of mp_open().
 **/
static inline unsigned mp_open_fast(struct mempool *pool, void *ptr)
{
  pool->idx = mp_idx(pool, ptr);
  unsigned size = ((uint8_t*)pool->state.last[pool->idx] - (uint8_t*)ptr) - pool->state.free[pool->idx];
  pool->state.free[pool->idx] += size;
  return size;
}

/**
 * Reallocate the last memory block (allocated with @mp_alloc() or @mp_end())
 * to the new @size. Behavior is similar to @mp_grow(), but the resulting
 * block is closed.
 **/
void *mp_realloc(struct mempool *pool, void *ptr, unsigned size);

/**
 * The same as @mp_realloc(), but fills the additional bytes (if any) with zeroes.
 **/
void *mp_realloc_zero(struct mempool *pool, void *ptr, unsigned size);

/**
 * Inlined version of mp_realloc().
 **/
static inline void *mp_realloc_fast(struct mempool *pool, void *ptr, unsigned size)
{
  mp_open_fast(pool, ptr);
  ptr = mp_grow(pool, size);
  mp_end(pool, (uint8_t*)ptr + size);
  return ptr;
}
