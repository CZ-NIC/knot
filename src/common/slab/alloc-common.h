/*!
 * \file alloc-common.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Common macros for alloc.
 *
 * \addtogroup alloc
 * @{
 */

#ifndef _KNOTD_COMMON_ALLOC_COMMON_H_
#define _KNOTD_COMMON_ALLOC_COMMON_H_

#include <stdio.h>

//#define MEM_DEBUG
//#define MEM_NOSLAB
//#define MEM_POISON
#define MEM_SLAB_CAP 5   // Cap slab_cache empty slab count (undefined = inf)
#define MEM_COLORING       // Slab cache coloring
//#define MEM_SLAB_DEPOT     // Use slab depot for slab caching (not thread-safe)

/* Eliminate compiler warning with unused parameters. */
#ifndef UNUSED
#define UNUSED(param) (void)(param)
#endif

/* Optimisation macros. */
#ifndef likely
#define likely(x)       __builtin_expect((x),1)
#endif
#ifndef unlikely
#define unlikely(x)     __builtin_expect((x),0)
#endif

#ifdef MEM_DEBUG
#define dbg_mem(msg...) fprintf(stderr, msg)
#else
#define dbg_mem(msg...)
#endif


#endif /* _KNOTD_COMMON_ALLOC_COMMON_H_ */

/*! @} */
