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

#ifndef _KNOT_COMMON_ALLOC_COMMON_H_
#define _KNOT_COMMON_ALLOC_COMMON_H_

#include <stdio.h>

//#define MEM_DEBUG
//#define MEM_NOSLAB
//#define MEM_POISON
//#define MEM_SLAB_CAP 3   // Cap slab_cache empty slab count (undefined = inf)
#define MEM_COLORING       // Slab cache coloring

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
#define debug_mem(msg...) fprintf(stderr, msg)
#else
#define debug_mem(msg...)
#endif


#endif /* _KNOT_COMMON_ALLOC_COMMON_H_ */

/*! @} */
