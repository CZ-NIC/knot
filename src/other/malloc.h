#ifndef __CUTEDNS_MALLOC_H__
#define __CUTEDNS_MALLOC_H__

#include <stdlib.h>

#include "debug.h"

/* Redirect malloc only if debugging.
 */
#ifdef MEM_DEBUG

/*! \brief Redirected malloc() call.
 *
 *  This function logs malloc() call with the associated metadata.
 *
 * \param caller - Name of the caller function.
 * \param line   - Number of the line in current caller function.
 * \param size   - Requested block size.
 * \return Result of malloc(size).
 */
void *log_malloc(const char *caller, int line, size_t size);

/* Rewrite original malloc. */
#define malloc(x) log_malloc(__func__, __LINE__, (x))
#else

/* If not MEM_NOSLAB is defined, use slab as GP allocator. */
#ifndef MEM_NOSLAB
#include "slab.h"

void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);

/*
#define malloc(x) slab_alloc_g((x))
#define calloc(n, x) memset(slab_alloc_g((n)*(x)), 0, (n)*(x))
#define realloc(x, sz) slab_realloc_g((x), (sz))
#define free(x) slab_free((x))
*/
/* Memory is MEM_NOSLAB. */
#else
#endif

#endif

#endif
