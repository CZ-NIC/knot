#ifndef __CUTEDNS_MALLOC_H__
#define __CUTEDNS_MALLOC_H__

#include <stdlib.h>
#include "debug.h"

/* If not MEM_NOSLAB is defined, use slab as GP allocator. */
#ifndef MEM_NOSLAB
#include "slab.h"

/*void *malloc(size_t size);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
void free(void *ptr);*/


#define malloc(x) slab_alloc_g((x))
#define calloc(n, x) memset(slab_alloc_g((n)*(x)), 0, (n)*(x))
#define realloc(x, sz) slab_realloc_g((x), (sz))
#define free(x) slab_free((x))

/* Memory is MEM_NOSLAB. */
#else
#endif

#endif
