#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <unistd.h>

#include "slab.h"

slab_t* slab_create(slab_cache_t* cache, size_t size)
{
	slab_t* slab = valloc(size);
	slab->parent = cache;
	// { critical section
	slab->next = cache->free;
	cache->free = slab->next;
	// } critical section
	slab->size = size;
	fprintf(stderr, "%s: created slab (%p, %p) (%u B)\n",
	        __func__, slab, slab + size, (unsigned)size);
	fprintf(stderr, "%s: parent = %p, next slab = %p\n",
	        __func__, cache, slab->next);

	// OPTIMIZE
	unsigned item_size = cache->item_size;
	fprintf(stderr, "%s: item_size = %u\n",
	        __func__, item_size);
	if (item_size < sizeof(void*)) {
		fprintf(stderr, "!! %s: item_size = %u -> %u\n",
		        __func__, item_size, (unsigned)sizeof(void*));
		item_size = sizeof(void*);
	}

	// Ensure at least some space for coloring
	unsigned data_size = size - sizeof(slab_t);
	unsigned free_space = (data_size % item_size);
	if(free_space < 64) {
		free_space = 64;
	}

	// { critical section
	slab->color = cache->next_color % free_space;
	cache->next_color += 8;
	fprintf(stderr, "%s: color = %u\n",
	        __func__, slab->color);
	// } critical section

	// Calculate useable data size
	data_size -= slab->color;
	fprintf(stderr, "%s: data_size = %u\n",
	        __func__, data_size);

	unsigned item_count = data_size / item_size;
	fprintf(stderr, "%s: max_item_count = %u\n",
	        __func__, item_count);

	// Save first item as next free
	char* item = slab->pool + slab->color;
	slab->next_free = item;
	fprintf(stderr, "%s: address space (%p, %p)\n",
	        __func__, item, item + data_size - item_size);

	// Create freelist
	for(unsigned i = 0; i < item_count - 1; ++i) {
		*((void**)item) = item + item_size;
		item += item_size;
	}
	*((void**)item) = (void*)0;

	// Ensure the last item has a NULL next
	fprintf(stderr, "%s: return = %p\n",
	        __func__, slab);
	return slab;
}

void slab_delete(slab_t** slab)
{
	free(*slab);
	fprintf(stderr, "%s: deleted slab %p\n",
	        __func__, *slab);
	*slab = 0;
}

void* slab_alloc(slab_t* slab)
{
	void** item =  (void**)slab->next_free;
	if (item == 0) {
		return 0;
	}
	unsigned long offset = slab->color - (unsigned long)slab->pool;
	fprintf(stderr, "%s: allocd item %lu from slab %p, next free is %lu\n",
	        __func__,
	        (unsigned long)item - offset,
	        slab,
	        (unsigned long)*item - offset);
	slab->next_free = *item;
	return item;
}

void slab_free(void* ptr)
{
	long page_size = sysconf(_SC_PAGESIZE);
	slab_t* slab = (slab_t*)((char*)ptr - ((unsigned long)ptr % page_size));
	fprintf(stderr, "%s: pointer %p belongs to slab %p\n",
	        __func__, ptr, slab);
	void** item = (void**)ptr;
	unsigned long offset = slab->color - (unsigned long)slab->pool;
	fprintf(stderr, "%s: prev_free %lu, next free %lu\n",
	        __func__,
	        (unsigned long)slab->next_free - offset,
	        (unsigned long)item - offset);
	*item = slab->next_free;
	slab->next_free = item;
}

slab_cache_t* slab_cache_create(size_t item_size);
void slab_cache_delete(slab_cache_t** cache);
void* slab_cache_alloc(slab_cache_t* cache);
int slab_cache_reap(slab_cache_t* cache);

