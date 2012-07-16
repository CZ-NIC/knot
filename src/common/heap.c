/*
 *	Universal Heap Macros
 *
 *	(c) 2012 Ondrej Filip <feela@network.cz>
 *
 *	This software may be freely distributed and used according to the terms
 *	of the GNU Lesser General Public License.
 */

/***
 * [[intro]]
 * Introduction
 * ------------
 *
 * Binary heap is a simple data structure, which for example supports efficient insertions, deletions
 * and access to the minimal inserted item. We define several macros for such operations.
 * Note that because of simplicity of heaps, we have decided to define direct macros instead
 * of a <<generic:,macro generator>> as for several other data structures in the Libucw.
 *
 * A heap is represented by a number of elements and by an array of values. Beware that we
 * index this array from one, not from zero as do the standard C arrays.
 *
 * Most macros use these parameters:
 *
 * - @type - the type of elements
 * - @num - a variable (signed or unsigned integer) with the number of elements
 * - @heap - a C array of type @type; the heap is stored in `heap[1] .. heap[num]`; `heap[0]` is unused
 * - @less - a callback to compare two element values; `less(x, y)` shall return a non-zero value iff @x is lower than @y
 * - @swap - a callback to swap two array elements; `swap(heap, i, j, t)` must swap `heap[i]` with `heap[j]` with possible help of temporary variable @t (type @type).
 *
 * A valid heap must follow these rules:
 *
 * - `num >= 0`
 * - `heap[i] >= heap[i / 2]` for each `i` in `[2, num]`
 *
 * The first element `heap[1]` is always lower or equal to all other elements.
 *
 * [[macros]]
 * Macros
 * ------
 ***/

#include "heap.h"
#include <string.h>
#include <stdlib.h>

void _def_swap(struct heap *h, void *e1, void *e2)
{
	if (e1 == e2) return;
	void *tmp = HTEMPELEMENT(h);
	memcpy(tmp, e1, h->elm_size);
	memcpy(e1, e2, h->elm_size);
	memcpy(e2, tmp, h->elm_size);
}


int heap_init(struct heap *h, int elm_size, int (*cmp)(void *, void *), int init_size, void (*swap)(struct heap *, void *, void *))
{
	int isize = init_size ? init_size : INITIAL_HEAP_SIZE;

	h->num = 0;
	h->max_size = isize;
	h->cmp = cmp;
	h->swap = swap ? swap : _def_swap;
	h->data = malloc((isize + 1) * elm_size);
	h->elm_size = elm_size;

	return h->data ? 1 : 0;
};

static inline void _heap_bubble_down(struct heap *h, int e)
{
	int e1;
	for (;;)
	{
		e1 = 2*e;
		if(e1 > h->num) break;
		if((h->cmp(HELEMENT(h, e),HELEMENT(h,e1)) < 0) && (e1 == h->num || (h->cmp(HELEMENT(h, e),HELEMENT(h,e1+1)) < 0))) break;
		if((e1 != h->num) && (h->cmp(HELEMENT(h, e1+1), HELEMENT(h,e1)) < 0)) e1++;
		h->swap(h,HELEMENT(h,e),HELEMENT(h,e1));
		e = e1;
	}
}

static inline void _heap_bubble_up(struct heap *h, int e)
{
	int e1;
	while (e > 1)
	{
		e1 = e/2;
		if(h->cmp(HELEMENT(h, e1),HELEMENT(h,e)) < 0) break;
		h->swap(h,HELEMENT(h,e),HELEMENT(h,e1));
		e = e1;
	}
		
}

void heap_delmin(struct heap *h)
{
	if(h->num == 0) return;
	if(h->num > 1)
	{
		h->swap(h,HHEAD(h),HELEMENT(h,h->num));
	}
	--h->num;
	_heap_bubble_down(h, 1);
}

int heap_insert(struct heap *h, void *e)
{
	if(h->num == h->max_size)
	{
		h->max_size = h->max_size * HEAP_INCREASE_STEP;
		h->data = realloc(h->data, (h->max_size + 1) * h->elm_size);
	}

	h->num++;
	memcpy(HELEMENT(h,h->num),e,h->elm_size);
	_heap_bubble_up(h,h->num);

	return h->data ? 1 :0 ;
}

int heap_find(struct heap *h, void *elm)	/* FIXME - very slow */
{
	int i = h->num;

	while(i > 0)
	{
		if(h->cmp(HELEMENT(h, i),elm) == 0) break;
		--i;
	}
	return i;
}

void heap_delete(struct heap *h, int e)
{
	h->swap(h, HELEMENT(h, e), HELEMENT(h, h->num));
	h->num--;
	if(h->cmp(HELEMENT(h, e), HELEMENT(h, h->num + 1)) < 0) _heap_bubble_up(h, e);
	else _heap_bubble_down(h, e);

	if ((h->num > INITIAL_HEAP_SIZE) && (h->num < h->max_size / HEAP_DECREASE_THRESHOLD))
	{
		h->max_size = h->max_size / HEAP_INCREASE_STEP;
		h->data = realloc(h->data, (h->max_size + 1) * h->elm_size);
	}
}

