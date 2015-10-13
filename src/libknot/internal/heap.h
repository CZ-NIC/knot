/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
/*!
 * \file heap.h
 *
 * \author Ondrej Filip <ondrej.filip@nic.cz>
 *
 * \brief Universal heap support
 *
 *
 * \addtogroup common_lib
 * @{
 */

#pragma once

typedef void* heap_val_t;

struct heap {
   int num;		/* Number of elements */
   int max_size;	/* Size of allocated memory */
   int (*cmp)(void *, void *);
   heap_val_t *data;
};		/* Array follows */

#define INITIAL_HEAP_SIZE 512 /* initial heap size */
#define HEAP_INCREASE_STEP 2  /* multiplier for each inflation, keep conservative */
#define HEAP_DECREASE_THRESHOLD 2 /* threshold for deflation, keep conservative */
#define HELEMENT(h,num) ((h)->data + (num))
#define HHEAD(h) HELEMENT((h),1)
#define EMPTY_HEAP(h) ((h)->num == 0)			/* h->num == 0 */

int heap_init(struct heap *, int (*cmp)(), int);
void heap_delmin(struct heap *);
int heap_insert(struct heap *, void *);
int heap_find(struct heap *, void *);
void heap_delete(struct heap *, int);
void heap_replace(struct heap *h, int pos, void *e);


/*! @} */
