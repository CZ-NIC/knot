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
 * \file fdset.h
 *
 * \author Ondrej Filip <ondrej.filip@nic.cz>
 *
 * \brief Universal heap support
 *
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _HEAP_H_
#define _HEAP_H_

struct heap {
   int num;		/* Number of elements */
   int elm_size;	/* Size of a single element */
   int max_size;	/* Size of allocated memory */
   int (*cmp)(void *, void *);
   void (*swap)(struct heap *, void *, void *);
   void *data;
};		/* Array follows */

#define INITIAL_HEAP_SIZE 1000
#define HEAP_INCREASE_STEP 10
#define HEAP_DECREASE_THRESHOLD 50			/* h->num be divided by this number */
#define HTEMPELEMENT(h) ((h)->data)			/* Pointer to tmp element (for swap) */
#define HHEAD(h) (void *)((h)->data + (h)->elm_size)
#define HELEMENT(h,num) ((h)->data + num * (h)->elm_size)
#define EMPTY_HEAP(h) ((h)->num)			/* h->num > 0 */

int heap_init(struct heap *, int, int (*cmp)(), int, void (*swap)());
void heap_delmin(struct heap *);
int heap_insert(struct heap *, void *);
int heap_find(struct heap *, void *);
void heap_delete(struct heap *, int);


#endif	/* _HEAP_H_ */
