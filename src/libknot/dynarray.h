/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/*!
 * \brief Simple write-once allocation-optimal dynamic array.
 *
 * Include it into your .c file
 *
 * prefix - identifier prefix, e.g. ptr -> struct ptr_dynarray, ptr_dynarray_add(), ...
 * ntype - data type to be stored. Let it be a number, pointer or small struct
 * initial_capacity - how many data items will be allocated on stac and copied with assignment
 *
 * prefix_dynarray_add() - add a data item
 * prefix_dynarray_fix() - call EVERYTIME the array is copied from some already invalid stack
 * prefix_dynarray_free() - call EVERYTIME you dismiss all copies of the array
 *
 */

#include <stdlib.h>
#include <assert.h>

#include "libknot/attribute.h"

#pragma once

#define DYNARRAY_VISIBILITY_NORMAL
#define DYNARRAY_VISIBILITY_STATIC static
#define DYNARRAY_VISIBILITY_PUBLIC _public_

#define knot_dynarray_declare(prefix, ntype, visibility, initial_capacity) \
	typedef struct prefix ## _dynarray { \
		ssize_t capacity; \
		ssize_t size; \
		ntype *(*arr)(struct prefix ## _dynarray *dynarray); \
		ntype init[initial_capacity]; \
		ntype *_arr; \
	} prefix ## _dynarray_t; \
	\
	visibility ntype *prefix ## _dynarray_arr(prefix ## _dynarray_t *dynarray); \
	visibility ntype *prefix ## _dynarray_add(prefix ## _dynarray_t *dynarray, \
	                                        ntype const *to_add); \
	visibility void prefix ## _dynarray_remove(prefix ## _dynarray_t *dynarray, \
	                                        ntype const *to_remove); \
	visibility void prefix ## _dynarray_sort(prefix ## _dynarray_t *dynarray); \
	visibility ntype *prefix ## _dynarray_bsearch(prefix ## _dynarray_t *dynarray, \
	                                        const ntype *bskey); \
	visibility void prefix ## _dynarray_sort_dedup(prefix ## _dynarray_t *dynarray); \
	visibility void prefix ## _dynarray_free(prefix ## _dynarray_t *dynarray);

#define knot_dynarray_foreach(prefix, ntype, ptr, array) \
	for (ntype *ptr = prefix ## _dynarray_arr(&(array)); \
	     ptr < prefix ## _dynarray_arr(&(array)) + (array).size; ptr++)

#define knot_dynarray_define(prefix, ntype, visibility) \
	\
	static void prefix ## _dynarray_free__(struct prefix ## _dynarray *dynarray) \
	{ \
		if (dynarray->capacity > sizeof(dynarray->init) / sizeof(*dynarray->init)) { \
			free(dynarray->_arr); \
		} \
	} \
	\
	_unused_ \
	visibility ntype *prefix ## _dynarray_arr(struct prefix ## _dynarray *dynarray) \
	{ \
		assert(dynarray->size <= dynarray->capacity); \
		return (dynarray->capacity <= sizeof(dynarray->init) / sizeof(*dynarray->init) ? \
			dynarray->init : dynarray->_arr); \
	} \
	\
	static ntype *prefix ## _dynarray_arr_init__(struct prefix ## _dynarray *dynarray) \
	{ \
		assert(dynarray->capacity == sizeof(dynarray->init) / sizeof(*dynarray->init)); \
		return dynarray->init; \
	} \
	\
	static ntype *prefix ## _dynarray_arr_arr__(struct prefix ## _dynarray *dynarray) \
	{ \
		assert(dynarray->capacity > sizeof(dynarray->init) / sizeof(*dynarray->init)); \
		return dynarray->_arr; \
	} \
	\
	_unused_ \
	visibility ntype *prefix ## _dynarray_add(struct prefix ## _dynarray *dynarray, \
	                                          ntype const *to_add) \
	{ \
		if (dynarray->capacity < 0) { \
			return NULL; \
		} \
		if (dynarray->capacity == 0) { \
			dynarray->capacity = sizeof(dynarray->init) / sizeof(*dynarray->init); \
			dynarray->arr = prefix ## _dynarray_arr_init__; \
		} \
		if (dynarray->size >= dynarray->capacity) { \
			ssize_t new_capacity = dynarray->capacity * 2 + 1; \
			ntype *new_arr = calloc(new_capacity, sizeof(ntype)); \
			if (new_arr == NULL) { \
				prefix ## _dynarray_free__(dynarray); \
				dynarray->capacity = dynarray->size = -1; \
				return NULL; \
			} \
			if (dynarray->capacity > 0) { \
				memcpy(new_arr, prefix ## _dynarray_arr(dynarray), \
				       dynarray->capacity * sizeof(ntype)); \
			} \
			prefix ## _dynarray_free__(dynarray); \
			dynarray->_arr = new_arr; \
			dynarray->capacity = new_capacity; \
			dynarray->arr = prefix ## _dynarray_arr_arr__; \
		} \
		ntype *add_to = &prefix ## _dynarray_arr(dynarray)[dynarray->size++]; \
		*add_to = *to_add; \
		return add_to; \
	} \
	\
	_unused_ \
	visibility void prefix ## _dynarray_remove(struct prefix ## _dynarray *dynarray, \
	                                           ntype const *to_remove) \
	{ \
		ntype *orig_arr = prefix ## _dynarray_arr(dynarray); \
		knot_dynarray_foreach(prefix, ntype, removable, *dynarray) { \
			if (memcmp(removable, to_remove, sizeof(*to_remove)) == 0) { \
				if (removable != orig_arr + --dynarray->size) { \
					*(removable--) = orig_arr[dynarray->size]; \
				} \
			} \
		} /* TODO enable lowering capacity, take care of capacity going back to initial! */ \
	} \
	\
	_unused_ \
	static int prefix ## _dynarray_memb_cmp(const void *a, const void *b) { \
		return memcmp(a, b, sizeof(ntype)); \
	} \
	\
	_unused_ \
	visibility void prefix ## _dynarray_sort(struct prefix ## _dynarray *dynarray) \
	{ \
		ntype *arr = prefix ## _dynarray_arr(dynarray); \
		qsort(arr, dynarray->size, sizeof(*arr), prefix ## _dynarray_memb_cmp); \
	} \
	\
	_unused_ \
	visibility ntype *prefix ## _dynarray_bsearch(struct prefix ## _dynarray *dynarray, const ntype *bskey) \
	{ \
		ntype *arr = prefix ## _dynarray_arr(dynarray); \
		return bsearch(bskey, arr, dynarray->size, sizeof(*arr), prefix ## _dynarray_memb_cmp); \
	} \
	\
	_unused_ \
	visibility void prefix ## _dynarray_sort_dedup(struct prefix ## _dynarray *dynarray) \
	{ \
		if (dynarray->size > 1) { \
			prefix ## _dynarray_sort(dynarray); \
			ntype *arr = prefix ## _dynarray_arr(dynarray); \
			ntype *rd = arr + 1; \
			ntype *wr = arr + 1; \
			ntype *end = arr + dynarray->size; \
			while (rd != end) { \
				if (memcmp(rd - 1, rd, sizeof(*rd)) != 0) { \
					if (wr != rd) { \
						*wr = *rd; \
					} \
					wr++; \
				} \
				rd++; \
			} \
			dynarray->size = wr - arr; \
		} \
	} \
	_unused_ \
	visibility void prefix ## _dynarray_free(struct prefix ## _dynarray *dynarray) \
	{ \
		prefix ## _dynarray_free__(dynarray); \
		memset(dynarray, 0, sizeof(*dynarray)); \
	}
