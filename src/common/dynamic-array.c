/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <pthread.h>
#include <assert.h>
#include <stdio.h>

#include <urcu.h>

//#include "common.h"
#include "common/dynamic-array.h"

#ifndef ERR_ALLOC_FAILED
#define ERR_ALLOC_FAILED fprintf(stderr, "Allocation failed at %s:%d\n", \
				 __FILE__, __LINE__)
#endif

//#define DA_DEBUG

#ifndef dbg_da
#ifdef DA_DEBUG
#define dbg_da(msg...) fprintf(stderr, msg)
#else
#define dbg_da(msg...)
#endif
#endif

/*----------------------------------------------------------------------------*/
/* Private functions                                                          */
/*----------------------------------------------------------------------------*/

enum da_resize_type {
	DA_LARGER, DA_SMALLER
};

typedef enum da_resize_type da_resize_type_t;

/*----------------------------------------------------------------------------*/
/*!
 * \retval 1 On success.
 * \retval -1 On failure.
 */
static int da_resize(da_array_t *array, da_resize_type_t type)
{
	dbg_da("da_resize(): array pointer: %p, items pointer: %p\n", array,
	         array->items);

	unsigned new_size = ((type == DA_LARGER)
	                 ? (array->allocated *= 2)
	                 : (array->allocated /= 2));

	void *new_items = malloc(new_size * array->item_size);
	if (new_items == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	dbg_da("Place for new items: %p\n", new_items);

	// copy the contents from the old array to the new
	memcpy(new_items, array->items, array->count * array->item_size);

	// do RCU update
	void *old_items = rcu_xchg_pointer(&array->items, new_items);
	array->allocated = new_size;

	dbg_da("Old items pointer: %p\n", old_items);

	// wait for readers to finish
	synchronize_rcu();
	// deallocate the old array
	dbg_da("RCU synchronized, deallocating old items array at address %p."
	         "\n", old_items);
	free(old_items);

	return 1;
}

/*----------------------------------------------------------------------------*/
/* Public functions                                                           */
/*----------------------------------------------------------------------------*/

da_array_t *da_create(unsigned count, size_t item_size)
{
	da_array_t *a = (da_array_t *)malloc(sizeof(da_array_t));
	if (a == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	da_initialize(a, count, item_size);
	return a;
}

/*----------------------------------------------------------------------------*/

int da_initialize(da_array_t *array, unsigned count, size_t item_size)
{
	assert(array != NULL);
	pthread_mutex_init(&array->mtx, NULL);
	pthread_mutex_lock(&array->mtx);

	array->items = malloc(count * item_size);
	if (array->items == NULL) {
		array->allocated = 0;
		array->count = 0;
		ERR_ALLOC_FAILED;
		return -1;
	}

	array->allocated = count;
	array->count = 0;
	array->item_size = item_size;
	memset(array->items, 0, count * item_size);

	pthread_mutex_unlock(&array->mtx);
	return 0;
}

/*----------------------------------------------------------------------------*/

int da_reserve(da_array_t *array, unsigned count)
{
	pthread_mutex_lock(&array->mtx);
	unsigned res = 0;

	assert(array->allocated >= array->count);
	if ((array->allocated - array->count) >= count) {
		dbg_da("Enough place in the array, no resize needed.\n");
		res = 0;
	} else {
		dbg_da("Resizing array.\n");
		res = da_resize(array, DA_LARGER);
	}
	pthread_mutex_unlock(&array->mtx);

	return res;
}

/*----------------------------------------------------------------------------*/

int da_occupy(da_array_t *array, unsigned count)
{
	pthread_mutex_lock(&array->mtx);
	unsigned res = 0;
	assert(array->allocated >= array->count);

	if ((array->allocated - array->count) < count) {
		dbg_da("Not enough place to occupy.\n");
		res = -1;
	} else {
		array->count += count;
	}

	pthread_mutex_unlock(&array->mtx);
	return res;
}

/*----------------------------------------------------------------------------*/

unsigned da_try_reserve(const da_array_t *array, unsigned count)
{
	assert(array->allocated >= array->count);
	if ((array->allocated - array->count) >= count) {
		return 0;
	}

	return 1;
}

/*----------------------------------------------------------------------------*/

void da_release(da_array_t *array, unsigned count)
{
	pthread_mutex_lock(&array->mtx);

	assert(array->allocated >= array->count);
	assert(array->count >= count);
	dbg_da("Decreasing count of items in array.\n");
	array->count -= count;

	pthread_mutex_unlock(&array->mtx);
}

/*----------------------------------------------------------------------------*/

void da_destroy(da_array_t *array)
{
	pthread_mutex_lock(&array->mtx);
	void *old_items = rcu_dereference(array->items);
	rcu_set_pointer(&array->items, NULL);
	pthread_mutex_unlock(&array->mtx);

	synchronize_rcu();
	free(old_items);
	pthread_mutex_destroy(&array->mtx);
}

/*----------------------------------------------------------------------------*/

void *da_get_items(const da_array_t *array)
{
	return array->items;
}

/*----------------------------------------------------------------------------*/

unsigned da_get_count(const da_array_t *array)
{
	return array->count;
}
