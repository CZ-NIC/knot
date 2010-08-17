#include "dynamic-array.h"

#include <pthread.h>
#include <assert.h>
#include <stdio.h>
#include <urcu.h>

/*----------------------------------------------------------------------------*/
/* Private functions          					                              */
/*----------------------------------------------------------------------------*/

typedef enum {
	DA_LARGER, DA_SMALLER
} da_resize_type;

/*----------------------------------------------------------------------------*/
/*!
 * @retval 1 On success.
 * @retval -1 On failure.
 */
int da_resize( da_array *array, da_resize_type type ) {
	debug_da("da_resize(): array pointer: %p, items pointer: %p\n", array,
			 array->items);

	uint new_size = ((type == DA_LARGER)
					 ? (array->allocated *= 2)
					 : (array->allocated /= 2));

	void *new_items = malloc(new_size * array->item_size);
	if (new_items == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	debug_da("Place for new items: %p\n", new_items);

	// copy the contents from the old array to the new
	memcpy(new_items, array->items, array->count * array->item_size);

	// do RCU update
	void *old_items = rcu_xchg_pointer(&array->items, new_items);
	array->allocated = new_size;

	debug_da("Old items pointer: %p\n", old_items);

	// wait for readers to finish
	synchronize_rcu();
	// deallocate the old array
	debug_da("RCU synchronized, deallocating old items array at address %p.\n",
			 old_items);
	free(old_items);

	return 1;
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

da_array *da_create( uint count, size_t item_size )
{
	da_array *a = (da_array *)malloc(sizeof(da_array));
	if (a == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	da_initialize(a, count, item_size);
	return a;
}

/*----------------------------------------------------------------------------*/

int da_initialize( da_array *array, uint count, size_t item_size )
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

int da_reserve( da_array *array, uint count )
{
	pthread_mutex_lock(&array->mtx);
	uint res = 0;

	assert(array->allocated >= array->count);
	if ((array->allocated - array->count) >= count) {
		debug_da("Enough place in the array, no resize needed.\n");
		res = 0;
	} else {
		debug_da("Resizing array.\n");
		res = da_resize(array, DA_LARGER);
	}
	pthread_mutex_unlock(&array->mtx);

	return res;
}

/*----------------------------------------------------------------------------*/

int da_occupy( da_array *array, uint count )
{
	pthread_mutex_lock(&array->mtx);
	uint res = 0;
	assert(array->allocated >= array->count);

	if ((array->allocated - array->count) < count) {
		debug_da("Not enough place to occupy.\n");
		res = -1;
	} else {
		array->count += count;
	}

	pthread_mutex_unlock(&array->mtx);
	return res;
}

/*----------------------------------------------------------------------------*/

uint da_try_reserve( const da_array *array, uint count )
{
	assert(array->allocated >= array->count);
	if ((array->allocated - array->count) >= count) {
		return 0;
	}

	return 1;
}

/*----------------------------------------------------------------------------*/

void da_release( da_array *array, uint count )
{
	pthread_mutex_lock(&array->mtx);

	assert(array->allocated >= array->count);
	assert(array->count >= count);
	debug_da("Decreasing count of items in array.\n");
	array->count -= count;

	pthread_mutex_unlock(&array->mtx);
}

/*----------------------------------------------------------------------------*/

void da_destroy( da_array *array )
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

void *da_get_items( const da_array *array )
{
	return array->items;
}

/*----------------------------------------------------------------------------*/

uint da_get_count( const da_array *array )
{
	return array->count;
}
