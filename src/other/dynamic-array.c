#include "dynamic-array.h"

#include <pthread.h>
#include <assert.h>
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
	uint new_size = ((type == DA_LARGER)
					 ? (array->allocated *= 2)
					 : (array->allocated /= 2));

	void *new_items = realloc(array->items, new_size * array->item_size);
	if (new_items == NULL) {
		ERR_ALLOC_FAILED;
		return -1;
	}

	array->items = new_items;
	array->allocated = new_size;

	return 1;
}

/*----------------------------------------------------------------------------*/
/* Public functions          					                              */
/*----------------------------------------------------------------------------*/

int da_initialize( da_array *array, uint count, size_t item_size )
{
	assert(array != NULL);

	array->items = malloc(count * item_size);
	if (array->items == NULL) {
		array->allocated = 0;
		array->count = 0;
		ERR_ALLOC_FAILED;
		return -1;
	}

	array->allocated = count;
	array->count = 0;
	return 0;
}

/*----------------------------------------------------------------------------*/

uint da_reserve( da_array *array, uint count )
{
	assert(array->allocated >= array->count);
	if ((array->allocated - array->count) >= count) {
		array->count += count;
		return 0;
	} else {
		return da_resize(array, DA_LARGER);
	}
}

/*----------------------------------------------------------------------------*/

void da_destroy( da_array *array )
{
	free(array->items);
}
