/*!
 * @file dynamic-array.h
 *
 * @todo Somehow check if the array is initialized and do not use otherwise.
 *       Maybe some magic, or so.
 * @todo Somehow synchronize!! Lock is probably useless as we do not lock the
 *       buffer when accessing and using its items anyway. However, we must
 *       somehow ensure, that nobody uses the old array when reallocating.
 *       Maybe change to dynamic array of pointers to pointers. Then the size of
 *       the item is known (size of a pointer) and we may provide functions
 *       for getting and setting items and thus synchronize easily using RCU.
 *       Maybe the RCU could be used anyway if using malloc instead of realloc.
 */
#ifndef DYNAMIC_ARRAY
#define DYNAMIC_ARRAY

#include <string.h>
#include <pthread.h>
#include "common.h"

/*----------------------------------------------------------------------------*/

typedef struct {
	void *items;
	size_t item_size;
	uint allocated;
	uint count;
} da_array;

/*----------------------------------------------------------------------------*/
/*!
 * @brief Initializes the dynamic array by allocating place for @a count items
 *        of size @a item_size.
 * @retval 0 if successful.
 * @retval -1 if not successful.
 */
int da_initialize( da_array *array, uint count, size_t item_size );

/*!
 * @brief Reserves space for @a count more items.
 * @retval 0 if successful and resizing was not necessary.
 * @retval 1 if successful and the array was enlarged.
 * @retval -1 if not successful - resizing was needed but could not be done.
 */
uint da_reserve( da_array *array, uint count );

/*!
 * @brief Poperly deallocates the array.
 */
void da_destroy( da_array *array );

/*----------------------------------------------------------------------------*/

#endif	// DYNAMIC_ARRAY
