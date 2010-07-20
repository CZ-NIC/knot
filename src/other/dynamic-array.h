/*!
 * @file dynamic-array.h
 *
 * @todo Somehow check if the array is initialized and do not use otherwise.
 *       Maybe some magic, or so.
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
	pthread_mutex_t mtx;
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
 * @brief Tries to reserve space for @a count more items.
 * @retval 0 if successful and resizing is not necessary.
 * @retval 1 if successful but the array will need to be resized.
 */
uint da_try_reserve( const da_array *array, uint count );

/*!
 * @brief Releases space taken by @a count items.
 */
void da_release( da_array *array, uint count );

/*!
 * @brief Poperly deallocates the array.
 */
void da_destroy( da_array *array );

/*!
 * @brief Returns the array of items as a void *.
 */
void *da_get_items( const da_array *array );

/*!
 * @brief Returns count of items in the array.
 */
uint da_get_count( const da_array *array );

/*----------------------------------------------------------------------------*/

#endif	// DYNAMIC_ARRAY
