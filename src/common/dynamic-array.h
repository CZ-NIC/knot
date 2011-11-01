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
/*!
 * \file dynamic-array.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief Safe dynamic array implementation.
 *
 * \todo Somehow check if the array is initialized and do not use otherwise.
 *       Maybe some magic, or so.
 * \todo This structure is too slow because of the mutex.
 *
 * \addtogroup common_lib
 * @{
 */

#ifndef _KNOTD_COMMON_DYNAMIC_ARRAY_H_
#define _KNOTD_COMMON_DYNAMIC_ARRAY_H_

#include <string.h>
#include <pthread.h>

/*----------------------------------------------------------------------------*/
/*!
 * \brief Dynamic array structure.
 *
 * Before using the dynamic array, it must be initialized using da_initialize().
 * When getting individual items always use da_get_items() to obtain pointer to
 * the actual array.
 *
 * Items in the array cannot be dereferenced (it uses void * for storing the
 * the items). It is needed to type-cast the item array (obtained by calling
 * da_get_items()) to a proper type before dereferencing.
 *
 * When adding items, first reserve enough space for them by callling
 * da_reserve() and subsequently tell the array about the inserted items by
 * calling da_occupy(). When removing, the array must be told about the fact
 * by calling da_release().
 *
 * For getting the actual number of items in array use da_get_count().
 *
 * When the array is no more needed, the da_destroy() function must be called
 * before deallocating the structure.
 */
struct da_array {
	/*! \brief The actual array. The items can't be dereferenced directly.*/
	void *items;

	/*!
	 * \brief Size of the stored items in bytes (used in counting of space
	 *        needed.
	 */
	size_t item_size;

	/*!
	 * \brief Size of allocated space in number of items that can be stored.
	 */
	unsigned allocated;

	/*! \brief Number of items actually stored in the array. */
	unsigned count;

	/*! \brief Mutex. */
	pthread_mutex_t mtx;
};

typedef struct da_array da_array_t;

/*----------------------------------------------------------------------------*/
/*!
 * \brief Creates and initializes the dynamic array.
 *
 * Initialization comprises of allocating place for \a count items of size
 * \a item_size and setting the items to zeros.
 *
 * \retval 0 if successful.
 * \retval -1 if not successful.
 */
da_array_t *da_create(unsigned count, size_t item_size);

/*!
 * \brief Initializes the dynamic array.
 *
 * Initialization comprises of allocating place for \a count items of size
 * \a item_size and setting the items to zeros.
 *
 * \retval 0 if successful.
 * \retval -1 if not successful.
 */
int da_initialize(da_array_t *array, unsigned count, size_t item_size);

/*!
 * \brief Reserves space for \a count more items.
 *
 * \retval 0 if successful and resizing was not necessary.
 * \retval 1 if successful and the array was enlarged.
 * \retval -1 if not successful - resizing was needed but could not be done.
 */
int da_reserve(da_array_t *array, unsigned count);

/*!
 * \brief Increases the number of items in array by \a count.
 *
 * \retval 0 If successful.
 * \retval -1 If not successful (not enough allocated space, i.e. must run
 *            da_reserve()).
 */
int da_occupy(da_array_t *array, unsigned count);

/*!
 * \brief Tries to reserve space for \a count more items.
 *
 * \retval 0 if successful and resizing is not necessary.
 * \retval 1 if successful but the array will need to be resized.
 */
unsigned da_try_reserve(const da_array_t *array, unsigned count);

/*!
 * \brief Releases space taken by \a count items.
 */
void da_release(da_array_t *array, unsigned count);

/*!
 * \brief Poperly deallocates the array.
 */
void da_destroy(da_array_t *array);

/*!
 * \brief Returns the array of items as a void *.
 */
void *da_get_items(const da_array_t *array);

/*!
 * \brief Returns count of items in the array.
 */
unsigned da_get_count(const da_array_t *array);

/*----------------------------------------------------------------------------*/

#endif /* _KNOTD_COMMON_DYNAMIC_ARRAY_H_ */

/*! @} */
