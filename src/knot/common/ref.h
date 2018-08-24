/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \brief Atomic reference counting structures.
 *
 * Reference counting allows implicit sharing of objects
 * between threads with custom destructor functions.
 */

#pragma once

#include <stddef.h>

struct ref;

/*! \brief Prototype for object destructor callback. */
typedef void (*ref_destructor_t)(struct ref * p);

/*!
 * \brief Structure for reference counting.
 *
 * Size equals to two sizes of pointer size.
 * Structure may be embedded to the structures which
 * we want to use for reference counting.
 *
 * \code
 * struct mystruct {
 *    ref_t ref;
 *    int mydata;
 *    char *mystr;
 * }
 * \endcode
 */
typedef struct ref {
	size_t count;          /*! \brief Reference counter. */
	ref_destructor_t dtor; /*! \brief Object destructor function. */
} ref_t;

/*!
 * \brief Initialize reference counter.
 *
 * Set reference counter to 0 and initialize destructor callback.
 *
 * \param p Reference-counted object.
 * \param dtor Destructor function.
 */
void ref_init(ref_t *p, ref_destructor_t dtor);

/*!
 * \brief Mark object as used by the caller.
 *
 * Reference counter will be incremented.
 *
 * \param p Reference-counted object.
 */
void ref_retain(ref_t *p);

/*!
 * \brief Marks object as unused by the caller.
 *
 * Reference counter will be decremented.
 *
 * \param p Reference-counted object.
 */
void ref_release(ref_t *p);
