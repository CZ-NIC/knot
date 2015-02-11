/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * DNSSEC generic lists.
 *
 * \defgroup list Lists
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdlib.h>

struct dnssec_list;
typedef struct dnssec_list dnssec_list_t;

struct dnssec_item;
typedef struct dnssec_item dnssec_item_t;

void *dnssec_item_get(const dnssec_item_t *item);
void dnssec_item_set(dnssec_item_t *item, void *data);

dnssec_list_t *dnssec_list_new(void);
void dnssec_list_free(dnssec_list_t *list);

typedef void (*dnssec_item_free_cb)(void *data, void *ctx);

/*!
 * Free the list including contained items.
 *
 * If \c free_cb is NULL, standard libc \c free will used to free the items.
 *
 * \param list      List to be freed.
 * \param free_cb   Free function called for each item in the list.
 * \param free_ctx  Context passed to item free.
 */
void dnssec_list_free_full(dnssec_list_t *list, dnssec_item_free_cb free_cb,
			   void *free_ctx);

void dnssec_list_clear(dnssec_list_t *list);
void dnssec_list_clear_full(dnssec_list_t *list, dnssec_item_free_cb free_cb,
			    void *free_ctx);

dnssec_item_t *dnssec_list_head(dnssec_list_t *list);
dnssec_item_t *dnssec_list_tail(dnssec_list_t *list);
dnssec_item_t *dnssec_list_next(dnssec_list_t *list, dnssec_item_t *item);
dnssec_item_t *dnssec_list_prev(dnssec_list_t *list, dnssec_item_t *item);
dnssec_item_t *dnssec_list_nth(dnssec_list_t *list, size_t position);

bool dnssec_list_is_empty(dnssec_list_t *list);
size_t dnssec_list_size(dnssec_list_t *list);

int dnssec_list_insert_after(dnssec_item_t *item, void *data);
int dnssec_list_insert_before(dnssec_item_t *item, void *data);
int dnssec_list_append(dnssec_list_t *list, void *data);
int dnssec_list_prepend(dnssec_list_t *list, void *data);

void dnssec_list_remove(dnssec_item_t *item);

dnssec_item_t *dnssec_list_search(dnssec_list_t *list, void *data);
bool dnssec_list_contains(dnssec_list_t *list, void *data);

#define dnssec_list_foreach(var, list) \
	for (dnssec_item_t *__tmp, *var = dnssec_list_head(list); \
	     __tmp = dnssec_list_next(list, var), var != NULL; \
	     var = __tmp)

/*! @} */
