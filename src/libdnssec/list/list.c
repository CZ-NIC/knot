/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdlib.h>

#include "libdnssec/list.h"
#include "error.h"
#include "list/ucw_clists.h"
#include "shared/shared.h"

struct dnssec_list {
	clist list;
};

struct dnssec_item {
	cnode node;
	void *data;
};

/*!
 * Allocate new list item and set item data.
 */
static dnssec_item_t *item_new(void *data)
{
	dnssec_item_t *item = malloc(sizeof(*item));
	if (item) {
		clear_struct(item);
		item->data = data;
	}

	return item;
}

/*!
 * Wrapper around libc free with unused context.
 */
static void wrap_free(void *ptr, void *ctx _unused_)
{
	free(ptr);
}

/* -- public API ----------------------------------------------------------- */

_public_
void *dnssec_item_get(const dnssec_item_t *item)
{
	return item ? item->data : NULL;
}

_public_
void dnssec_item_set(dnssec_item_t *item, void *data)
{
	if (item) {
		item->data = data;
	}
}

_public_
dnssec_list_t *dnssec_list_new(void)
{
	dnssec_list_t *list = malloc(sizeof(*list));
	if (list) {
		clist_init(&list->list);
	}

	return list;
}

_public_
void dnssec_list_clear(dnssec_list_t *list)
{
	if (!list) {
		return;
	}

	dnssec_list_foreach(item, list) {
		free(item);
	}
}

_public_
void dnssec_list_clear_full(dnssec_list_t *list, dnssec_item_free_cb free_cb,
			    void *free_ctx)
{
	if (!list) {
		return;
	}

	if (!free_cb) {
		free_cb = wrap_free;
	}

	dnssec_list_foreach(item, list) {
		free_cb(item->data, free_ctx);
		free(item);
	}
}

_public_
void dnssec_list_free(dnssec_list_t *list)
{
	if (!list) {
		return;
	}

	dnssec_list_clear(list);
	free(list);
}

_public_
void dnssec_list_free_full(dnssec_list_t *list, dnssec_item_free_cb free_cb,
			   void *free_ctx)
{
	if (!list) {
		return;
	}

	dnssec_list_clear_full(list, free_cb, free_ctx);
	free(list);
}

_public_
dnssec_item_t *dnssec_list_head(dnssec_list_t *list)
{
	if (!list) {
		return NULL;
	}

	return clist_head(&list->list);
}

_public_
dnssec_item_t *dnssec_list_tail(dnssec_list_t *list)
{
	if (!list) {
		return NULL;
	}

	return clist_tail(&list->list);
}

_public_
dnssec_item_t *dnssec_list_next(dnssec_list_t *list, dnssec_item_t *item)
{
	if (!list || !item) {
		return NULL;
	}

	return clist_next(&list->list, &item->node);
}

_public_
dnssec_item_t *dnssec_list_prev(dnssec_list_t *list, dnssec_item_t *item)
{
	if (!list || !item) {
		return NULL;
	}

	return clist_prev(&list->list, &item->node);
}

_public_
dnssec_item_t *dnssec_list_nth(dnssec_list_t *list, size_t position)
{
	size_t index = 0;
	dnssec_item_t *item = dnssec_list_head(list);

	while (item) {
		if (index == position) {
			return item;
		} else {
			item = dnssec_list_next(list, item);
			index += 1;
		}
	}

	return NULL;
}

_public_
bool dnssec_list_is_empty(dnssec_list_t *list)
{
	return !list || clist_empty(&list->list);
}

_public_
size_t dnssec_list_size(dnssec_list_t *list)
{
	return list ? clist_size(&list->list) : 0;
}

_public_
int dnssec_list_insert_before(dnssec_item_t *item, void *data)
{
	if (!item) {
		return DNSSEC_EINVAL;
	}

	dnssec_item_t *add = item_new(data);
	if (!add) {
		return DNSSEC_ENOMEM;
	}

	clist_insert_before(&add->node, &item->node);

	return DNSSEC_EOK;
}

_public_
int dnssec_list_insert_after(dnssec_item_t *item, void *data)
{
	if (!item) {
		return DNSSEC_EINVAL;
	}

	dnssec_item_t *add = item_new(data);
	if (!add) {
		return DNSSEC_ENOMEM;
	}

	clist_insert_after(&add->node, &item->node);

	return DNSSEC_EOK;
}

_public_
int dnssec_list_append(dnssec_list_t *list, void *data)
{
	if (!list) {
		return DNSSEC_EINVAL;
	}

	dnssec_item_t *add = item_new(data);
	if (!add) {
		return DNSSEC_ENOMEM;
	}

	clist_add_tail(&list->list , &add->node);

	return DNSSEC_EOK;
}

_public_
int dnssec_list_prepend(dnssec_list_t *list, void *data)
{
	if (!list) {
		return DNSSEC_EINVAL;
	}

	dnssec_item_t *add = item_new(data);
	if (!add) {
		return DNSSEC_ENOMEM;
	}

	clist_add_head(&list->list , &add->node);

	return DNSSEC_EOK;
}

_public_
void dnssec_list_remove(dnssec_item_t *item)
{
	if (item) {
		clist_remove(&item->node);
		free(item);
	}
}

_public_
dnssec_item_t *dnssec_list_search(dnssec_list_t *list, void *data)
{
	dnssec_list_foreach(item, list) {
		if (item->data == data) {
			return item;
		}
	}

	return NULL;
}

_public_
bool dnssec_list_contains(dnssec_list_t *list, void *data)
{
	return dnssec_list_search(list, data) != NULL;
}
