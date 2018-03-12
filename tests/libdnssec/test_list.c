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

#include <stdint.h>
#include <tap/basic.h>

#include "list.h"

static void * const free_context = (void *)0xcafe;
static int counter = 0;

static void item_free(void *pointer, void *data)
{
	if (pointer && data == free_context) {
		counter += 1;
	}
}

int main(int argc, char *argv[])
{
	plan_lazy();

	/* new list */

	dnssec_list_t *list = dnssec_list_new();
	ok(list != NULL, "create new list");

	ok(dnssec_list_size(list) == 0, "new list has zero size");
	ok(dnssec_list_is_empty(list), "new list is empty");
	ok(dnssec_list_head(list) == NULL, "new list has no head");
	ok(dnssec_list_tail(list) == NULL, "new list has no tail");

	/* populate the list */

	dnssec_list_append(list, (void *)7);
	dnssec_list_append(list, (void *)9);
	// 7, 9

	dnssec_list_prepend(list, (void *)5);
	dnssec_list_prepend(list, (void *)2);
	// 2, 5, 7, 9

	dnssec_item_t *head = dnssec_list_head(list);
	dnssec_list_insert_before(head, (void *)1);
	dnssec_list_insert_after(head, (void *)3);
	// 1, 2, 3, 5, 7, 9

	dnssec_item_t *tail = dnssec_list_tail(list);
	dnssec_list_insert_before(tail, (void *)8);
	dnssec_list_insert_after(tail, (void *)10);
	// 1, 2, 3, 5, 7, 8, 9, 10

	dnssec_item_t *item_5 = dnssec_list_nth(list, 3);
	dnssec_list_insert_before(item_5, (void *)4);
	dnssec_list_insert_after(item_5, (void *)6);
	// 1, 2, 3, 4, 5, 6, 7, 8, 9, 10

	ok(dnssec_list_size(list) == 10, "populated list has expected size");
	ok(!dnssec_list_is_empty(list), "populated list is non-empty");

	// content iteration

	int sum = 0;
	int previous = 0;
	bool increasing = true;

	for (dnssec_item_t *i = dnssec_list_head(list); i; i = dnssec_list_next(list, i)) {
		int number = (int)(intptr_t)dnssec_item_get(i);
		sum += number;

		if (previous + 1 != number) {
			increasing = false;
		}

		previous = number;
	}

	ok(sum == 55, "all items are in the list");
	ok(increasing, "append and prepend work");

	// content lookup

	ok(dnssec_list_contains(list, (void *)7), "contains: positive");
	ok(!dnssec_list_contains(list, (void *)17), "contains: negative");

	ok(dnssec_list_search(list, (void *)3) == dnssec_list_nth(list, 2), "search: positive");
	ok(dnssec_list_search(list, (void *)12) == NULL, "search: negative");

	// item removal

	dnssec_list_remove(dnssec_list_head(list));
	dnssec_list_remove(dnssec_list_tail(list));
	dnssec_list_remove(dnssec_list_nth(list, 5));

	ok(dnssec_list_size(list) == 7, "three items removed");

	// full free

	counter = 0;
	dnssec_list_free_full(list, item_free, free_context);
	ok(counter == 7, "list full free");

	// non-full free

	list = dnssec_list_new();
	dnssec_list_append(list, NULL);
	ok(!dnssec_list_is_empty(list), "new list with one item");

	counter = 0;
	dnssec_list_free(list);
	ok(counter == 0, "list non-full free");

	return 0;
}
