/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>
#include <tap/basic.h>

#include "libknot/dynarray.h"

#define test_capacity 5
// minimum 3

typedef struct {
	int x;
	int x2;
} quadrate_t;

knot_dynarray_declare(q, quadrate_t, DYNARRAY_VISIBILITY_STATIC, test_capacity);
knot_dynarray_define(q, quadrate_t, DYNARRAY_VISIBILITY_STATIC);

static q_dynarray_t q_fill(size_t howmany)
{
	quadrate_t q = { 0 };
	q_dynarray_t qd = { 0 };

	for (size_t i = 0; i < howmany; i++) {
		q.x2 = q.x * q.x;
		q_dynarray_add(&qd, &q);
		q.x++;
	}
	return qd;
}

static void check_arr(q_dynarray_t *q, size_t count, size_t index, const char *msg)
{
	quadrate_t *arr = q->arr(q);
	ok(arr[index].x == index && arr[index].x2 == index * index,
	   "%s check: index %zu", msg, index);

	size_t i = 0;
	knot_dynarray_foreach(q, quadrate_t, p, *q) {
		ok(p->x == i && p->x2 == i * i, "%s foreach: index %zu", msg, i);
		i++;
	}

	ok(i == count, "%s foreach: whole array", msg);
}

static size_t q_set_dups(q_dynarray_t *q, double dup_percentage, const quadrate_t *dupval)
{
	size_t dup_cnt = 0;
	int threshold = (int)(dup_percentage / 100 * ((double)RAND_MAX + 1.0));

	knot_dynarray_foreach(q, quadrate_t, item, *q) {
		if (rand() < threshold && q_dynarray_memb_cmp(item, dupval) != 0) {
			*item = *dupval;
			dup_cnt++;
		}
	}

	return dup_cnt;
}

static void check_dups(q_dynarray_t *q, const quadrate_t *dupval,
                       const size_t expected, const char *msg)
{
	size_t cnt = 0;
	knot_dynarray_foreach(q, quadrate_t, item, *q) {
		if (q_dynarray_memb_cmp(item, dupval) == 0) {
			cnt++;
		}
	}
	ok(cnt == expected, "duplicate items: %s", msg);
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// first fill
	q_dynarray_t q = q_fill(test_capacity - 1);
	check_arr(&q, test_capacity - 1, test_capacity - 3, "initial");
	q_dynarray_free(&q);

	// second fill
	q = q_fill(test_capacity + 3);
	check_arr(&q, test_capacity + 3, test_capacity + 1, "second");
	q_dynarray_free(&q);

	// third fill
	q = q_fill(test_capacity * 5);
	check_arr(&q, test_capacity * 5, test_capacity * 4, "third");
	q_dynarray_free(&q);

	// duplicate items removal test
	q = q_fill(test_capacity * 10);
	quadrate_t dup_item = { .x = 0, .x2 = 0 };  // matches the first item
	size_t dups = q_set_dups(&q, 50, &dup_item);
	ok(q.size == test_capacity * 10, "duplicate items: created");
	check_dups(&q, &dup_item, dups + 1, "created all");

	q_dynarray_remove(&q, &dup_item);
	ok(q.size == test_capacity * 10 - dups - 1, "duplicate items: removed");
	check_dups(&q, &dup_item, 0, "removed all");

	q_dynarray_free(&q);

	// binary search removal test
	q = q_fill(test_capacity * 10);
	for (int i = 0; i < test_capacity * 10; i++) {
		quadrate_t qu = { i, i * i };
		if ((qu.x % 2) == 0) {
			q_dynarray_remove(&q, &qu);
		}
	}
	q_dynarray_sort(&q);
	for (int i = 0; i < test_capacity * 10; i++) {
		quadrate_t qu = { i, i * i };
		int present = (q_dynarray_bsearch(&q, &qu) != NULL ? 1 : 0);
		ok(present == (i % 2), "presence in sorted array %d", i);
	}
	q_dynarray_free(&q);

	return 0;
}
