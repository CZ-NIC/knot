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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <tap/basic.h>

#include "contrib/dynarray.h"

#define test_capacity 5
// minimum 3

typedef struct {
	int x;
	int x2;
} quadrate_t;

dynarray_declare(q, quadrate_t, DYNARRAY_VISIBILITY_STATIC, test_capacity);
dynarray_define(q, quadrate_t, DYNARRAY_VISIBILITY_STATIC, test_capacity);

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

static void check_arr(q_dynarray_t *q, size_t index, const char *msg)
{
	quadrate_t *arr = q->arr(q);
	ok(arr[index].x == index && arr[index].x2 == index * index,
	   "%s check: index %zu", msg, index);

	size_t i = 0;
	dynarray_foreach(q, quadrate_t, p, *q) {
		ok(p->x == i && p->x2 == i * i, "%s foreach: index %zu", msg, i);
		i++;
	}
}

int main(int argc, char *argv[])
{
	plan_lazy();

	// first fill
	q_dynarray_t q = q_fill(test_capacity - 1);
	check_arr(&q, test_capacity - 3, "initial");
	q_dynarray_free(&q);

	// second fill
	q = q_fill(test_capacity + 3);
	check_arr(&q, test_capacity + 1, "second");
	q_dynarray_free(&q);

	// third fill
	q = q_fill(test_capacity * 5);
	check_arr(&q, test_capacity * 4, "third");
	q_dynarray_free(&q);

	return 0;
}
