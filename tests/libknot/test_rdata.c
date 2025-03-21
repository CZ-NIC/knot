/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdbool.h>
#include <tap/basic.h>

#include "libknot/rdata.h"

int main(int argc, char *argv[])
{
	plan_lazy();

	// Test array size
	ok(knot_rdata_size(1) == 2 + 1 + 1, "rdata: array size odd.");
	ok(knot_rdata_size(2) == 2 + 2, "rdata: array size even.");

	// Test init
	const size_t data_size = 16;
	uint8_t buf1[knot_rdata_size(data_size)];
	knot_rdata_t *rdata = (knot_rdata_t *)buf1;
	uint8_t payload[] = "abcdefghijklmnop";
	knot_rdata_init(rdata, data_size, payload);
	const bool set_ok = rdata->len == data_size &&
	                    memcmp(rdata->data, payload, data_size) == 0;
	ok(set_ok, "rdata: init.");

	// Test compare
	rdata->len = data_size;
	ok(knot_rdata_cmp(rdata, rdata) == 0, "rdata: cmp eq.");

	knot_rdata_t *lower = rdata;
	uint8_t buf2[knot_rdata_size(data_size)];
	knot_rdata_t *greater = (knot_rdata_t *)buf2;
	knot_rdata_init(greater, data_size, (uint8_t *)"qrstuvwxyz123456");
	ok(knot_rdata_cmp(lower, greater) < 0, "rdata: cmp lower.");
	ok(knot_rdata_cmp(greater, lower) > 0, "rdata: cmp greater.");

	// Payloads will be the same.
	memcpy(greater->data, lower->data, data_size);
	assert(knot_rdata_cmp(lower, greater) == 0);

	lower->len = data_size - 1;
	ok(knot_rdata_cmp(lower, greater) < 0, "rdata: cmp lower size.");
	ok(knot_rdata_cmp(greater, lower) > 0, "rdata: cmp greater size.");

	return 0;
}
