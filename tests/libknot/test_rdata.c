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
	const bool set_ok = knot_rdata_rdlen(rdata) == data_size &&
	                    memcmp(knot_rdata_data(rdata), payload, data_size) == 0;
	ok(set_ok, "rdata: init.");

	// Test setters
	knot_rdata_set_rdlen(rdata, 1);
	ok(knot_rdata_rdlen(rdata) == 1, "rdata: set RDLEN.");

	// Test compare
	knot_rdata_set_rdlen(rdata, data_size);
	ok(knot_rdata_cmp(rdata, rdata) == 0, "rdata: cmp eq.");

	knot_rdata_t *lower = rdata;
	uint8_t buf2[knot_rdata_size(data_size)];
	knot_rdata_t *greater = (knot_rdata_t *)buf2;
	knot_rdata_init(greater, data_size, (uint8_t *)"qrstuvwxyz123456");
	ok(knot_rdata_cmp(lower, greater) < 0, "rdata: cmp lower.");
	ok(knot_rdata_cmp(greater, lower) > 0, "rdata: cmp greater.");

	// Payloads will be the same.
	memcpy(knot_rdata_data(greater), knot_rdata_data(lower), data_size);
	assert(knot_rdata_cmp(lower, greater) == 0);

	knot_rdata_set_rdlen(lower, data_size - 1);
	ok(knot_rdata_cmp(lower, greater) < 0, "rdata: cmp lower size.");
	ok(knot_rdata_cmp(greater, lower) > 0, "rdata: cmp greater size.");

	return 0;
}
