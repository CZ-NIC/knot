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

#include <tap/basic.h>

#include "base32hex.h"
#include "error.h"

struct test {
	const char *name;
	const dnssec_binary_t in;
	const dnssec_binary_t out;
};

static const struct test TESTS[] = {
	{
		.name = "invalid, unaligned",
		.in  = {
			.data = (uint8_t *)"abcdefghijk",
			.size = 12
		},
		.out = {
			.data = NULL,
			.size = 0
		}
	},
	{
		.name = "valid, short",
		.in  = {
			.data = (uint8_t *)"\x1a\x2b\x3c\x4d\x5e",
			.size = 5
		},
		.out = {
			.data = (uint8_t *)"38LJOJAU",
			.size = 8
		}
	},
	{
		.name = "valid, long",
		.in  = {
			.data = (uint8_t *)"\xc7\x75\x08\x05\x9e"
					   "\x1d\x75\x00\x99\xab"
					   "\x43\xb5\xa2\xfe\xea"
					   "\xe7\x0b\x3a\x6b\x83",
			.size = 20
		},
		.out = {
			.data = (uint8_t *)"OTQGG1CU3LQG16DB8EQQ5VNASS5JKQS3",
			.size = 32
		}
	},
	{ NULL }
};

int main(void)
{

	plan_lazy();

	for (const struct test *t = TESTS; t->name; t++) {
		dnssec_binary_t out = { 0 };
		int r = base32hex_encode(&t->in, &out);

		if (t->out.data == NULL) {
			ok(r != DNSSEC_EOK && out.size == 0 && out.data == NULL,
			   "expected failure: %s", t->name);
		} else {
			ok(r == DNSSEC_EOK && dnssec_binary_cmp(&out, &t->out) == 0,
			   "expected success: %s", t->name);
			dnssec_binary_free(&out);
		}
	}

	return 0;
}
