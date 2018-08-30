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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdint.h>
#include <string.h>
#include <tap/basic.h>

#include "crypto.h"
#include "error.h"
#include "random.h"

int check_buffer(void)
{
	const size_t buffer_size = 128;
	uint8_t buffer_prev[buffer_size];
	memset(buffer_prev, 0, buffer_size);
	uint8_t buffer[buffer_size];
	memset(buffer, 0, buffer_size);

	for (int i = 0; i < 10; i++) {
		int result = dnssec_random_buffer(buffer, buffer_size);
		if (result != DNSSEC_EOK) {
			return 1;
		}

		if (memcmp(buffer, buffer_prev, buffer_size) == 0) {
			return 1;
		}

		memmove(buffer_prev, buffer, buffer_size);
	}

	return 0;
}

int check_random_type(void)
{
	uint16_t numbers[1000] = { 0 };
	int conflicts = 0;

	for (int i = 0; i < 1000; i++) {
		numbers[i] = dnssec_random_uint16_t();
		// check all previous
		for (int j = 0; j < i; j++) {
			if (numbers[i] == numbers[j]) {
				conflicts += 1;
			}
		}
	}

	// allow 5 % of conflicts
	return conflicts <= 50 ? 0 : 1;
}

int main(void)
{
	plan_lazy();

	dnssec_crypto_init();

	// quite stupid, just check if it does something

	ok(check_buffer() == 0, "dnssec_random_buffer()");
	ok(check_random_type() == 0, "dnssec_random_uint16_t()");

	dnssec_crypto_cleanup();

	return 0;
}
