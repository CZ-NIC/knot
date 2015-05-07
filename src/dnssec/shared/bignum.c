/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <string.h>

#include "bignum.h"

static void skip_leading_zeroes(dnssec_binary_t *value)
{
	while (value->size > 0 && value->data[0] == 0) {
		value->data += 1;
		value->size -= 1;
	}
}

size_t bignum_size_u(const dnssec_binary_t *_value)
{
	dnssec_binary_t value = *_value;
	skip_leading_zeroes(&value);

	if (value.size == 0) {
		return value.size + 1;
	} else {
		return value.size;
	}
}

size_t bignum_size_s(const dnssec_binary_t *_value)
{
	dnssec_binary_t value = *_value;
	skip_leading_zeroes(&value);

	if (value.size == 0 || value.data[0] & 0x80) {
		return value.size + 1;
	} else {
		return value.size;
	}
}

void bignum_write(dnssec_binary_t *dest, const dnssec_binary_t *_value)
{
	dnssec_binary_t value = *_value;
	skip_leading_zeroes(&value);

	assert(dest->size >= value.size);

	size_t padding = dest->size - value.size;
	if (padding > 0) {
		memset(dest->data, 0, padding);
	}

	memmove(dest->data + padding, value.data, value.size);
}
