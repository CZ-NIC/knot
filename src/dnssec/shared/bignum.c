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

void bignum_write(wire_ctx_t *ctx, size_t width, const dnssec_binary_t *_value)
{
	dnssec_binary_t value = *_value;
	skip_leading_zeroes(&value);

	size_t padding_len = width - value.size;
	if (padding_len > 0) {
		uint8_t padding[padding_len];
		memset(padding, 0, padding_len);
		wire_write(ctx, padding, padding_len);
	}
	wire_write(ctx, value.data, value.size);
}
