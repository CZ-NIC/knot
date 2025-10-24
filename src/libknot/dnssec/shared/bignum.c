/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <string.h>

#include "libknot/dnssec/shared/bignum.h"

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
		wire_ctx_clear(ctx, padding_len);
	}
	wire_ctx_write(ctx, value.data, value.size);
}
