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

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "base32hex.h"
#include "binary.h"
#include "error.h"
#include "wire.h"

/*!
 * Reorder five eight-bit groups into eight five-bit groups.
 */
static void reorder_block(const uint8_t in[5], uint8_t out[8])
{
	out[0] = (in[0] & 0xf8) >> 3;
	out[1] = (in[0] & 0x07) << 2 | (in[1] & 0xc0) >> 6;
	out[2] = (in[1] & 0x3e) >> 1;
	out[3] = (in[1] & 0x01) << 4 | (in[2] & 0xf0) >> 4;
	out[4] = (in[2] & 0x0f) << 1 | (in[3] & 0x80) >> 7;
	out[5] = (in[3] & 0x7c) >> 2;
	out[6] = (in[3] & 0x03) << 3 | (in[4] & 0xe0) >> 5;
	out[7] = (in[4] & 0x1f);
}

/*!
 * Write one reordered block into output binary.
 */
static void write_block(const uint8_t data[8], wire_ctx_t *dst_ctx)
{
	for (int i = 0; i < 8; i++) {
		assert(data[i] < 32);
		assert(wire_available(dst_ctx) > 0);

		if (data[i] < 10) {
			wire_write_u8(dst_ctx, '0' + data[i]);
		} else {
			wire_write_u8(dst_ctx, 'A' - 10 + data[i]);
		}
	}
}

/*!
 * Convert binary data to base32hex.
 */
int base32hex_encode(const dnssec_binary_t *src, dnssec_binary_t *dst)
{
	assert(src && src->data);
	assert(dst);

	if (src->size % 5 != 0) {
		return DNSSEC_EINVAL;
	}

	int r = dnssec_binary_alloc(dst, src->size / 5 * 8);
	if (r != DNSSEC_EOK) {
		return r;
	}

	wire_ctx_t src_ctx = wire_init_binary(src);
	wire_ctx_t dst_ctx = wire_init_binary(dst);

	while (wire_available(&src_ctx) > 0) {
		uint8_t in[5] = { 0 };
		assert(wire_available(&src_ctx) >= sizeof(in));
		wire_read(&src_ctx, in, sizeof(in));

		uint8_t out[8];
		reorder_block(in, out);
		write_block(out, &dst_ctx);
	}

	assert(wire_available(&src_ctx) == 0);
	assert(wire_available(&dst_ctx) == 0);

	return DNSSEC_EOK;
}
