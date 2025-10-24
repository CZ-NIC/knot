/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "libknot/dnssec/nsec.h"
#include "libknot/dnssec/shared/shared.h"

#define BITMAP_WINDOW_SIZE 256
#define BITMAP_WINDOW_BYTES (BITMAP_WINDOW_SIZE/CHAR_BIT)
#define BITMAP_WINDOW_COUNT 256

/*!
 * One window of an NSEC bitmap.
 */
typedef struct window {
	uint8_t used;
	uint8_t data[BITMAP_WINDOW_BYTES];
} window_t;

struct dnssec_nsec_bitmap {
	int used;
	window_t windows[BITMAP_WINDOW_COUNT];
};

/* -- public API ----------------------------------------------------------- */

/*!
 * Allocate new bit map encoding context.
 */
_public_
dnssec_nsec_bitmap_t *dnssec_nsec_bitmap_new(void)
{
	dnssec_nsec_bitmap_t *bitmap = malloc(sizeof(*bitmap));
	if (!bitmap) {
		return NULL;
	}

	dnssec_nsec_bitmap_clear(bitmap);

	return bitmap;
}

/*!
 * Clear existing bit map encoding context.
 */
_public_
void dnssec_nsec_bitmap_clear(dnssec_nsec_bitmap_t *bitmap)
{
	clear_struct(bitmap);
}

/*!
 * Free bit map encoding context.
 */
_public_
void dnssec_nsec_bitmap_free(dnssec_nsec_bitmap_t *bitmap)
{
	free(bitmap);
}

/*!
 * Add one RR type into the bitmap.
 */
_public_
void dnssec_nsec_bitmap_add(dnssec_nsec_bitmap_t *bitmap, uint16_t type)
{
	int win = type / BITMAP_WINDOW_SIZE;
	int bit = type % BITMAP_WINDOW_SIZE;

	if (bitmap->used <= win) {
		bitmap->used = win + 1;
	}

	int win_byte = bit / CHAR_BIT;
	int win_bit  = bit % CHAR_BIT;

	window_t *window = &bitmap->windows[win];
	window->data[win_byte] |= 0x80 >> win_bit;
	if (window->used <= win_byte) {
		window->used = win_byte + 1;
	}
}

/*!
 * Compute the size of the encoded bitmap.
 */
_public_
size_t dnssec_nsec_bitmap_size(const dnssec_nsec_bitmap_t *bitmap)
{
	size_t result = 0;

	for (int i = 0; i < bitmap->used; i++) {
		int used = bitmap->windows[i].used;
		if (used == 0) {
			continue;
		}

		result += 2 + used; // windows number, window size, data
	}

	return result;
}

/*!
 * Write encoded bitmap into the given buffer.
 */
_public_
void dnssec_nsec_bitmap_write(const dnssec_nsec_bitmap_t *bitmap, uint8_t *output)
{
	uint8_t *write_ptr = output;
	for (int win = 0; win < bitmap->used; win++) {
		int used = bitmap->windows[win].used;
		if (used == 0) {
			continue;
		}

		*write_ptr = (uint8_t)win;
		write_ptr += 1;

		*write_ptr = (uint8_t)used;
		write_ptr += 1;

		memmove(write_ptr, bitmap->windows[win].data, used);
		write_ptr += used;
	}
}
