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

#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "nsec.h"
#include "shared/shared.h"

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
