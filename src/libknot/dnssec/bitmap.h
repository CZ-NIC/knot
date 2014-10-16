/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file bitmap.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief RR bitmap used in NSEC/NSEC3 records (RFC 4034).
 *
 * \addtogroup dnssec
 * @{
 */

#pragma once

#include <stdint.h>
#include <string.h>
#include <limits.h>

#define KNOT_BITMAP_WINDOW_SIZE 256
#define KNOT_BITMAP_WINDOW_BYTES (KNOT_BITMAP_WINDOW_SIZE/CHAR_BIT)
#define KNOT_BITMAP_WINDOW_COUNT 256

/*!
 * \brief One window of a bitmap.
 */
typedef struct {
	uint8_t used;
	uint8_t data[KNOT_BITMAP_WINDOW_BYTES];
} bitmap_window_t;

/*!
 * \brief Bitmap of RR types.
 */
typedef struct {
	int used;
	bitmap_window_t windows[KNOT_BITMAP_WINDOW_COUNT];
} bitmap_t;

/*!
 * \brief Add one RR type into the bitmap.
 */
inline static void knot_bitmap_add_type(bitmap_t *bitmap, uint16_t type)
{
	int win = type / KNOT_BITMAP_WINDOW_SIZE;
	int bit = type % KNOT_BITMAP_WINDOW_SIZE;

	if (bitmap->used <= win) {
		bitmap->used = win + 1;
	}

	int win_byte = bit / CHAR_BIT;
	int win_bit  = bit % CHAR_BIT;

	bitmap_window_t *window = &bitmap->windows[win];
	window->data[win_byte] |= 0x80 >> win_bit;
	if (window->used <= win_byte) {
		window->used = win_byte + 1;
	}
}

/*!
 * \brief Compute the size of the bitmap in NSEC RDATA format.
 */
inline static size_t knot_bitmap_size(const bitmap_t *bitmap)
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
 * \brief Write bitmap in NSEC RDATA format.
 */
inline static void knot_bitmap_write(const bitmap_t *bitmap, uint8_t *output)
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

		memcpy(write_ptr, bitmap->windows[win].data, used);
		write_ptr += used;
	}
}

/*! @} */
