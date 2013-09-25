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
 * \file nsec-bitmap.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 *
 * \brief RR bitmap used in NSEC/NSEC3 records (RFC 4034).
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_ZONE_NSEC_BITMAP_H_
#define _KNOT_DNSSEC_ZONE_NSEC_BITMAP_H_

#include <stdint.h>
#include <string.h>
#include "libknot/zone/node.h"
#include "libknot/rrset.h"

#define BITMAP_WINDOW_SIZE 256
#define BITMAP_WINDOW_BYTES (BITMAP_WINDOW_SIZE/CHAR_BIT)
#define BITMAP_WINDOW_COUNT 256

/*!
 * \brief One window of a bitmap.
 */
typedef struct {
	uint8_t used;
	uint8_t data[BITMAP_WINDOW_BYTES];
} bitmap_window_t;

/*!
 * \brief Bitmap of RR types.
 */
typedef struct {
	int used;
	bitmap_window_t windows[BITMAP_WINDOW_COUNT];
} bitmap_t;

/*!
 * \brief Add one RR type into the bitmap.
 */
inline static void bitmap_add_type(bitmap_t *bitmap, uint16_t type)
{
	int win = type / BITMAP_WINDOW_SIZE;
	int bit = type % BITMAP_WINDOW_SIZE;

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
 * \brief Add all RR types from a node into the bitmap.
 */
inline static void bitmap_add_node_rrsets(bitmap_t *bitmap,
                                          const knot_node_t *node)
{
	knot_rrset_t **node_rrsets = knot_node_get_rrsets_no_copy(node);
	for (int i = 0; i < node->rrset_count; i++) {
		bitmap_add_type(bitmap, node_rrsets[i]->type);
	}
}

/*!
 * \brief Compute the size of the bitmap in NSEC RDATA format.
 */
inline static size_t bitmap_size(const bitmap_t *bitmap)
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
inline static void bitmap_write(const bitmap_t *bitmap, uint8_t *output)
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

#endif // _KNOT_DNSSEC_ZONE_NSEC_BITMAP_H_

/*! @} */
