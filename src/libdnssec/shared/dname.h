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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/*!
 * Maximal length of domain name including labels and length bytes.
 * \see RFC 1035
 */
#define DNAME_MAX_LENGTH 255

/*!
 * Maximal length of the domain name label, excluding the label size.
 * \see RFC 1035
 */
#define DNAME_MAX_LABEL_LENGTH 63

/*!
 * Get length of a domain name in wire format.
 */
size_t dname_length(const uint8_t *dname);

/*!
 * Copy domain name in wire format.
 */
uint8_t *dname_copy(const uint8_t *dname);

/*!
 * Normalize domain name in wire format.
 *
 * Currently converts all letters to lowercase.
 */
void dname_normalize(uint8_t *dname);

/*!
 * Check if two dnames are equal.
 *
 * Case insensitive.
 */
bool dname_equal(const uint8_t *one, const uint8_t *two);
