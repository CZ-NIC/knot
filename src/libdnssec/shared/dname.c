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
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "shared/dname.h"
#include "shared/shared.h"
#include "../contrib/tolower.h"

/*!
 * Get length of a domain name in wire format.
 */
size_t dname_length(const uint8_t *dname)
{
	if (!dname) {
		return 0;
	}

	const uint8_t *scan = dname;
	uint8_t label_len;
	do {
		label_len = *scan;
		scan += 1 + label_len;
	} while (label_len > 0);
	assert(scan > dname);

	size_t length = scan - dname;
	if (length > DNAME_MAX_LENGTH) {
		return 0;
	}

	return length;
}

/*!
 * Copy domain name in wire format.
 */
uint8_t *dname_copy(const uint8_t *dname)
{
	if (!dname) {
		return NULL;
	}

	size_t length = dname_length(dname);
	if (length == 0) {
		return NULL;
	}

	uint8_t *copy = malloc(length);
	if (!copy) {
		return NULL;
	}

	memmove(copy, dname, length);
	return copy;
}

/*!
 * Normalize dname label in-place.
 *
 * \return Number of processed bytes, 0 if we encounter the last label.
 */
static uint8_t normalize_label(uint8_t *label)
{
	assert(label);

	uint8_t len = *label;
	if (len == 0 || len > DNAME_MAX_LABEL_LENGTH) {
		return 0;
	}

	for (uint8_t *scan = label + 1, *end = scan + len; scan < end; scan++) {
		*scan = knot_tolower(*scan);
	}

	return len + 1;
}

/*!
 * Normalize domain name in wire format.
 */
void dname_normalize(uint8_t *dname)
{
	if (!dname) {
		return;
	}

	uint8_t read, *scan = dname;
	do {
		read = normalize_label(scan);
		scan += read;
	} while (read > 0);
}

/*!
 * Compare dname labels case insensitively.
 */
static int label_casecmp(const uint8_t *a, const uint8_t *b, uint8_t len)
{
	assert(a);
	assert(b);

	for (const uint8_t *a_end = a + len; a < a_end; a++, b++) {
		if (knot_tolower(*a) != knot_tolower(*b)) {
			return false;
		}
	}

	return true;
}

/*!
 * Check if two dnames are equal.
 */
bool dname_equal(const uint8_t *one, const uint8_t *two)
{
	if (!one || !two) {
		return false;
	}

	const uint8_t *scan_one = one;
	const uint8_t *scan_two = two;

	for (;;) {
		if (*scan_one != *scan_two) {
			return false;
		}

		uint8_t len = *scan_one;
		if (len == 0) {
			return true;
		} else if (len > DNAME_MAX_LABEL_LENGTH) {
			return false;
		}

		scan_one += 1;
		scan_two += 1;

		if (!label_casecmp(scan_one, scan_two, len)) {
			return false;
		}

		scan_one += len;
		scan_two += len;
	}

	return true;
}
