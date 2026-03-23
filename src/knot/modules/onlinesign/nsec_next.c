/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include "knot/modules/onlinesign/nsec_next.h"
#include "libknot/libknot.h"

static bool inc_label(const uint8_t *buffer, uint8_t **label_ptr)
{
	assert(buffer);
	assert(label_ptr && *label_ptr);
	assert(buffer <= *label_ptr && *label_ptr < buffer + KNOT_DNAME_MAXLEN);

	uint8_t *label = *label_ptr;
	const uint8_t len = *label;
	const uint8_t *first = *label_ptr + 1;
	uint8_t *last = *label_ptr + len;

	assert(len > 0 && len <= KNOT_DNAME_MAXLABELLEN);

	// append a zero byte at the end whenever possible
	if (len < KNOT_DNAME_MAXLABELLEN && label > buffer) {
		uint8_t *label_new = label - 1;
		*label_new = len + 1;
		memmove(label_new + 1, first, len);
		label_new[len + 1] = 0x00;

		*label_ptr = label_new;
		return true;
	}

	// strip trailing 0xff chars
	if (*last == 0xff) {
		unsigned num0xff = 1;
		while (num0xff < len && *(last - num0xff) == 0xff) {
			num0xff += 1;
		}

		if (num0xff == len) {
			// impossible to increment label, strip it and increment next label
			return false;
		}

		uint8_t *label_new = label + num0xff;
		memmove(label_new + 1, first, len - num0xff);
		*label_new = len - num0xff;

		*label_ptr = label_new;
		// pointer 'last' still valid, able to further manipulate with that one
	}

	// increase in place, skip possible upper-case result
	if (*last == 'A' - 1) {
		*last = 'Z' + 1;
	} else {
		*last += 1;
	}

	return true;
}

static void strip_label(uint8_t **name_ptr)
{
	assert(name_ptr && *name_ptr);

	uint8_t len = **name_ptr;
	*name_ptr += 1 + len;
}

knot_dname_t *online_nsec_next(const knot_dname_t *dname, const knot_dname_t *apex)
{
	assert(dname);
	assert(apex);

	// right aligned copy of the domain name
	knot_dname_storage_t copy = { 0 };
	const size_t dname_len = knot_dname_size(dname);
	const size_t empty_len = sizeof(copy) - dname_len;
	memmove(copy + empty_len, dname, dname_len);

	// add new zero-byte label
	if (empty_len >= 2) {
		uint8_t *pos = copy + empty_len - 2;
		pos[0] = 0x01;
		pos[1] = 0x00;
		return knot_dname_copy(pos, NULL);
	}

	// find apex position in the buffer
	size_t apex_len = knot_dname_size(apex);
	const uint8_t *apex_pos = copy + sizeof(copy) - apex_len;
	assert(knot_dname_is_equal(apex, apex_pos));

	// find first label which can be incremented
	uint8_t *pos = copy + empty_len;
	while (pos != apex_pos) {
		if (inc_label(copy, &pos)) {
			return knot_dname_copy(pos, NULL);
		}
		strip_label(&pos);
	}

	// apex completes the chain
	return knot_dname_copy(pos, NULL);
}
