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

#include "knot/modules/onlinesign/nsec_next.h"
#include "libknot/libknot.h"

static bool inc_label(const uint8_t *buffer, uint8_t **label_ptr)
{
	assert(buffer);
	assert(label_ptr && *label_ptr);
	assert(buffer <= *label_ptr && *label_ptr < buffer + KNOT_DNAME_MAXLEN);

	const uint8_t *label = *label_ptr;
	const uint8_t len    = *label;
	const uint8_t *first = *label_ptr + 1;
	const uint8_t *last  = *label_ptr + len;

	assert(len <= KNOT_DNAME_MAXLABELLEN);

	// jump over trailing 0xff chars
	uint8_t *scan = (uint8_t *)last;
	while (scan >= first && *scan == 0xff) {
		scan -= 1;
	}

	// increase in place
	if (scan >= first) {
		*scan += 1;
		memset(scan + 1, 0x00, last - scan);
		return true;
	}

	// check name and label boundaries
	if (scan - 1 < buffer || len == KNOT_DNAME_MAXLABELLEN) {
		return false;
	}

	// append a zero byte at the end of the label
	scan -= 1;
	scan[0] = len + 1;
	memmove(scan + 1, first, len);
	scan[len + 1] = 0x00;

	*label_ptr = scan;

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
	uint8_t copy[KNOT_DNAME_MAXLEN] = { 0 };
	size_t dname_len = knot_dname_size(dname);
	size_t empty_len = sizeof(copy) - dname_len;
	uint8_t *pos = copy + empty_len;
	memmove(pos, dname, dname_len);

	// add new zero-byte label
	if (empty_len >= 2) {
		pos -= 2;
		pos[0] = 0x01;
		pos[1] = 0x00;
		return knot_dname_copy(pos, NULL);
	}

	// find apex position in the buffer
	size_t apex_len = knot_dname_size(apex);
	const uint8_t *apex_pos = copy + sizeof(copy) - apex_len;
	assert(knot_dname_cmp(apex, apex_pos) == 0);

	// find first label which can be incremented
	while (pos != apex_pos) {
		if (inc_label(copy, &pos)) {
			return knot_dname_copy(pos, NULL);
		}
		strip_label(&pos);
	}

	// apex completes the chain
	return knot_dname_copy(pos, NULL);
}
