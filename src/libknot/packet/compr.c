/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libknot/attribute.h"
#include "libknot/packet/compr.h"
#include "libknot/errcode.h"
#include "libknot/packet/pkt.h"
#include "contrib/tolower.h"

/*! \brief Case insensitive label compare for compression. */
static bool compr_label_match(const uint8_t *n, const uint8_t *p)
{
	assert(n);
	assert(p);

	if (*n != *p) {
		return false;
	}

	uint8_t len = *n;
	for (uint8_t i = 1; i <= len; ++i) {
		if (knot_tolower(n[i]) != knot_tolower(p[i])) {
			return false;
		}
	}

	return true;
}

/*! \brief Helper for \fn knot_compr_put_dname, writes label(s) with size checks. */
#define WRITE_LABEL(dst, written, label, max, len) \
	if ((written) + (len) > (max)) { \
		return KNOT_ESPACE; \
	} else { \
		memcpy((dst) + (written), (label), (len)); \
		written += (len); \
	}

_public_
int knot_compr_put_dname(const knot_dname_t *dname, uint8_t *dst, uint16_t max,
                         knot_compr_t *compr)
{
	if (dname == NULL || dst == NULL) {
		return KNOT_EINVAL;
	}

	/* Write uncompressible names directly (zero label dname). */
	if (compr == NULL || *dname == '\0') {
		return knot_dname_to_wire(dst, dname, max);
	}

	/* Get number of labels (should not be a zero label dname). */
	int name_labels = knot_dname_labels(dname, NULL);
	assert(name_labels > 0);

	/* Suffix must not be longer than whole name. */
	const knot_dname_t *suffix = compr->wire + compr->suffix.pos;
	int suffix_labels = compr->suffix.labels;
	while (suffix_labels > name_labels) {
		suffix = knot_wire_next_label(suffix, compr->wire);
		--suffix_labels;
	}

	/* Suffix is shorter than name, write labels until aligned. */
	uint8_t orig_labels = name_labels;
	uint16_t written = 0;
	while (name_labels > suffix_labels) {
		WRITE_LABEL(dst, written, dname, max, (*dname + 1));
		dname = knot_wire_next_label(dname, NULL);
		--name_labels;
	}

	/* Label count is now equal. */
	assert(name_labels == suffix_labels);
	const knot_dname_t *match_begin = dname;
	const knot_dname_t *compr_ptr = suffix;
	while (dname[0] != '\0') {

		/* Next labels. */
		const knot_dname_t *next_dname = knot_wire_next_label(dname, NULL);
		const knot_dname_t *next_suffix = knot_wire_next_label(suffix, compr->wire);

		/* Two labels match, extend suffix length. */
		if (!compr_label_match(dname, suffix)) {
			/* If they don't match, write unmatched labels. */
			uint16_t mismatch_len = (dname - match_begin) + (*dname + 1);
			WRITE_LABEL(dst, written, match_begin, max, mismatch_len);
			/* Start new potential match. */
			match_begin = next_dname;
			compr_ptr = next_suffix;
		}

		/* Jump to next labels. */
		dname = next_dname;
		suffix = next_suffix;
	}

	/* If match begins at the end of the name, write '\0' label. */
	if (match_begin == dname) {
		WRITE_LABEL(dst, written, dname, max, 1);
	} else {
		/* Match covers >0 labels, write out compression pointer. */
		if (written + sizeof(uint16_t) > max) {
			return KNOT_ESPACE;
		}
		knot_wire_put_pointer(dst + written, compr_ptr - compr->wire);
		written += sizeof(uint16_t);
	}

	assert(dst >= compr->wire);
	size_t wire_pos = dst - compr->wire;
	assert(wire_pos < KNOT_WIRE_MAX_PKTSIZE);

	/* Heuristics - expect similar names are grouped together. */
	if (written > sizeof(uint16_t) && wire_pos + written < KNOT_WIRE_PTR_MAX) {
		compr->suffix.pos = wire_pos;
		compr->suffix.labels = orig_labels;
	}

	return written;
}

#undef WRITE_LABEL
