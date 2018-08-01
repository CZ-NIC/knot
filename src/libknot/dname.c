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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/attribute.h"
#include "libknot/consts.h"
#include "libknot/dname.h"
#include "libknot/errcode.h"
#include "libknot/packet/wire.h"
#include "contrib/ctype.h"
#include "contrib/mempattern.h"
#include "contrib/tolower.h"

static int label_is_equal(const uint8_t *lb1, const uint8_t *lb2)
{
	return (*lb1 == *lb2) && memcmp(lb1 + 1, lb2 + 1, *lb1) == 0;
}

/*!
 * \brief Align name end-to-end and return number of common suffix labels.
 *
 * \param d1         Domain name1.
 * \param d1_labels  Number of labels in d1.
 * \param d2         Domain name2.
 * \param d2_labels  Number of labels in d2.
 */
static int dname_align(const uint8_t **d1, uint8_t d1_labels,
                       const uint8_t **d2, uint8_t d2_labels)
{
	assert(d1 && d2);

	for (unsigned j = d1_labels; j < d2_labels; ++j) {
		*d2 = knot_wire_next_label(*d2, NULL);
	}

	for (unsigned j = d2_labels; j < d1_labels; ++j) {
		*d1 = knot_wire_next_label(*d1, NULL);
	}

	return (d1_labels < d2_labels) ? d1_labels : d2_labels;
}

_public_
int knot_dname_wire_check(const uint8_t *name, const uint8_t *endp,
                          const uint8_t *pkt)
{
	if (name == NULL || name == endp) {
		return KNOT_EINVAL;
	}

	int wire_len = 0;
	int name_len = 1; /* Keep \x00 terminal label in advance. */
	bool is_compressed = false;

	while (*name != '\0') {
		/* Check bounds (must have at least 2 octets remaining). */
		if (name + 2 > endp) {
			return KNOT_EMALF;
		}

		if (knot_wire_is_pointer(name)) {
			/* Check that the pointer points backwards
			 * otherwise it could result in infinite loop
			 */
			if (pkt == NULL) {
				return KNOT_EINVAL;
			}
			uint16_t ptr = knot_wire_get_pointer(name);
			if (ptr >= (name - pkt)) {
				return KNOT_EMALF;
			}

			name = pkt + ptr; /* Hop to compressed label */
			if (!is_compressed) { /* Measure compressed size only */
				wire_len += sizeof(uint16_t);
				is_compressed = true;
			}
		} else {
			/* Check label length. */
			if (*name > KNOT_DNAME_MAXLABELLEN) {
				return KNOT_EMALF;
			}
			/* Check if there's enough space. */
			int lblen = *name + 1;
			if (name_len + lblen > KNOT_DNAME_MAXLEN) {
				return KNOT_EMALF;
			}
			/* Update wire size only for noncompressed part. */
			name_len += lblen;
			if (!is_compressed) {
				wire_len += lblen;
			}
			/* Hop to next label. */
			name += lblen;
		}

		/* Check bounds (must have at least 1 octet). */
		if (name + 1 > endp) {
			return KNOT_EMALF;
		}
	}

	if (!is_compressed) { /* Terminal label. */
		wire_len += 1;
	}

	return wire_len;
}

_public_
size_t knot_dname_store(knot_dname_storage_t dst, const knot_dname_t *name)
{
	if (dst == NULL || name == NULL) {
		return 0;
	}

	size_t len = knot_dname_size(name);
	assert(len <= KNOT_DNAME_MAXLEN);
	memcpy(dst, name, len);

	return len;
}

_public_
knot_dname_t *knot_dname_copy(const knot_dname_t *name, knot_mm_t *mm)
{
	if (name == NULL) {
		return NULL;
	}

	size_t len = knot_dname_size(name);
	knot_dname_t *dst = mm_alloc(mm, len);
	if (dst == NULL) {
		return NULL;
	}
	memcpy(dst, name, len);

	return dst;
}

_public_
int knot_dname_to_wire(uint8_t *dst, const knot_dname_t *src, size_t maxlen)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	size_t len = knot_dname_size(src);
	if (len > maxlen) {
		return KNOT_ESPACE;
	}
	memcpy(dst, src, len);

	return len;
}

_public_
int knot_dname_unpack(uint8_t *dst, const knot_dname_t *src,
                      size_t maxlen, const uint8_t *pkt)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	/* Seek first real label occurrence. */
	src = knot_wire_seek_label(src, pkt);

	/* Unpack rest of the labels. */
	int len = 0;
	while (*src != '\0') {
		uint8_t lblen = *src + 1;
		if (len + lblen > maxlen) {
			return KNOT_ESPACE;
		}
		memcpy(dst + len, src, lblen);
		len += lblen;
		src = knot_wire_next_label(src, pkt);
	}

	/* Terminal label */
	if (len + 1 > maxlen) {
		return KNOT_EINVAL;
	}

	*(dst + len) = '\0';
	return len + 1;
}

_public_
char *knot_dname_to_str(char *dst, const knot_dname_t *name, size_t maxlen)
{
	if (name == NULL) {
		return NULL;
	}

	size_t dname_size = knot_dname_size(name);

	/* Check the size for len(dname) + 1 char termination. */
	size_t alloc_size = (dst == NULL) ? dname_size + 1 : maxlen;
	if (alloc_size < dname_size + 1) {
		return NULL;
	}

	char *res = (dst == NULL) ? malloc(alloc_size) : dst;
	if (res == NULL) {
		return NULL;
	}

	uint8_t label_len = 0;
	size_t  str_len = 0;

	for (unsigned i = 0; i < dname_size; i++) {
		uint8_t c = name[i];

		/* Read next label size. */
		if (label_len == 0) {
			label_len = c;

			/* Write label separation. */
			if (str_len > 0 || dname_size == 1) {
				if (alloc_size <= str_len + 1) {
					goto dname_to_str_failed;
				}
				res[str_len++] = '.';
			}

			continue;
		}

		if (is_alnum(c) || c == '-' || c == '_' || c == '*' ||
		    c == '/') {
			if (alloc_size <= str_len + 1) {
				goto dname_to_str_failed;
			}
			res[str_len++] = c;
		} else if (is_punct(c) && c != '#') {
			/* Exclusion of '#' character is to avoid possible
			 * collision with rdata hex notation '\#'. So it is
			 * encoded in \ddd notation.
			 */

			if (dst != NULL) {
				if (maxlen <= str_len + 2) {
					goto dname_to_str_failed;
				}
			} else {
				/* Extend output buffer for \x format. */
				alloc_size += 1;
				char *extended = realloc(res, alloc_size);
				if (extended == NULL) {
					goto dname_to_str_failed;
				}
				res = extended;
			}

			/* Write encoded character. */
			res[str_len++] = '\\';
			res[str_len++] = c;
		} else {
			if (dst != NULL) {
				if (maxlen <= str_len + 4) {
					goto dname_to_str_failed;
				}
			} else {
				/* Extend output buffer for \DDD format. */
				alloc_size += 3;
				char *extended = realloc(res, alloc_size);
				if (extended == NULL) {
					goto dname_to_str_failed;
				}
				res = extended;
			}

			/* Write encoded character. */
			int ret = snprintf(res + str_len, alloc_size - str_len,
			                   "\\%03u", c);
			if (ret <= 0 || ret >= alloc_size - str_len) {
				goto dname_to_str_failed;
			}

			str_len += ret;
		}

		label_len--;
	}

	/* String_termination. */
	assert(str_len < alloc_size);
	res[str_len] = 0;

	return res;

dname_to_str_failed:

	if (dst == NULL) {
		free(res);
	}

	return NULL;
}

_public_
knot_dname_t *knot_dname_from_str(uint8_t *dst, const char *name, size_t maxlen)
{
	if (name == NULL) {
		return NULL;
	}

	size_t name_len = strlen(name);
	if (name_len == 0) {
		return NULL;
	}

	/* Wire size estimation. */
	size_t alloc_size = maxlen;
	if (dst == NULL) {
		/* Check for the root label. */
		if (name[0] == '.') {
			/* Just the root dname can begin with a dot. */
			if (name_len > 1) {
				return NULL;
			}
			name_len = 0; /* Skip the following parsing. */
			alloc_size = 1;
		} else if (name[name_len - 1] != '.') { /* Check for non-FQDN. */
			alloc_size = 1 + name_len + 1;
		} else {
			alloc_size = 1 + name_len ; /* + 1 ~ first label length. */
		}
	}

	/* The minimal (root) dname takes 1 byte. */
	if (alloc_size == 0) {
		return NULL;
	}

	/* Check the maximal wire size. */
	if (alloc_size > KNOT_DNAME_MAXLEN) {
		alloc_size = KNOT_DNAME_MAXLEN;
	}

	/* Prepare output buffer. */
	uint8_t *wire = (dst == NULL) ? malloc(alloc_size) : dst;
	if (wire == NULL) {
		return NULL;
	}

	uint8_t *label = wire;
	uint8_t *wire_pos = wire + 1;
	uint8_t *wire_end = wire + alloc_size;

	/* Initialize the first label (root label). */
	*label = 0;

	const uint8_t *ch = (const uint8_t *)name;
	const uint8_t *end = ch + name_len;

	while (ch < end) {
		/* Check the output buffer for enough space. */
		if (wire_pos >= wire_end) {
			goto dname_from_str_failed;
		}

		switch (*ch) {
		case '.':
			/* Check for invalid zero-length label. */
			if (*label == 0 && name_len > 1) {
				goto dname_from_str_failed;
			}
			label = wire_pos++;
			*label = 0;
			break;
		case '\\':
			ch++;

			/* At least one more character is required OR
			 * check for maximal label length.
			 */
			if (ch == end || ++(*label) > KNOT_DNAME_MAXLABELLEN) {
				goto dname_from_str_failed;
			}

			/* Check for \DDD notation. */
			if (is_digit(*ch)) {
				/* Check for next two digits. */
				if (ch + 2 >= end ||
				    !is_digit(*(ch + 1)) ||
				    !is_digit(*(ch + 2))) {
					goto dname_from_str_failed;
				}

				uint32_t num = (*(ch + 0) - '0') * 100 +
				               (*(ch + 1) - '0') * 10 +
				               (*(ch + 2) - '0') * 1;
				if (num > UINT8_MAX) {
					goto dname_from_str_failed;
				}
				*(wire_pos++) = num;
				ch +=2;
			} else {
				*(wire_pos++) = *ch;
			}
			break;
		default:
			/* Check for maximal label length. */
			if (++(*label) > KNOT_DNAME_MAXLABELLEN) {
				goto dname_from_str_failed;
			}
			*(wire_pos++) = *ch;
		}
		ch++;
	}

	/* Check for non-FQDN name. */
	if (*label > 0) {
		if (wire_pos >= wire_end) {
			goto dname_from_str_failed;
		}
		*(wire_pos++) = 0;
	}

	/* Reduce output buffer if the size is overestimated. */
	if (wire_pos < wire_end && dst == NULL) {
		uint8_t *reduced = realloc(wire, wire_pos - wire);
		if (reduced == NULL) {
			goto dname_from_str_failed;
		}
		wire = reduced;
	}

	return wire;

dname_from_str_failed:

	if (dst == NULL) {
		free(wire);
	}

	return NULL;
}

_public_
void knot_dname_to_lower(knot_dname_t *name)
{
	if (name == NULL) {
		return;
	}

	while (*name != '\0') {
		uint8_t len = *name;
		for (uint8_t i = 1; i <= len; ++i) {
			name[i] = knot_tolower(name[i]);
		}
		name += 1 + len;
	}
}

_public_
size_t knot_dname_size(const knot_dname_t *name)
{
	if (name == NULL) {
		return 0;
	}

	/* Count name size without terminal label. */
	size_t len = 0;
	while (*name != '\0' && !knot_wire_is_pointer(name)) {
		uint8_t lblen = *name + 1;
		len += lblen;
		name += lblen;
	}

	if (knot_wire_is_pointer(name)) {
		/* Add 2-octet compression pointer. */
		return len + 2;
	} else {
		/* Add 1-octet terminal label. */
		return len + 1;
	}
}

_public_
size_t knot_dname_realsize(const knot_dname_t *name, const uint8_t *pkt)
{
	if (name == NULL) {
		return 0;
	}

	/* Seek first real label occurrence. */
	name = knot_wire_seek_label(name, pkt);

	size_t len = 0;
	while (*name != '\0') {
		len += *name + 1;
		name = knot_wire_next_label(name, pkt);
	}

	/* Add 1-octet terminal label. */
	return len + 1;
}

_public_
size_t knot_dname_matched_labels(const knot_dname_t *d1, const knot_dname_t *d2)
{
	/* Count labels. */
	size_t l1 = knot_dname_labels(d1, NULL);
	size_t l2 = knot_dname_labels(d2, NULL);
	if (l1 == 0 || l2 == 0) {
		return 0;
	}

	/* Align end-to-end to common suffix. */
	int common = dname_align(&d1, l1, &d2, l2);

	/* Count longest chain leading to root label. */
	size_t matched = 0;
	while (common > 0) {
		if (label_is_equal(d1, d2)) {
			++matched;
		} else {
			matched = 0; /* Broken chain. */
		}

		/* Next label. */
		d1 = knot_wire_next_label(d1, NULL);
		d2 = knot_wire_next_label(d2, NULL);
		--common;
	}

	return matched;
}

_public_
knot_dname_t *knot_dname_replace_suffix(const knot_dname_t *name, unsigned labels,
                                        const knot_dname_t *suffix, knot_mm_t *mm)
{
	if (name == NULL) {
		return NULL;
	}

	/* Calculate prefix and suffix lengths. */
	size_t dname_lbs = knot_dname_labels(name, NULL);
	if (dname_lbs < labels) {
		return NULL;
	}
	size_t prefix_lbs = dname_lbs - labels;

	size_t prefix_len = knot_dname_prefixlen(name, prefix_lbs, NULL);
	size_t suffix_len = knot_dname_size(suffix);
	if (prefix_len == 0 || suffix_len == 0) {
		return NULL;
	}

	/* Create target name. */
	size_t new_len = prefix_len + suffix_len;
	knot_dname_t *out = mm_alloc(mm, new_len);
	if (out == NULL) {
		return NULL;
	}

	/* Copy prefix. */
	uint8_t *dst = out;
	while (prefix_lbs > 0) {
		memcpy(dst, name, *name + 1);
		dst += *name + 1;
		name = knot_wire_next_label(name, NULL);
		--prefix_lbs;
	}

	/* Copy suffix. */
	while (*suffix != '\0') {
		memcpy(dst, suffix, *suffix + 1);
		dst += *suffix + 1;
		suffix = knot_wire_next_label(suffix, NULL);
	}

	*dst = '\0';
	return out;
}

_public_
void knot_dname_free(knot_dname_t *name, knot_mm_t *mm)
{
	if (name == NULL) {
		return;
	}

	mm_free(mm, name);
}

_public_
int knot_dname_cmp(const knot_dname_t *d1, const knot_dname_t *d2)
{
	if (d1 == NULL) {
		return -1;
	} else if (d2 == NULL) {
		return 1;
	}

	/* Convert to lookup format. */
	knot_dname_storage_t lf1_storage;
	knot_dname_storage_t lf2_storage;

	uint8_t *lf1 = knot_dname_lf(d1, lf1_storage);
	uint8_t *lf2 = knot_dname_lf(d2, lf2_storage);
	assert(lf1 && lf2);

	/* Compare common part. */
	uint8_t common = lf1[0];
	if (common > lf2[0]) {
		common = lf2[0];
	}
	int ret = memcmp(lf1 + 1, lf2 + 1, common);
	if (ret != 0) {
		return ret;
	}

	/* If they match, compare lengths. */
	if (lf1[0] < lf2[0]) {
		return -1;
	} else if (lf1[0] > lf2[0]) {
		return 1;
	} else {
		return 0;
	}
}

_public_
bool knot_dname_is_equal(const knot_dname_t *d1, const knot_dname_t *d2)
{
	if (d1 == NULL || d2 == NULL) {
		return false;
	}

	while (*d1 != '\0' || *d2 != '\0') {
		if (label_is_equal(d1, d2)) {
			d1 = knot_wire_next_label(d1, NULL);
			d2 = knot_wire_next_label(d2, NULL);
		} else {
			return false;
		}
	}

	return true;
}

_public_
size_t knot_dname_prefixlen(const uint8_t *name, unsigned nlabels, const uint8_t *pkt)
{
	if (name == NULL) {
		return 0;
	}

	/* Zero labels means no prefix. */
	if (nlabels == 0) {
		return 0;
	}

	/* Seek first real label occurrence. */
	name = knot_wire_seek_label(name, pkt);

	size_t len = 0;
	while (*name != '\0') {
		len += *name + 1;
		name = knot_wire_next_label(name, pkt);
		if (--nlabels == 0) { /* Count N first labels only. */
			break;
		}
	}

	return len;
}

_public_
size_t knot_dname_labels(const uint8_t *name, const uint8_t *pkt)
{
	if (name == NULL) {
		return 0;
	}

	size_t count = 0;
	while (*name != '\0') {
		++count;
		name = knot_wire_next_label(name, pkt);
		if (name == NULL) {
			return 0;
		}
	}

	return count;
}

_public_
uint8_t *knot_dname_lf(const knot_dname_t *src, knot_dname_storage_t storage)
{
	if (src == NULL || storage == NULL) {
		return NULL;
	}

	/* Writing from the end. */
	storage[KNOT_DNAME_MAXLEN - 1] = '\0';
	size_t idx = KNOT_DNAME_MAXLEN - 1;

	while (*src != 0) {
		size_t len = *src + 1;

		assert(idx >= len);
		idx -= len;
		memcpy(&storage[idx], src, len);
		storage[idx] = '\0';

		src += len;
	}

	assert(KNOT_DNAME_MAXLEN >= 1 + idx);
	storage[idx] = KNOT_DNAME_MAXLEN - 1 - idx;

	return &storage[idx];
}

_public_
int knot_dname_in_bailiwick(const knot_dname_t *name, const knot_dname_t *bailiwick)
{
	if (name == NULL || bailiwick == NULL) {
		return KNOT_EINVAL;
	}

	int label_diff = knot_dname_labels(name, NULL) - knot_dname_labels(bailiwick, NULL);
	if (label_diff < 0) {
		return KNOT_EOUTOFZONE;
	}

	for (int i = 0; i < label_diff; ++i) {
		name = knot_wire_next_label(name, NULL);
	}

	return knot_dname_is_equal(name, bailiwick) ? label_diff : KNOT_EOUTOFZONE;
}
