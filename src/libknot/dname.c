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

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "libknot/common.h"
#include "libknot/mempattern.h"
#include "libknot/dname.h"
#include "libknot/consts.h"
#include "libknot/util/tolower.h"
#include "common/debug.h"
#include "libknot/util/utils.h"
#include "libknot/packet/wire.h"

/*----------------------------------------------------------------------------*/

static int knot_label_is_equal(const uint8_t *lb1, const uint8_t *lb2)
{
	return (*lb1 == *lb2) && memcmp(lb1 + 1, lb2 + 1, *lb1) == 0;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int knot_dname_wire_check(const uint8_t *name, const uint8_t *endp,
                          const uint8_t *pkt)
{
	if (name == NULL || name == endp)
		return KNOT_EMALF;

	int wire_len = 0;
	int name_len = 1; /* Keep \x00 terminal label in advance. */
	bool is_compressed = false;

	while (*name != '\0') {

		/* Check bounds (must have at least 2 octets remaining). */
		if (name + 2 > endp)
			return KNOT_ESPACE;

		if (knot_wire_is_pointer(name)) {
			/* Check that the pointer points backwards
			 * otherwise it could result in infinite loop
			 */
			if (pkt == NULL)
				return KNOT_EINVAL;
			uint16_t ptr = knot_wire_get_pointer(name);
			if (ptr >= (name - pkt))
				return KNOT_EMALF;

			name = pkt + ptr; /* Hop to compressed label */
			if (!is_compressed) { /* Measure compressed size only */
				wire_len += sizeof(uint16_t);
				is_compressed = true;
			}
		} else {
			/* Check label length. */
			if (*name > KNOT_DNAME_MAXLABELLEN)
				return KNOT_EMALF;
			/* Check if there's enough space. */
			int lblen = *name + 1;
			if (name_len + lblen > KNOT_DNAME_MAXLEN)
				return KNOT_EMALF;
			/* Update wire size only for noncompressed part. */
			name_len += lblen;
			if (!is_compressed)
				wire_len += lblen;
			/* Hop to next label. */
			name += lblen;
		}

		/* Check bounds (must have at least 1 octet). */
		if (name + 1 > endp)
			return KNOT_ESPACE;
	}

	if (!is_compressed) /* Terminal label. */
		wire_len += 1;

	return wire_len;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_parse(const uint8_t *pkt, size_t *pos, size_t maxpos,
                               mm_ctx_t *mm)
{
	if (pkt == NULL || pos == NULL)
		return NULL;

	const uint8_t *name = pkt + *pos;
	const uint8_t *endp = pkt + maxpos;
	int parsed = knot_dname_wire_check(name, endp, pkt);
	if (parsed < 0) {
		return NULL;
	}

	/* Calculate decompressed length. */
	int decompressed_len = knot_dname_realsize(name, pkt);
	if (decompressed_len < 1) {
		return NULL;
	}

	/* Allocate space for the name. */
	knot_dname_t *res = mm_alloc(mm, decompressed_len);
	if (res) {
		/* Unpack name (expand compression pointers). */
		if (knot_dname_unpack(res, name, decompressed_len, pkt) > 0) {
			*pos += parsed;
		} else {
			free(res);
			res = NULL;
		}
	}

	return res;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_copy(const knot_dname_t *name, mm_ctx_t *mm)
{
	if (name == NULL)
		return NULL;

	return knot_dname_copy_part(name, knot_dname_size(name), mm);
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_copy_part(const knot_dname_t *name, unsigned len,
                                   mm_ctx_t *mm)
{
	if (name == NULL || len == 0)
		return NULL;

	knot_dname_t *dst = mm_alloc(mm, len);
	if (knot_dname_to_wire(dst, name, len) < 1) {
		free(dst);
		return NULL;
	}

	return dst;
}

/*----------------------------------------------------------------------------*/

int knot_dname_to_wire(uint8_t *dst, const knot_dname_t *src, size_t maxlen)
{
	if (dst == NULL || src == NULL) {
		return KNOT_EINVAL;
	}

	int len = knot_dname_size(src);
	if (len > maxlen) {
		return KNOT_ESPACE;
	}

	memcpy(dst, src, len);
	return len;
}

/*----------------------------------------------------------------------------*/

int knot_dname_unpack(uint8_t* dst, const knot_dname_t *src,
                      size_t maxlen, const uint8_t *pkt)
{
	if (dst == NULL || src == NULL)
		return KNOT_EINVAL;

	/* Seek first real label occurence. */
	src = knot_wire_seek_label(src, pkt);

	/* Unpack rest of the labels. */
	int len = 0;
	while (*src != '\0') {
		uint8_t lblen = *src + 1;
		if (len + lblen > maxlen)
			return KNOT_ESPACE;
		memcpy(dst + len, src, lblen);
		len += lblen;
		src = knot_wire_next_label(src, pkt);
	}

	/* Terminal label */
	if (len + 1 > maxlen)
		return KNOT_EINVAL;

	*(dst + len) = '\0';
	return len + 1;
}

/*----------------------------------------------------------------------------*/

char *knot_dname_to_str(char *dst, const knot_dname_t *name, size_t maxlen)
{
	if (name == NULL) {
		return NULL;
	}

	int dname_size = knot_dname_size(name);
	if (dname_size <= 0) {
		return NULL;
	}

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

	for (uint i = 0; i < dname_size; i++) {
		uint8_t c = name[i];

		/* Read next label size. */
		if (label_len == 0) {
			label_len = c;

			/* Write label separation. */
			if (str_len > 0 || dname_size == 1) {
				res[str_len++] = '.';
			}

			continue;
		}

		if (isalnum(c) != 0 || c == '-' || c == '_' || c == '*' ||
		    c == '/') {
			res[str_len++] = c;
		} else if (ispunct(c) != 0 && c != '#') {
			/* Exclusion of '#' character is to avoid possible
			 * collision with rdata hex notation '\#'. So it is
			 * encoded in \ddd notation.
			 */

			if (dst != NULL) {
				if (maxlen <= str_len + 2) {
					return NULL;
				}
			} else {
				/* Extend output buffer for \x format. */
				alloc_size += 1;
				char *extended = realloc(res, alloc_size);
				if (extended == NULL) {
					free(res);
					return NULL;
				}
				res = extended;
			}

			/* Write encoded character. */
			res[str_len++] = '\\';
			res[str_len++] = c;
		} else {
			if (dst != NULL) {
				if (maxlen <= str_len + 4) {
					return NULL;
				}
			} else {
				/* Extend output buffer for \DDD format. */
				alloc_size += 3;
				char *extended = realloc(res, alloc_size);
				if (extended == NULL) {
					free(res);
					return NULL;
				}
				res = extended;
			}

			/* Write encoded character. */
			int ret = snprintf(res + str_len, alloc_size - str_len,
			                   "\\%03u", c);
			if (ret <= 0 || ret >= alloc_size - str_len) {
				if (dst == NULL) {
					free(res);
				}
				return NULL;
			}

			str_len += ret;
		}

		label_len--;
	}

	/* String_termination. */
	res[str_len] = 0;

	return res;
}

/*----------------------------------------------------------------------------*/

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
			if (isdigit(*ch) != 0) {
				/* Check for next two digits. */
				if (ch + 2 >= end ||
				    isdigit(*(ch + 1)) == 0 ||
				    isdigit(*(ch + 2)) == 0) {
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

/*----------------------------------------------------------------------------*/

int knot_dname_to_lower(knot_dname_t *name)
{
	if (name == NULL)
		return KNOT_EINVAL;

	/*! \todo Faster with \xdfdf mask. */
	while (*name != '\0') {
		for (uint8_t i = 0; i < *name; ++i)
			name[1 + i] = knot_tolower(name[1 + i]);
		name = (uint8_t *)knot_wire_next_label(name, NULL);
		if (name == NULL) { /* Must not be used on compressed names. */
			return KNOT_EMALF;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_dname_size(const knot_dname_t *name)
{
	if (name == NULL)
		return KNOT_EINVAL;

	/* Count name size without terminal label. */
	int len = 0;
	while (*name != '\0' && !knot_wire_is_pointer(name)) {
		uint8_t lblen = *name + 1;
		len += lblen;
		name += lblen;
	}

	/* Compression pointer is 2 octets. */
	if (knot_wire_is_pointer(name))
		return len + 2;

	return len + 1;
}

/*----------------------------------------------------------------------------*/

int knot_dname_realsize(const knot_dname_t *name, const uint8_t *pkt)
{
	return knot_dname_prefixlen(name, KNOT_DNAME_MAXLABELS, pkt);
}

/*----------------------------------------------------------------------------*/

bool knot_dname_is_sub(const knot_dname_t *sub, const knot_dname_t *domain)
{
	if (sub == domain)
		return false;

	/* Count labels. */
	assert(sub != NULL && domain != NULL);
	int sub_l = knot_dname_labels(sub, NULL);
	int domain_l = knot_dname_labels(domain, NULL);

	if (sub_l < 0 || domain_l < 0)
		return false;

	assert(sub_l >= 0 && sub_l <= KNOT_DNAME_MAXLABELS);
	assert(domain_l >= 0 && domain_l <= KNOT_DNAME_MAXLABELS);

	/* Subdomain must have more labels as parent. */
	if (sub_l <= domain_l)
		return false;

	/* Align end-to-end to common suffix. */
	int common = knot_dname_align(&sub, sub_l, &domain, domain_l, NULL);

	/* Compare common suffix. */
	while(common > 0) {
		/* Compare label. */
		if (!knot_label_is_equal(sub, domain))
			return false;
		/* Next label. */
		sub = knot_wire_next_label(sub, NULL);
		domain = knot_wire_next_label(domain, NULL);
		--common;
	}
	return true;
}

/*----------------------------------------------------------------------------*/

bool knot_dname_in(const knot_dname_t *domain, const knot_dname_t *sub)
{
	return knot_dname_is_equal(domain, sub) || knot_dname_is_sub(sub, domain);
}

/*----------------------------------------------------------------------------*/

bool knot_dname_is_wildcard(const knot_dname_t *name)
{
	assert(name != NULL);
	return name[0] == 1 && name[1] == '*';
}

/*----------------------------------------------------------------------------*/

int knot_dname_matched_labels(const knot_dname_t *d1, const knot_dname_t *d2)
{
	if (d1 == NULL || d2 == NULL)
		return KNOT_EINVAL;

	/* Count labels. */
	int l1 = knot_dname_labels(d1, NULL);
	int l2 = knot_dname_labels(d2, NULL);

	if (l1 < 0 || l2 < 0)
		return KNOT_EINVAL;

	assert(l1 >= 0 && l1 <= KNOT_DNAME_MAXLABELS);
	assert(l2 >= 0 && l2 <= KNOT_DNAME_MAXLABELS);

	/* Align end-to-end to common suffix. */
	int common = knot_dname_align(&d1, l1, &d2, l2, NULL);

	/* Count longest chain leading to root label. */
	int matched = 0;
	while (common > 0) {
		if (knot_label_is_equal(d1, d2))
			++matched;
		else
			matched = 0; /* Broken chain. */

		/* Next label. */
		d1 = knot_wire_next_label(d1, NULL);
		d2 = knot_wire_next_label(d2, NULL);
		--common;
	}

	return matched;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_replace_suffix(const knot_dname_t *name, unsigned labels,
                                        const knot_dname_t *suffix)
{
	if (name == NULL)
		return NULL;

	/* Calculate prefix and suffix lengths. */
	int dname_lbs = knot_dname_labels(name, NULL);
	assert(dname_lbs >= labels);
	unsigned prefix_lbs = dname_lbs - labels;

	/* Trim 1 octet from prefix, as it is measured as FQDN. */
	int prefix_len = knot_dname_prefixlen(name, prefix_lbs, NULL) - 1;
	int suffix_len = knot_dname_size(suffix);
	if (prefix_len < 0 || suffix_len < 0)
		return NULL;

	/* Create target name. */
	int new_len = prefix_len + suffix_len;
	knot_dname_t *out = malloc(new_len);
	if (out == NULL)
		return NULL;

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

/*----------------------------------------------------------------------------*/

void knot_dname_free(knot_dname_t **name, mm_ctx_t *mm)
{
	if (name == NULL || *name == NULL)
		return;

	mm_free(mm, *name);
	*name = NULL;
}

/*----------------------------------------------------------------------------*/

int knot_dname_cmp(const knot_dname_t *d1, const knot_dname_t *d2)
{
	return knot_dname_cmp_wire(d1, d2, NULL);
}

/*----------------------------------------------------------------------------*/

int knot_dname_cmp_wire(const knot_dname_t *d1, const knot_dname_t *d2,
                        const uint8_t *pkt)
{
	/* This would be hard to catch since -1 is a good result, assert instead. */
	assert(d1 != NULL || d2 != NULL);

	/* Convert to lookup format. */
	uint8_t d1_lf[KNOT_DNAME_MAXLEN], d2_lf[KNOT_DNAME_MAXLEN];
	if (knot_dname_lf(d1_lf, d1, pkt) < 0 || knot_dname_lf(d2_lf, d2, pkt) < 0) {
		assert(0); /* This must not happend as the d1, d2 are checked. */
		return KNOT_EINVAL;
	}

	/* Compare common part. */
	uint8_t common = d1_lf[0];
	if (common > d2_lf[0])
		common = d2_lf[0];
	int ret = memcmp(d1_lf+1, d2_lf+1, common);
	if (ret != 0)
		return ret;

	/* If they match, compare lengths. */
	if (d1_lf[0] < d2_lf[0])
		return -1;
	if (d1_lf[0] > d2_lf[0])
		return 1;
	return 0;
}

/*----------------------------------------------------------------------------*/

bool knot_dname_is_equal(const knot_dname_t *d1, const knot_dname_t *d2)
{
	while(*d1 != '\0' || *d2 != '\0') {
		if (knot_label_is_equal(d1, d2)) {
			d1 = knot_wire_next_label(d1, NULL);
			d2 = knot_wire_next_label(d2, NULL);
		} else {
			return false;
		}
	}

	return true;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_cat(knot_dname_t *d1, const knot_dname_t *d2)
{
	if (d1 == NULL || d2 == NULL)
		return NULL;

	/* This is problem equal to replacing last \x00 from d1 with d2. */
	knot_dname_t *ret = knot_dname_replace_suffix(d1, 0, d2);

	/* Like if we are reallocating d1. */
	if (ret != NULL)
		knot_dname_free(&d1, NULL);

	return ret;
}

/*----------------------------------------------------------------------------*/

int knot_dname_prefixlen(const uint8_t *name, unsigned nlabels, const uint8_t *pkt)
{
	if (name == NULL)
		return KNOT_EINVAL;

	/* Zero labels means 1 octet \x00 */
	if (nlabels == 0)
		return 1;

	/* Seek first real label occurence. */
	name = knot_wire_seek_label(name, pkt);

	int len = 1; /* Terminal label */
	while (*name != '\0') {
		len += *name + 1;
		name = knot_wire_next_label(name, pkt);
		if (--nlabels == 0) /* Count N first labels only. */
			break;
	}

	return len;
}

/*----------------------------------------------------------------------------*/

int knot_dname_labels(const uint8_t *name, const uint8_t *pkt)
{
	if (name == NULL)
		return KNOT_EINVAL;

	uint8_t count = 0;
	while (*name != '\0') {
		++count;
		name = knot_wire_next_label((uint8_t *)name, (uint8_t *)pkt);
		if (!name)
			return KNOT_EMALF;
	}
	return count;
}

/*----------------------------------------------------------------------------*/

int knot_dname_align(const uint8_t **d1, uint8_t d1_labels,
                     const uint8_t **d2, uint8_t d2_labels,
                     uint8_t *wire)
{
	if (d1 == NULL || d2 == NULL)
		return KNOT_EINVAL;

	for (unsigned j = d1_labels; j < d2_labels; ++j)
		*d2 = knot_wire_next_label(*d2, wire);

	for (unsigned j = d2_labels; j < d1_labels; ++j)
		*d1 = knot_wire_next_label(*d1, wire);

	return (d1_labels < d2_labels) ? d1_labels : d2_labels;
}

/*----------------------------------------------------------------------------*/

int knot_dname_lf(uint8_t *dst, const knot_dname_t *src, const uint8_t *pkt)
{
	if (dst == NULL || src == NULL)
		return KNOT_EINVAL;

	uint8_t *len = dst++;
	*len = '\0';
	*dst = '\0';
	const uint8_t* l = src;
	/*! \todo This could be made as offsets to pkt? */
	const uint8_t* lstack[KNOT_DNAME_MAXLABELS];
	const uint8_t **sp = lstack;
    //int counter =0;
	while(*l != 0) { /* build label stack */
        //printf("%d ",counter);
        //counter++;
		*sp++ = l;
		l = knot_wire_next_label(l, pkt);
	}
    //printf("\n");
	while(sp != lstack) {          /* consume stack */
		l = *--sp; /* fetch rightmost label */
		memcpy(dst, l+1, *l);  /* write label */
		for (int i = 0; i < *l; ++i) {   /* convert to lowercase */
			dst[i] = knot_tolower(dst[i]);
		}
		dst += *l;
		*dst++ = '\0';         /* label separator */
		*len += *l + 1;
	}

	/* root label special case */
	if (*len == 0)
		*len = 1; /* \x00 */

	return KNOT_EOK;
}
