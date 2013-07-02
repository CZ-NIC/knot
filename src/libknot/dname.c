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

#include <config.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>	// tolower()
#include <inttypes.h>

#include "common.h"
#include "common/mempattern.h"
#include "dname.h"
#include "consts.h"
#include "util/tolower.h"
#include "util/debug.h"
#include "util/utils.h"
#include "util/wire.h"


/*----------------------------------------------------------------------------*/
/* Non-API functions                                                          */
/*----------------------------------------------------------------------------*/

static knot_dname_t *knot_dname_new()
{
	knot_dname_t *dname = malloc(sizeof(knot_dname_t));

	dname->name = NULL;
	dname->count = 1;
	dname->size = 0;

	return dname;
}

/*!
 * \brief Converts domain name from string representation to wire format.
 *
 * This function also allocates the space for the wire format.
 *
 * \param name Domain name in string representation (presentation format).
 * \param size Size of the given domain name in characters (not counting the
 *             terminating 0 character.
 * \param dname Domain name where to store the wire format.
 *
 * \return Size of the wire format of the domain name in octets. If 0, no
 *         space has been allocated.
 *
 * \todo handle \X and \DDD (RFC 1035 5.1) or it can be handled by the parser?
 */
static int knot_dname_str_to_wire(const char *name, uint size,
                                    knot_dname_t *dname)
{
	if (size == 0 || size > KNOT_MAX_DNAME_LENGTH) {
		return KNOT_EINVAL;
	}

	unsigned wire_size = size + 1;
	if (name[0] == '.' && size == 1) {
		wire_size = 1; /* Root label. */
		size = 0;      /* Do not parse input. */
	} else if (name[size - 1] != '.') {
		++wire_size; /* No FQDN, reserve last root label. */
	}

	/* Create wire. */
	uint8_t *wire = malloc(wire_size * sizeof(uint8_t));
	if (wire == NULL)
		return KNOT_ENOMEM;
	*wire = '\0';

	const uint8_t *ch = (const uint8_t *)name;
	const uint8_t *np = ch + size;
	uint8_t *label = wire;
	uint8_t *w = wire + 1; /* Reserve 1 for label len */
	while (ch != np) {
		if (*ch == '.') {
			/* Zero-length label inside a dname - invalid. */
			if (*label == 0) {
				free(wire);
				return KNOT_EMALF;
			}
			label = w;
			*label = '\0';
		} else {
			*w = *ch;
			*label += 1;
		}
		++w;
		++ch;
	}

	/* Check for non-FQDN name. */
	if (*label > 0) {
		*w = '\0';
	}

	dname->name = wire;
	dname->size = wire_size;
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_label_is_equal(const uint8_t *lb1, const uint8_t *lb2)
{
	return (*lb1 == *lb2) && memcmp(lb1 + 1, lb2 + 1, *lb1) == 0;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_new_from_str(const char *name, uint size)
{
	if (name == NULL || size == 0) {
		return NULL;
	}

	knot_dname_t *dname = knot_dname_new();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	/*! \todo The function should return error codes. */
	int ret = knot_dname_str_to_wire(name, size, dname);
	if (ret != 0) {
		dbg_dname("Failed to create domain name from string.\n");
		knot_dname_free(&dname);
		return NULL;
	}

	if (dname->size <= 0) {
		dbg_dname("Could not parse domain name "
		          "from string: '%.*s'\n", size, name);
	}
	assert(dname->name != NULL);

	return dname;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_new_from_wire(const uint8_t *name, uint size)
{
	if (name == NULL) { /* && size != 0) { !OS: Nerozumjaju */
		dbg_dname("No name given!\n");
		return NULL;
	}

	knot_dname_t *dname = knot_dname_new();

	if (dname == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	dname->name = (uint8_t *)malloc(size * sizeof(uint8_t));
	if (dname->name == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&dname);
		return NULL;
	}

	/*! \todo this won't work for non-linear names */
	memcpy(dname->name, name, size);
	dname->size = size;
	return dname;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_parse_from_wire(const uint8_t *wire,
                                         size_t *pos, size_t size)
{
	const uint8_t *name = wire + *pos;
	const uint8_t *endp = wire + size;
	int parsed = knot_dname_wire_check(name, endp, wire);
	if (parsed < 0)
		return NULL;

	knot_dname_t *dname = knot_dname_new_from_wire(name, parsed);
	if (dname)
		*pos += parsed;

	return dname;
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_deep_copy(const knot_dname_t *dname)
{
	/* dname_new_from_wire() does not accept non-FQDN dnames, so we
	 * do the copy by hand. It's faster anyway */

	if (dname == NULL) {
		return NULL;
	}

	knot_dname_t *copy = knot_dname_new();
	CHECK_ALLOC(copy, NULL);

	copy->name = (uint8_t *)(malloc(dname->size));
	if (copy->name == NULL) {
		knot_dname_free(&copy);
		return NULL;
	}

	memcpy(copy->name, dname->name, dname->size);
	copy->size = dname->size;

	return copy;
}

/*----------------------------------------------------------------------------*/

char *knot_dname_to_str(const knot_dname_t *dname)
{
	if (!dname || dname->size == 0) {
		return 0;
	}

	// Allocate space for dname string + 1 char termination.
	size_t alloc_size = dname->size + 1;
	char *name = malloc(alloc_size);
	if (name == NULL) {
		return NULL;
	}

	uint8_t label_len = 0;
	size_t  str_len = 0;

	for (uint i = 0; i < dname->size; i++) {
		uint8_t c = dname->name[i];

		// Read next label size.
		if (label_len == 0) {
			label_len = c;

			// Write label separation.
			if (str_len > 0 || dname->size == 1) {
				name[str_len++] = '.';
			}

			continue;
		}

		if (isalnum(c) != 0 || c == '-' || c == '_' || c == '*' ||
		    c == '/') {
			name[str_len++] = c;
		} else if (ispunct(c) != 0) {
			// Increase output size for \x format.
			alloc_size += 1;
			char *extended = realloc(name, alloc_size);
			if (extended == NULL) {
				free(name);
				return NULL;
			}
			name = extended;

			// Write encoded character.
			name[str_len++] = '\\';
			name[str_len++] = c;
		} else {
			// Increase output size for \DDD format.
			alloc_size += 3;
			char *extended = realloc(name, alloc_size);
			if (extended == NULL) {
				free(name);
				return NULL;
			}
			name = extended;

			// Write encoded character.
			int ret = snprintf(name + str_len, alloc_size - str_len,
			                   "\\%03u", c);
			if (ret <= 0 || ret >= alloc_size - str_len) {
				free(name);
				return NULL;
			}

			str_len += ret;
		}

		label_len--;
	}

	// String_termination.
	name[str_len] = 0;

	return name;
}

/*----------------------------------------------------------------------------*/

int knot_dname_to_lower(knot_dname_t *dname)
{
	return knot_dname_to_lower_copy(dname, (char*)dname->name, dname->size);
}

/*----------------------------------------------------------------------------*/

int knot_dname_to_lower_copy(const knot_dname_t *dname, char *name,
                             size_t size)
{
	if (dname == NULL || name == NULL || size < dname->size) {
		return KNOT_EINVAL;
	}

	for (int i = 0; i < dname->size; ++i) {
		name[i] = knot_tolower(dname->name[i]);
	}
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

const uint8_t *knot_dname_name(const knot_dname_t *dname)
{
	return dname->name;
}

/*----------------------------------------------------------------------------*/

uint knot_dname_size(const knot_dname_t *dname)
{
	return dname->size;
}

/*----------------------------------------------------------------------------*/

int knot_dname_is_fqdn(const knot_dname_t *dname)
{
	return (dname->name[dname->size - 1] == '\0');
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_left_chop(const knot_dname_t *dname)
{
	if (dname == NULL || *knot_dname_name(dname) == '\0') { /* root */
		return NULL;
	}

	knot_dname_t *parent = knot_dname_new();
	if (parent == NULL) {
		return NULL;
	}

	parent->size = dname->size - dname->name[0] - 1;
	parent->name = (uint8_t *)malloc(parent->size);
	if (parent->name == NULL) {
		ERR_ALLOC_FAILED;
		knot_dname_free(&parent);
		return NULL;
	}

	memcpy(parent->name, &dname->name[dname->name[0] + 1], parent->size);
	return parent;
}

/*----------------------------------------------------------------------------*/

void knot_dname_left_chop_no_copy(knot_dname_t *dname)
{
	uint8_t len = *knot_dname_name(dname);
	if (len == 0)
		return;

	/*! \todo this will work only with linearized names (as of now) */
	dname->size -= (len + 1);
	memmove(dname->name, dname->name + len + 1, dname->size);
}

/*----------------------------------------------------------------------------*/

int knot_dname_is_subdomain(const knot_dname_t *sub,
                              const knot_dname_t *domain)
{
	if (sub == domain)
		return 0;

	/* Count labels. */
	const uint8_t *sub_p = sub->name;
	const uint8_t *domain_p = domain->name;
	int sub_l = knot_dname_wire_labels(sub_p, NULL);
	int domain_l = knot_dname_wire_labels(domain_p, NULL);

	/* Subdomain must have more labels as parent. */
	if (sub_l <= domain_l)
		return 0;

	/* Align end-to-end to common suffix. */
	int common = knot_dname_align(&sub_p, sub_l, &domain_p, domain_l, NULL);

	/* Compare common suffix. */
	while(common > 0) {
		/* Compare label. */
		if (!knot_label_is_equal(sub_p, domain_p))
			return 0;
		/* Next label. */
		sub_p = knot_wire_next_label(sub_p, NULL);
		domain_p = knot_wire_next_label(domain_p, NULL);
		--common;
	}
	return 1;
}

/*----------------------------------------------------------------------------*/

int knot_dname_is_wildcard(const knot_dname_t *dname)
{
	return (dname->size >= 2
		&& dname->name[0] == 1
		&& dname->name[1] == '*');
}

/*----------------------------------------------------------------------------*/

int knot_dname_matched_labels(const knot_dname_t *dname1,
                                const knot_dname_t *dname2)
{
	/* Count labels. */
	const uint8_t *d1 = dname1->name;
	const uint8_t *d2 = dname2->name;
	int l1 = knot_dname_wire_labels(d1, NULL);
	int l2 = knot_dname_wire_labels(d2, NULL);

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

knot_dname_t *knot_dname_replace_suffix(const knot_dname_t *dname, int size,
                                        const knot_dname_t *suffix)
{
dbg_dname_exec_verb(
	char *name = knot_dname_to_str(dname);
	dbg_dname_verb("Replacing suffix of name %s, size %d with ", name,
	               size);
	free(name);
	name = knot_dname_to_str(suffix);
	dbg_dname_verb("%s (size %d)\n", name, suffix->size);
	free(name);
);
	knot_dname_t *res = knot_dname_new();
	CHECK_ALLOC(res, NULL);

	res->size = dname->size - size + suffix->size;

	dbg_dname_detail("Allocating %d bytes...\n", res->size);
	res->name = (uint8_t *)malloc(res->size);
	if (res->name == NULL) {
		knot_dname_free(&res);
		return NULL;
	}

	dbg_dname_hex((char *)res->name, res->size);

	dbg_dname_detail("Copying %d bytes from the original name.\n",
	                 dname->size - size);
	memcpy(res->name, dname->name, dname->size - size);
	dbg_dname_hex((char *)res->name, res->size);

	dbg_dname_detail("Copying %d bytes from the suffix.\n", suffix->size);
	memcpy(res->name + dname->size - size, suffix->name, suffix->size);

	dbg_dname_hex((char *)res->name, res->size);

	return res;
}

/*----------------------------------------------------------------------------*/

void knot_dname_free(knot_dname_t **dname)
{
	if (dname == NULL || *dname == NULL) {
		return;
	}

	free((*dname)->name);

//	slab_free(*dname);
	free(*dname);
	*dname = NULL;
}

/*----------------------------------------------------------------------------*/

int knot_dname_compare(const knot_dname_t *d1, const knot_dname_t *d2)
{
	return knot_dname_wire_cmp(d1, d2, NULL);
}

/*----------------------------------------------------------------------------*/

int knot_dname_compare_cs(const knot_dname_t *d1, const knot_dname_t *d2)
{
	return knot_dname_wire_cmp(d1, d2, NULL);
}

int knot_dname_compare_non_canon(const knot_dname_t *d1, const knot_dname_t *d2)
{
	int ret = memcmp(d1->name, d2->name,
	                 d1->size > d2->size ? d2->size : d1->size);
	if (d1->size != d2->size && ret == 0) {
		return d1->size < d2->size ? -1 : 1;
	} else {
		return ret;
	}
}

/*----------------------------------------------------------------------------*/

knot_dname_t *knot_dname_cat(knot_dname_t *d1, const knot_dname_t *d2)
{
	if (d2->size == 0) {
		return d1;
	}

	// allocate new space
	size_t new_size = d1->size + d2->size - 1; /* Trim the d1 \0 label */
	uint8_t *new_dname = (uint8_t *)malloc(new_size);
	CHECK_ALLOC_LOG(new_dname, NULL);

	dbg_dname_detail("1: copying %d bytes from adress %p to %p\n",
	                 d1->size, d1->name, new_dname);

	memcpy(new_dname, d1->name, d1->size);

	dbg_dname_detail("2: copying %d bytes from adress %p to %p\n",
	                 d2->size, d2->name, new_dname + d1->size);

	/* Overwrite the d1 \0 label. */
	memcpy(new_dname + d1->size - 1, d2->name, d2->size);

	uint8_t *old_name = d1->name;
	d1->name = new_dname;
	free(old_name);

	d1->size = new_size;

	return d1;
}

int knot_dname_wire_check(const uint8_t *name, const uint8_t *endp,
                          const uint8_t *pkt)
{
	if (name == NULL || name == endp)
		return KNOT_EMALF;

	int wire_len = 0; /* Keep terminal label in advance. */
	int name_len = 0;
	uint8_t is_compressed = 0;
	uint8_t labels = 0;

	while (*name != '\0') {

		/* Check bounds (must have at least 2 octets remaining). */
		if (name + 2 > endp)
			return KNOT_ESPACE;

		/* Reject more labels. */
		if (labels == KNOT_MAX_DNAME_LABELS - 1)
			return KNOT_EMALF;

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
				is_compressed = 1;
			}
		} else {
			/* Check label length (maximum 63 bytes allowed). */
			if (*name > 63)
				return KNOT_EMALF;
			/* Check if there's enough space. */
			int lblen = *name + 1;
			if (name_len + lblen > KNOT_MAX_DNAME_LENGTH)
				return KNOT_EMALF;
			/* Update wire size only for noncompressed part. */
			name_len += lblen;
			if (!is_compressed)
				wire_len += lblen;
			/* Hop to next label. */
			name += lblen;
			++labels;
		}

		/* Check bounds (must have at least 1 octet). */
		if (name + 1 > endp)
			return KNOT_ESPACE;
	}

	if (!is_compressed) /* Terminal label. */
		wire_len += 1;

	return wire_len;
}

int knot_dname_wire_size(const uint8_t *name, const uint8_t *pkt)
{
	if (!name)
		return KNOT_EINVAL;

	/* Seek first real label occurence. */
	while (knot_wire_is_pointer(name)) {
		name = knot_wire_next_label((uint8_t *)name, (uint8_t *)pkt);
	}

	int len = 1; /* Terminal label */
	while (*name != '\0') {
		len += *name + 1;
		name = knot_wire_next_label((uint8_t *)name, (uint8_t *)pkt);
	}

	return len;
}

int knot_dname_wire_labels(const uint8_t *name, const uint8_t *pkt)
{
	uint8_t count = 0;
	while (*name != '\0') {
		++count;
		name = knot_wire_next_label((uint8_t *)name, (uint8_t *)pkt);
		if (!name)
			return KNOT_EMALF;
	}
	return count;
}

int knot_dname_align(const uint8_t **d1, uint8_t d1_labels,
                     const uint8_t **d2, uint8_t d2_labels,
                     uint8_t *wire)
{
	for (unsigned j = d1_labels; j < d2_labels; ++j)
		*d2 = knot_wire_next_label(*d2, wire);

	for (unsigned j = d2_labels; j < d1_labels; ++j)
		*d1 = knot_wire_next_label(*d1, wire);

	return (d1_labels < d2_labels) ? d1_labels : d2_labels;
}

int knot_dname_wire_cmp(const knot_dname_t *d1, const knot_dname_t *d2,
                        const uint8_t *pkt)
{
	/*! \todo lf conversion should respect packet wire. */

	/* Convert to lookup format. */
	unsigned buflen = DNAME_LFT_MAXLEN;
	uint8_t d1_lf[DNAME_LFT_MAXLEN], d2_lf[DNAME_LFT_MAXLEN];
	if (dname_lf(d1_lf, d1, buflen) < 0 || dname_lf(d2_lf, d2, buflen) < 0)
		return KNOT_EINVAL;

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

int dname_lf(uint8_t *dst, const knot_dname_t *src, size_t maxlen)
{
	if (src->size > maxlen)
		return KNOT_ESPACE;
	*dst = (uint8_t)src->size;
	/* need to save last \x00 for root dname */
	if (*dst > 1)
		*dst -= 1;
	*++dst = '\0';
	uint8_t* l = src->name;
	uint8_t lstack[DNAME_LFT_MAXLEN];
	uint8_t *sp = lstack;
	while(*l != 0) { /* build label stack */
		*sp++ = (l - src->name);
		l += 1 + *l;
	}
	while(sp != lstack) {          /* consume stack */
		l = src->name + *--sp; /* fetch rightmost label */
		memcpy(dst, l+1, *l);  /* write label */
		dst += *l;
		*dst++ = '\0';         /* label separator */
	}
	return KNOT_EOK;
}
