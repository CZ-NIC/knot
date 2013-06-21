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
#include <assert.h>

#include "estimator.h"
#include "dname.h"
#include "libknot/zone/node.h"
#include "common/hattrie/ahtable.h"
#include "zscanner/scanner.h"
#include "common/descriptor.h"

enum estim_consts {
	DNAME_MULT = 1,
	DNAME_ADD = 0,
	RDATA_MULT = 1,
	RDATA_ADD = 0,
	RRSET_MULT = 1,
	RRSET_ADD = 0,
	NODE_MULT = 1,
	NODE_ADD = 0
};

typedef struct dummy_node {
	// Types are enough for now, later we can add more
	uint16_t *types;
	size_t allocated;
	size_t used;
} dummy_node_t;

// Insert value to position - move the rest of the array
static void insert_on_pos(dummy_node_t *n, size_t pos, uint16_t t)
{
	assert(pos <= n->used);
	memmove(n->types + pos + 1, n->types + pos, n->used - pos);
	n->types[pos] = t;
	n->used++;
}

// Binary search in sorted array
static int find_in_array(dummy_node_t *n, uint16_t t, size_t *pos, size_t bound)
{
	if (*pos < 0) {
		*pos = 0;
		return 0;
	} else if (*pos > n->used) {
		*pos = n->used;
		return 0;
	} else if (bound == 0) {
		return 0;
	} else if (n->types[*pos] == t) {
		return 1;
	} else if (n->types[*pos] > t) {
		*pos -= bound / 2;
		return find_in_array(n, t, pos, bound / 2);
	} else {
		*pos += bound / 2;
		return find_in_array(n, t, pos, bound / 2);
	}
}

// return: 0 not present, 1 - present
static int dummy_node_add_type(dummy_node_t *n, uint16_t t)
{
	size_t pos = n->used / 2;
	int found = find_in_array(n, t, &pos, n->used);
	if (found) {
		// Found, nothing to do
		return 1;
	} else {
		// Not found, need to insert and possibly realloc
		if (n->used + 1 >= n->allocated) {
			n->allocated *= 2;
			n->types = xrealloc(n->types,
			                    n->allocated * sizeof(uint16_t));
		}
		insert_on_pos(n, pos, t);
		return 0;
	}
}

static size_t dname_memsize(const knot_dname_t *d)
{
	return (sizeof(knot_dname_t) + d->size + d->label_count)
	       * DNAME_MULT + DNAME_ADD;
}

// return: 0 - unique, 1 - duplicate
static int insert_dname_into_table(zone_estim_t *est, knot_dname_t *d,
                                   dummy_node_t **n)
{
	value_t *val = ahtable_tryget(est->table, d->name, d->size);
	if (val == NULL) {
		// Create new dummy node to use for this dname
		*n = xmalloc(sizeof(dummy_node_t));
		(*n)->allocated = 16;
		(*n)->used = 0;
		(*n)->types = xmalloc(16 * sizeof(uint16_t));
		memset((*n)->types, 0, 16 * sizeof(uint16_t))	;
		*ahtable_get(est->table, d->name, d->size) = *n;
		return 0;
	} else {
		// Return previously found dummy node
		*n = (dummy_node_t *)(*val);
		assert((*n)->allocated);
		return 1;
	}
}

static size_t rdata_memsize(zone_estim_t *est, const scanner_t *scanner)
{
	const rdata_descriptor_t *desc = get_rdata_descriptor(scanner->r_type);
	size_t size = 0;
	for (int i = 0; desc->block_types[i] != KNOT_RDATA_WF_END; ++i) {
		// DNAME - pointer in memory
		int item = desc->block_types[i];
		if (descriptor_item_is_dname(item)) {
			size += sizeof(knot_dname_t *);
			knot_dname_t *dname =
				knot_dname_new_from_wire(scanner->r_data +
			                                 scanner->r_data_blocks[i],
			                                 scanner->r_data_blocks[i + 1] -
			                                 scanner->r_data_blocks[i],
			                                 NULL);
			if (dname == NULL) {
				return KNOT_ERROR;
			}

			knot_dname_to_lower(dname);
			dummy_node_t *n;
			if (insert_dname_into_table(est, dname, &n) == 0) {
				// First time we see this dname, add size
				size += dname_memsize(dname);
			}
			knot_dname_free(&dname);
		} else if (descriptor_item_is_fixed(item)) {
		// Fixed length
			size += item;
		} else {
		// Variable length
			size += scanner->r_data_blocks[i + 1] -
			        scanner->r_data_blocks[i];
		}
	}

	return size * RDATA_MULT + RDATA_ADD;
}

static void rrset_memsize(zone_estim_t *est, const scanner_t *scanner)
{
	const rdata_descriptor_t *desc = get_rdata_descriptor(scanner->r_type);

	// Handle RRSet's owner
	knot_dname_t *owner = knot_dname_new_from_wire(scanner->r_owner,
	                         scanner->r_owner_length,
	                         NULL);
	dummy_node_t *n;
	if (insert_dname_into_table(est, owner, &n) == 0) {
		// First time we see this dname
		est->size += dname_memsize(owner);
		// Add node constants
		est->size += sizeof(knot_node_t) * NODE_MULT + NODE_ADD;
	}
	knot_dname_free(&owner);
	assert(n);

	// We will always add RDATA
	size_t rdlen = rdata_memsize(est, scanner);
	est->size += rdlen;

	est->record_count++;
	est->signed_count += scanner->r_type == KNOT_RRTYPE_RRSIG ? 1 : 0;

	/*
	 * RDATA size done, now add static part of RRSet to size, included
	 * owner. Do not add for RRs that would be merged.
	 * All possible duplicates will be added to total size.
	 */

	if (dummy_node_add_type(n, scanner->r_type) == 0) {
		// New RR type, add actual RRSet struct's size
		est->size += sizeof(knot_rrset_t) * RRSET_MULT + RRSET_ADD;
		// Add pointer in node's array
		est->size += sizeof(knot_rrset_t *);
	} else {
		// Merge would happen, so just RDATA index is added
		est->size += sizeof(uint32_t);
	}
}

void rrset_memsize_wrap(const scanner_t *scanner) {
	rrset_memsize(scanner->data, scanner);
}

