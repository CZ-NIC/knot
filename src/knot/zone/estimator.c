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

#include <assert.h>

#include "knot/zone/estimator.h"
#include "libknot/dname.h"
#include "common/lists.h"
#include "knot/zone/node.h"
#include "zscanner/zscanner.h"
#include "common/descriptor.h"

// Addition constants used for tweaking, mostly malloc overhead
enum estim_consts {
	MALLOC_OVERHEAD = sizeof(size_t),   // set according to malloc.c
	DNAME_ADD = MALLOC_OVERHEAD,        // just dname allocation
	NODE_ADD = MALLOC_OVERHEAD * 2,     // node itself, rrset array
	AHTABLE_ADD = MALLOC_OVERHEAD * 2,  // table, index
	MALLOC_MIN = MALLOC_OVERHEAD * 3    // minimum size of malloc'd chunk
};

typedef struct type_list_item {
	node_t n;
	uint16_t type;
} type_list_item_t;

typedef struct dummy_node {
	list_t node_list;
} dummy_node_t;

// return: 0 not present, 1 - present
static int find_in_list(list_t *node_list, uint16_t type)
{
	node_t *n = NULL;
	WALK_LIST(n, *node_list) {
		type_list_item_t *l_entr = (type_list_item_t *)n;
		assert(l_entr);
		if (l_entr->type == type) {
			return 1;
		}
	}

	type_list_item_t *new_entry = xmalloc(sizeof(type_list_item_t));
	new_entry->type = type;

	add_head(node_list, (node_t *)new_entry);
	return 0;
}

// return: 0 not present (added), 1 - present
static int dummy_node_add_type(dummy_node_t *n, uint16_t t)
{
	return find_in_list(&n->node_list, t);
}

static size_t dname_memsize(const knot_dname_t *d)
{

	size_t d_size = knot_dname_size(d);
	if (d_size < MALLOC_MIN) {
		d_size = MALLOC_MIN;
	}

	return d_size + DNAME_ADD;
}

// return: 0 - unique, 1 - duplicate
static int insert_dname_into_table(hattrie_t *table, knot_dname_t *d,
                                   dummy_node_t **n)
{
	int d_size = knot_dname_size(d);
	if (d_size < 0) {
		return KNOT_EINVAL;
	}

	value_t *val = hattrie_tryget(table, (char *)d, d_size);
	if (val == NULL) {
		// Create new dummy node to use for this dname
		*n = xmalloc(sizeof(dummy_node_t));
		init_list(&(*n)->node_list);
		*hattrie_get(table, (char *)d, d_size) = *n;
		return 0;
	} else {
		// Return previously found dummy node
		*n = (dummy_node_t *)(*val);
		return 1;
	}
}

static void rrset_memsize(zone_estim_t *est, const zs_scanner_t *scanner)
{
	// Handle RRSet's owner
	knot_dname_t *owner = knot_dname_copy(scanner->r_owner, NULL);
	if (owner == NULL) {
		return;
	}

	dummy_node_t *n = NULL;
	if (insert_dname_into_table(est->node_table, owner, &n) == 0) {
		// First time we see this name == new node
		est->node_size += sizeof(knot_node_t) + NODE_ADD;
		// Also, RRSet's owner will now contain full dname
		est->dname_size += dname_memsize(owner);
		// Trie's nodes handled at the end of computation
	}
	knot_dname_free(&owner, NULL);
	assert(n);

	// Add RDATA + size + TTL
	size_t rdlen = scanner->r_data_length + sizeof(uint16_t) +
	               sizeof(uint32_t);
	if (rdlen < MALLOC_MIN) {
		rdlen = MALLOC_MIN;
	}

	est->rdata_size += rdlen;
	est->record_count++;

	/*
	 * RDATA size done, now add static part of RRSet to size.
	 * Do not add for RRs that would be merged.
	 * All possible duplicates will be added to total size.
	 */
	if (dummy_node_add_type(n, scanner->r_type) == 0) {
		/*
		 * New RR type, add actual rr_data struct's size.
		 */
		est->node_size += sizeof(struct rr_data);
	}
}

void *estimator_malloc(void *ctx, size_t len)
{
	size_t *count = (size_t *)ctx;
	*count += len + MALLOC_OVERHEAD;
	return xmalloc(len);
}

void estimator_free(void *p)
{
	free(p);
}

static int get_ahtable_size(void *t, void *d)
{
	hhash_t *table = (hhash_t *)t;
	size_t *size = (size_t *)d;

	/* Size of the empty table. */
	*size += sizeof(hhash_t) + table->size * sizeof(hhelem_t) + AHTABLE_ADD;

	/* Allocated keys. */
	uint16_t key_len = 0;
	hhash_iter_t it;
	hhash_iter_begin(table, &it, false);
	while (!hhash_iter_finished(&it)) {
		(void)hhash_iter_key(&it, &key_len);
		*size += sizeof(value_t) + sizeof(uint16_t) + key_len;
		hhash_iter_next(&it);
	}

	return KNOT_EOK;
}

size_t estimator_trie_ahtable_memsize(hattrie_t *table)
{
	/*
	 * Iterate through trie's node, and get stats from each ahtable.
	 * Space taken up by the trie itself is measured using malloc wrapper.
	 * (Even for large zones, space taken by trie itself is very small)
	 */
	size_t size = 0;
	hattrie_apply_rev_ahtable(table, get_ahtable_size, &size);
	return size;
}

void estimator_rrset_memsize_wrap(const zs_scanner_t *scanner)
{
	rrset_memsize(scanner->data, scanner);
}

int estimator_free_trie_node(value_t *val, void *data)
{
	UNUSED(data);
	dummy_node_t *trie_n = (dummy_node_t *)(*val);
	WALK_LIST_FREE(trie_n->node_list);
	free(trie_n);

	return KNOT_EOK;
}
