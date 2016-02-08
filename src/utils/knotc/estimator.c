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

#include "utils/knotc/estimator.h"
#include "knot/zone/node.h"
#include "libknot/errcode.h"
#include "libknot/dname.h"
#include "libknot/descriptor.h"
#include "contrib/macros.h"
#include "contrib/string.h"
#include "contrib/ucw/lists.h"

// Addition constants used for tweaking, mostly malloc overhead
enum estim_consts {
	MALLOC_OVERHEAD = sizeof(size_t),   // set according to malloc.c
	MALLOC_MIN = MALLOC_OVERHEAD * 3    // minimum size of malloc'd chunk
};

typedef struct type_list_item {
	node_t n;
	uint16_t type;
} type_list_item_t;

static size_t add_overhead(size_t size)
{
	return MALLOC_OVERHEAD + size + size % MALLOC_MIN;
}

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

	type_list_item_t *new_entry = malloc(sizeof(type_list_item_t));
	assert(new_entry != NULL);
	new_entry->type = type;

	add_head(node_list, (node_t *)new_entry);
	return 0;
}

// return: 0 not present (added), 1 - present
static int dummy_node_add_type(list_t *l, uint16_t t)
{
	return find_in_list(l, t);
}

// return: 0 - unique, 1 - duplicate
static int insert_dname_into_table(hattrie_t *table, const knot_dname_t *d,
                                   list_t **dummy_node)
{
	int d_size = knot_dname_size(d);
	if (d_size < 0) {
		return KNOT_EINVAL;
	}

	value_t *val = hattrie_tryget(table, (char *)d, d_size);
	if (val == NULL) {
		// Create new dummy node to use for this dname
		*dummy_node = malloc(sizeof(list_t));
		assert(dummy_node != NULL);
		init_list(*dummy_node);
		*hattrie_get(table, (char *)d, d_size) = *dummy_node;
		return 0;
	} else {
		// Return previously found dummy node
		*dummy_node = (list_t *)(*val);
		return 1;
	}
}

static void rrset_memsize(zone_estim_t *est, const zs_scanner_t *scanner)
{
	// Handle RRSet's owner
	list_t *dummy_node = NULL;
	if (insert_dname_into_table(est->node_table, scanner->r_owner, &dummy_node) == 0) {
		// First time we see this name == new node
		est->node_size += add_overhead(sizeof(zone_node_t));
		// Also, node has an owner.
		est->dname_size += add_overhead(knot_dname_size(scanner->r_owner));
		// Trie's nodes handled at the end of computation
	}
	assert(dummy_node);

	// Add RDATA + size + TTL
	size_t rdlen = knot_rdata_array_size(scanner->r_data_length);
	est->rdata_size += add_overhead(rdlen);
	est->record_count++;

	/*
	 * RDATA size done, now add static part of RRSet to size.
	 * Do not add for RRs that would be merged.
	 * All possible duplicates will be added to total size.
	 */
	if (dummy_node_add_type(dummy_node, scanner->r_type) == 0) {
		/*
		 * New RR type, add actual rr_data struct's size. No way to
		 * guess the actual overhead taken up by the array, so we add
		 * it each time.
		 */
		est->node_size += add_overhead(sizeof(struct rr_data));
	}
}

void *estimator_malloc(void *ctx, size_t len)
{
	size_t *count = (size_t *)ctx;
	*count += add_overhead(len);
	return malloc(len);
}

void estimator_free(void *p)
{
	free(p);
}

static int get_htable_size(void *t, void *d)
{
	hhash_t *table = (hhash_t *)t;
	size_t *size = (size_t *)d;

	/* Size of the empty table. */
	*size += add_overhead(sizeof(hhash_t) + table->size * sizeof(hhelem_t));

	/* Allocated keys. */
	uint16_t key_len = 0;
	hhash_iter_t it;
	hhash_iter_begin(table, &it, false);
	while (!hhash_iter_finished(&it)) {
		(void)hhash_iter_key(&it, &key_len);
		*size += add_overhead(sizeof(value_t) + sizeof(uint16_t) + key_len);
		hhash_iter_next(&it);
	}

	return KNOT_EOK;
}

size_t estimator_trie_htable_memsize(hattrie_t *table)
{
	/*
	 * Iterate through trie's node, and get stats from each htable.
	 * Space taken up by the trie itself is measured using malloc wrapper.
	 * (Even for large zones, space taken by trie itself is very small)
	 */
	size_t size = 0;
	hattrie_apply_rev_ahtable(table, get_htable_size, &size);
	return size;
}

void estimator_rrset_memsize_wrap(zs_scanner_t *scanner)
{
	rrset_memsize(scanner->process.data, scanner);
}

int estimator_free_trie_node(value_t *val, void *data)
{
	UNUSED(data);
	list_t *trie_n = (list_t *)(*val);
	WALK_LIST_FREE(*trie_n);
	free(trie_n);

	return KNOT_EOK;
}
