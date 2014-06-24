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

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "knot/updates/changesets.h"
#include "libknot/common.h"
#include "common/descriptor.h"
#include "common/mempattern.h"
#include "common/mempool.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/soa.h"
#include "common/debug.h"

void changeset_init(changeset_t *ch, const knot_dname_t *apex, mm_ctx_t *mm)
{
	memset(ch, 0, sizeof(changeset_t));

	ch->mm = mm;

	// Init local changes
	ch->add = zone_contents_new(apex);
	ch->remove = zone_contents_new(apex);

	// Init change lists
	init_list(&ch->new_data);
	init_list(&ch->old_data);
}

changeset_t *changeset_new(mm_ctx_t *mm, const knot_dname_t *apex)
{
	changeset_t *ret = mm_alloc(mm, sizeof(changeset_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	changeset_init(ret, apex, mm);
	return ret;
}

int changeset_add_rrset(changeset_t *ch, const knot_rrset_t *rrset)
{
	zone_node_t *n = NULL;
	int ret = zone_contents_add_rr(ch->add, rrset, &n);
	UNUSED(n);
	return ret;
}

int changeset_rem_rrset(changeset_t *ch, const knot_rrset_t *rrset)
{
	zone_node_t *n = NULL;
	int ret = zone_contents_add_rr(ch->remove, rrset, &n);
	UNUSED(n);
	return ret;
}

bool changeset_empty(const changeset_t *ch)
{
	if (ch == NULL || ch->add == NULL || ch->remove == NULL) {
		return true;
	}

	changeset_iter_t *itt = changeset_iter_all(ch ,false);
	if (itt == NULL) {
		return false;
	}

	knot_rrset_t rr = changeset_iter_next(itt);
	changeset_iter_free(itt, NULL);

	return knot_rrset_empty(&rr);
}

size_t changeset_size(const changeset_t *ch)
{
	if (ch == NULL) {
		return 0;
	}

	changeset_iter_t *itt = changeset_iter_all(ch ,false);
	if (itt == NULL) {
		return 0;
	}

	size_t size = 0;
	knot_rrset_t rr = changeset_iter_next(itt);
	while(!knot_rrset_empty(&rr)) {
		++size;
		rr = changeset_iter_next(itt);
	}
	changeset_iter_free(itt, NULL);

	return size;
}

int changeset_merge(changeset_t *ch1, changeset_t *ch2)
{
#warning slow slow slow slow
	changeset_iter_t *itt = changeset_iter_add(ch2, false);
	if (itt == NULL) {
		return KNOT_ENOMEM;
	}

	knot_rrset_t rrset = changeset_iter_next(itt);
	while (!knot_rrset_empty(&rrset)) {
		int ret = changeset_add_rrset(ch1, &rrset);
		if (ret != KNOT_EOK) {
			changeset_iter_free(itt, NULL);
		}
		rrset = changeset_iter_next(itt);
	}
	changeset_iter_free(itt, NULL);

	itt = changeset_iter_add(ch2, false);
	if (itt == NULL) {
		return KNOT_ENOMEM;
	}

	rrset = changeset_iter_next(itt);
	while (!knot_rrset_empty(&rrset)) {
		int ret = changeset_rem_rrset(ch1, &rrset);
		if (ret != KNOT_EOK) {
			changeset_iter_free(itt, NULL);
		}
		rrset = changeset_iter_next(itt);
	}
	changeset_iter_free(itt, NULL);

	// Use soa_to and serial from the second changeset
	// soa_to from the first changeset is redundant, delete it
	knot_rrset_free(&ch1->soa_to, NULL);
	ch1->soa_to = ch2->soa_to;

	return KNOT_EOK;
}

void changeset_clear(changeset_t *ch, mm_ctx_t *rr_mm)
{
	if (ch == NULL) {
		return;
	}

	// Delete RRSets in lists, in case there are any left
	zone_contents_deep_free(&ch->add);
	zone_contents_deep_free(&ch->remove);

	knot_rrset_free(&ch->soa_from, rr_mm);
	knot_rrset_free(&ch->soa_to, rr_mm);

	// Delete binary data
	free(ch->data);
}

void changesets_free(list_t *chgs, mm_ctx_t *rr_mm)
{
	if (chgs) {
		changeset_t *chg, *nxt;
		WALK_LIST_DELSAFE(chg, nxt, *chgs) {
			changeset_clear(chg, rr_mm);
			rem_node(&chg->n);
		}
	}
}

static void cleanup_iter_list(list_t *l, mm_ctx_t *mm)
{
	ptrnode_t *n;
	WALK_LIST_FIRST(n, *l) {
		hattrie_iter_t *it = (hattrie_iter_t *)n->d;
		hattrie_iter_free(it);
		rem_node(&n->n);
		mm_free(mm, n);
	}
}

static changeset_iter_t *changeset_iter_begin(const changeset_t *ch, list_t *trie_l, bool sorted)
{
	changeset_iter_t *ret = mm_alloc(ch->mm, sizeof(changeset_iter_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	memset(ret, 0, sizeof(*ret));
	init_list(&ret->iters);

	ptrnode_t *n;
	WALK_LIST(n, *trie_l) {
		hattrie_t *t = (hattrie_t *)n->d;
		if (t) {
			if (sorted) {
				hattrie_build_index(t);
			}
			hattrie_iter_t *it = hattrie_iter_begin(t, sorted);
			if (it == NULL) {
				cleanup_iter_list(&ret->iters, ch->mm);
				mm_free(ch->mm, ret);
				return NULL;
			}
			if (ptrlist_add(&ret->iters, it, NULL) == NULL) {
				cleanup_iter_list(&ret->iters, ch->mm);
				mm_free(ch->mm, ret);
				return NULL;
			}
		}
	}

	return ret;
}

changeset_iter_t *changeset_iter_add(const changeset_t *ch, bool sorted)
{
	list_t tries;
	init_list(&tries);
	ptrlist_add(&tries, ch->add->nodes, NULL);
	ptrlist_add(&tries, ch->add->nsec3_nodes, NULL);
	changeset_iter_t *ret = changeset_iter_begin(ch, &tries, sorted);
	ptrlist_free(&tries, NULL);
	return ret;
}

changeset_iter_t *changeset_iter_rem(const changeset_t *ch, bool sorted)
{
	list_t tries;
	init_list(&tries);
	ptrlist_add(&tries, ch->remove->nodes, NULL);
	ptrlist_add(&tries, ch->remove->nsec3_nodes, NULL);
	changeset_iter_t *ret = changeset_iter_begin(ch, &tries, sorted);
	ptrlist_free(&tries, NULL);
	return ret;
}

changeset_iter_t *changeset_iter_all(const changeset_t *ch, bool sorted)
{
	list_t tries;
	init_list(&tries);
	ptrlist_add(&tries, ch->add->nodes, NULL);
	ptrlist_add(&tries, ch->add->nsec3_nodes, NULL);
	ptrlist_add(&tries, ch->remove->nodes, NULL);
	ptrlist_add(&tries, ch->remove->nsec3_nodes, NULL);
	changeset_iter_t *ret = changeset_iter_begin(ch, &tries, sorted);
	ptrlist_free(&tries, NULL);
	return ret;
}

static void iter_next_node(changeset_iter_t *ch_it, hattrie_iter_t *t_it)
{
	assert(!hattrie_iter_finished(t_it));
	// Get next node, but not for the very first call.
	if (ch_it->node) {
		hattrie_iter_next(t_it);
	}
	if (hattrie_iter_finished(t_it)) {
		ch_it->node = NULL;
		return;
	}

	ch_it->node = (zone_node_t *)*hattrie_iter_val(t_it);
	assert(ch_it->node);
	while (ch_it->node && ch_it->node->rrset_count == 0) {
		// Skip empty non-terminals.
		hattrie_iter_next(t_it);
		if (hattrie_iter_finished(t_it)) {
			ch_it->node = NULL;
		} else {
			ch_it->node = (zone_node_t *)*hattrie_iter_val(t_it);
			assert(ch_it->node);
		}
	}

	ch_it->node_pos = 0;
}

static knot_rrset_t get_next_rr(changeset_iter_t *ch_it, hattrie_iter_t *t_it) // pun intented
{
	if (ch_it->node == NULL || ch_it->node_pos == ch_it->node->rrset_count) {
		iter_next_node(ch_it, t_it);
		if (ch_it->node == NULL) {
			assert(hattrie_iter_finished(t_it));
			knot_rrset_t rr;
			knot_rrset_init_empty(&rr);
			return rr;
		}
	}
	
	return node_rrset_at(ch_it->node, ch_it->node_pos++);
}

knot_rrset_t changeset_iter_next(changeset_iter_t *it)
{
	assert(it);
	ptrnode_t *n = NULL;
	knot_rrset_t rr;
	knot_rrset_init_empty(&rr);
	WALK_LIST(n, it->iters) {
		hattrie_iter_t *t_it = (hattrie_iter_t *)n->d;
		if (hattrie_iter_finished(t_it)) {
			continue;
		}

		rr = get_next_rr(it, t_it);
		if (!knot_rrset_empty(&rr)) {
			// Got valid RRSet.
			return rr;
		}
	}

	return rr;
}

void changeset_iter_free(changeset_iter_t *it, mm_ctx_t *mm)
{
	if (it) {
		cleanup_iter_list(&it->iters, mm);
		mm_free(mm, it);
	}
}

