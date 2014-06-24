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
	return ret;
}

int changeset_rem_rrset(changeset_t *ch, const knot_rrset_t *rrset)
{
	zone_node_t *n = NULL;
	int ret = zone_contents_add_rr(ch->remove, rrset, &n);
	return ret;
}

bool changeset_empty(const changeset_t *ch)
{
	if (ch == NULL) {
		return true;
	}

#warning will not work for apex changes
	return ch->soa_to == NULL && changeset_size(ch) <= 2;
}

size_t changeset_size(const changeset_t *ch)
{
	if (ch == NULL) {
		return 0;
	}

	return hattrie_weight(ch->add->nodes) +
	       hattrie_weight(ch->add->nsec3_nodes) +
	       hattrie_weight(ch->remove->nodes) +
	       hattrie_weight(ch->remove->nsec3_nodes);
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
		zone_node_t *n;
		int ret = zone_contents_add_rr(ch1->add, &rrset, &n);
		UNUSED(n);
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
		zone_node_t *n;
		int ret = zone_contents_add_rr(ch1->remove, &rrset, &n);
		UNUSED(n);
		if (ret != KNOT_EOK) {
			changeset_iter_free(itt, NULL);
		}
		rrset = changeset_iter_next(itt);
	}

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
		}
	}
}

#define NODE_DONE -1

static changeset_iter_t *changeset_iter_begin(const changeset_t *ch, hattrie_t *tr,
                                              hattrie_t *nsec3_tr, bool sorted)
{
#warning emptiness check
	changeset_iter_t *ret = mm_alloc(ch->mm, sizeof(changeset_iter_t));
	if (ret == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(ret, 0, sizeof(*ret));
	ret->node_pos = NODE_DONE;

	ret->normal_it = hattrie_iter_begin(tr, sorted);
	if (ret->normal_it == NULL) {
		mm_free(ch->mm, ret);
		return NULL;
	}
	
	if (nsec3_tr) {
		ret->nsec3_it = hattrie_iter_begin(nsec3_tr, sorted);
		if (ret->nsec3_it == NULL) {
			hattrie_iter_free(ret->normal_it);
			mm_free(ch->mm, ret);
			return NULL;
		}
	} else {
		ret->nsec3_it = NULL;
	}

	return ret;
}

changeset_iter_t *changeset_iter_add(const changeset_t *ch, bool sorted)
{
	return changeset_iter_begin(ch, ch->add->nodes, ch->add->nsec3_nodes, sorted);
}

changeset_iter_t *changeset_iter_rem(const changeset_t *ch, bool sorted)
{
	return changeset_iter_begin(ch, ch->remove->nodes, ch->remove->nsec3_nodes, sorted);
}

static void get_next_rr(knot_rrset_t *rr, changeset_iter_t *ch_it, hattrie_iter_t **t_it) // pun intented
{
#warning get rid of recursion
	if (ch_it->node_pos == NODE_DONE) {
		// Get next node.
		if (ch_it->node) {
			// Do not get next for very first node.
			hattrie_iter_next(*t_it);
		}
		if (hattrie_iter_finished(*t_it)) {
			hattrie_iter_free(*t_it);
			*t_it = NULL;
			ch_it->node = NULL;
			ch_it->node_pos = NODE_DONE;
			return;
		}
		ch_it->node = (zone_node_t *)*hattrie_iter_val(*t_it);
		if (ch_it->node->rrset_count == 0) {
			get_next_rr(rr, ch_it, t_it);
		}
		
		if (ch_it->node == NULL) {
			return;
		}
	}
	
	assert(ch_it->node);

	if (ch_it->node_pos < ch_it->node->rrset_count) {
		*rr = node_rrset_at(ch_it->node, ch_it->node_pos);
		++ch_it->node_pos;
	} else {
		// Node is done, get next.
		ch_it->node_pos = NODE_DONE;
		get_next_rr(rr, ch_it, t_it);
	}
	
	assert(!knot_rrset_empty(rr));
}

knot_rrset_t changeset_iter_next(changeset_iter_t *it)
{
	knot_rrset_t ret;
	knot_rrset_init_empty(&ret);
	if (it->normal_it) {
		get_next_rr(&ret, it, &it->normal_it);
	} else if (it->nsec3_it) {
		get_next_rr(&ret, it, &it->nsec3_it);
	}

	return ret;
}

void changeset_iter_free(changeset_iter_t *it, mm_ctx_t *mm)
{
	if (it) {
		hattrie_iter_free(it->normal_it);
		hattrie_iter_free(it->nsec3_it);
		mm_free(mm, it);
	}
}

