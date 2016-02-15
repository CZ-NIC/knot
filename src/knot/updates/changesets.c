/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdlib.h>
#include <stdarg.h>

#include "knot/updates/changesets.h"
#include "libknot/libknot.h"
#include "contrib/macros.h"
#include "contrib/mempattern.h"

/* -------------------- Changeset iterator helpers -------------------------- */

/*! \brief Adds RRSet to given zone. */
static int add_rr_to_contents(zone_contents_t *z, knot_rrset_t **soa, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_SOA) {
		if (*soa == NULL) {
			*soa = knot_rrset_copy(rrset, NULL);
			if (*soa == NULL) {
				return KNOT_ENOMEM;
			}
		}
		/* Do not add SOAs into actual contents. */
		return KNOT_EOK;
	}

	zone_node_t *n = NULL;
	int ret = zone_contents_add_rr(z, rrset, &n);
	UNUSED(n);
	return ret;
}

/*! \brief Cleans up trie iterations. */
static void cleanup_iter_list(list_t *l)
{
	ptrnode_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		hattrie_iter_t *it = (hattrie_iter_t *)n->d;
		hattrie_iter_free(it);
		rem_node(&n->n);
		free(n);
	}
	init_list(l);
}

/*! \brief Inits changeset iterator with given HAT-tries. */
static int changeset_iter_init(changeset_iter_t *ch_it,
                               const changeset_t *ch, bool sorted, size_t tries, ...)
{
	memset(ch_it, 0, sizeof(*ch_it));
	init_list(&ch_it->iters);

	va_list args;
	va_start(args, tries);

	for (size_t i = 0; i < tries; ++i) {
		hattrie_t *t = va_arg(args, hattrie_t *);
		if (t) {
			if (sorted) {
				hattrie_build_index(t);
			}
			hattrie_iter_t *it = hattrie_iter_begin(t, sorted);
			if (it == NULL) {
				cleanup_iter_list(&ch_it->iters);
				return KNOT_ENOMEM;
			}
			if (ptrlist_add(&ch_it->iters, it, NULL) == NULL) {
				cleanup_iter_list(&ch_it->iters);
				return KNOT_ENOMEM;
			}
		}
	}

	va_end(args);

	return KNOT_EOK;
}

/*! \brief Gets next node from trie iterators. */
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

/*! \brief Gets next RRSet from trie iterators. */
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

static bool intersection_exists(const knot_rrset_t *node_rr, const knot_rrset_t *inc_rr)
{
	knot_rdataset_t intersection;
	knot_rdataset_init(&intersection);
	int ret = knot_rdataset_intersect(&node_rr->rrs, &inc_rr->rrs, &intersection, NULL);
	if (ret != KNOT_EOK) {
		return false;
	}
	const uint16_t rr_count = intersection.rr_count;
	knot_rdataset_clear(&intersection, NULL);

	return rr_count > 0;
}

static bool need_to_insert(zone_contents_t *counterpart, const knot_rrset_t *rr)
{
	zone_node_t *node = zone_contents_find_node_for_rr(counterpart, rr);
	if (node == NULL) {
		return true;
	}

	if (!node_rrtype_exists(node, rr->type)) {
		return true;
	}

	knot_rrset_t node_rr = node_rrset(node, rr->type);
	if (!intersection_exists(&node_rr, rr)) {
		return true;
	}

	// Subtract the data from node's RRSet.
	int ret = knot_rdataset_subtract(&node->rrs->rrs, &rr->rrs, NULL);
	if (ret != KNOT_EOK) {
		return true;
	}

	if (knot_rrset_empty(&node_rr)) {
		// Remove empty type.
		node_remove_rdataset(node, rr->type);
	}

	if (node->rrset_count == 0) {
		// Remove empty node.
		zone_tree_t *t = knot_rrset_is_nsec3rel(rr) ?
		                     counterpart->nsec3_nodes : counterpart->nodes;
		zone_contents_delete_empty_node(counterpart, t, node);
	}

	return false;
}

/* ------------------------------- API -------------------------------------- */

int changeset_init(changeset_t *ch, const knot_dname_t *apex)
{
	memset(ch, 0, sizeof(changeset_t));

	// Init local changes
	ch->add = zone_contents_new(apex);
	if (ch->add == NULL) {
		return KNOT_ENOMEM;
	}
	ch->remove = zone_contents_new(apex);
	if (ch->remove == NULL) {
		zone_contents_free(&ch->add);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

changeset_t *changeset_new(const knot_dname_t *apex)
{
	changeset_t *ret = malloc(sizeof(changeset_t));
	if (ret == NULL) {
		return NULL;
	}

	if (changeset_init(ret, apex) == KNOT_EOK) {
		return ret;
	} else {
		free(ret);
		return NULL;
	}
}

bool changeset_empty(const changeset_t *ch)
{
	if (ch == NULL || ch->add == NULL || ch->remove == NULL) {
		return true;
	}

	if (ch->soa_to) {
		return false;
	}

	changeset_iter_t itt;
	changeset_iter_all(&itt, ch, false);

	knot_rrset_t rr = changeset_iter_next(&itt);
	changeset_iter_clear(&itt);

	return knot_rrset_empty(&rr);
}

size_t changeset_size(const changeset_t *ch)
{
	if (ch == NULL) {
		return 0;
	}

	changeset_iter_t itt;
	changeset_iter_all(&itt, ch, false);

	size_t size = 0;
	knot_rrset_t rr = changeset_iter_next(&itt);
	while(!knot_rrset_empty(&rr)) {
		++size;
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	if (!knot_rrset_empty(ch->soa_from)) {
		size += 1;
	}
	if (!knot_rrset_empty(ch->soa_to)) {
		size += 1;
	}

	return size;
}

int changeset_add_rrset(changeset_t *ch, const knot_rrset_t *rrset, bool check_redundancy)
{
	/* Check if there's any removal and remove that, then add this
	 * addition anyway. Required to change TTLs. */
	if (check_redundancy) {
		need_to_insert(ch->remove, rrset);
	}

	return add_rr_to_contents(ch->add, &ch->soa_to, rrset);
}

int changeset_rem_rrset(changeset_t *ch, const knot_rrset_t *rrset, bool check_redundancy)
{
	if (!check_redundancy || need_to_insert(ch->add, rrset)) {
		return add_rr_to_contents(ch->remove, &ch->soa_from, rrset);
	} else {
		return KNOT_EOK;
	}
}

int changeset_merge(changeset_t *ch1, const changeset_t *ch2)
{
	changeset_iter_t itt;
	changeset_iter_add(&itt, ch2, false);

	knot_rrset_t rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		int ret = changeset_add_rrset(ch1, &rrset, true);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rrset = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	changeset_iter_rem(&itt, ch2, false);

	rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		int ret = changeset_rem_rrset(ch1, &rrset, true);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rrset = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	// Use soa_to and serial from the second changeset
	// soa_to from the first changeset is redundant, delete it
	knot_rrset_t *soa_copy = knot_rrset_copy(ch2->soa_to, NULL);
	if (soa_copy == NULL && ch2->soa_to) {
		return KNOT_ENOMEM;
	}
	knot_rrset_free(&ch1->soa_to, NULL);
	ch1->soa_to = soa_copy;

	return KNOT_EOK;
}

void changesets_clear(list_t *chgs)
{
	if (chgs) {
		changeset_t *chg, *nxt;
		WALK_LIST_DELSAFE(chg, nxt, *chgs) {
			changeset_clear(chg);
			rem_node(&chg->n);
		}
		init_list(chgs);
	}
}

void changesets_free(list_t *chgs)
{
	if (chgs) {
		changeset_t *chg, *nxt;
		WALK_LIST_DELSAFE(chg, nxt, *chgs) {
			rem_node(&chg->n);
			changeset_free(chg);
		}
		init_list(chgs);
	}
}

void changeset_clear(changeset_t *ch)
{
	if (ch == NULL) {
		return;
	}

	// Delete RRSets in lists, in case there are any left
	zone_contents_deep_free(&ch->add);
	zone_contents_deep_free(&ch->remove);

	knot_rrset_free(&ch->soa_from, NULL);
	knot_rrset_free(&ch->soa_to, NULL);

	// Delete binary data
	free(ch->data);
}

void changeset_free(changeset_t *ch)
{
	changeset_clear(ch);
	free(ch);
}

int changeset_iter_add(changeset_iter_t *itt, const changeset_t *ch, bool sorted)
{
	return changeset_iter_init(itt, ch, sorted, 2,
	                           ch->add->nodes, ch->add->nsec3_nodes);
}

int changeset_iter_rem(changeset_iter_t *itt, const changeset_t *ch, bool sorted)
{
	return changeset_iter_init(itt, ch, sorted, 2,
	                           ch->remove->nodes, ch->remove->nsec3_nodes);
}

int changeset_iter_all(changeset_iter_t *itt, const changeset_t *ch, bool sorted)
{
	return changeset_iter_init(itt, ch, sorted, 4,
	                           ch->add->nodes, ch->add->nsec3_nodes,
	                           ch->remove->nodes, ch->remove->nsec3_nodes);
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

void changeset_iter_clear(changeset_iter_t *it)
{
	if (it) {
		cleanup_iter_list(&it->iters);
		it->node = NULL;
		it->node_pos = 0;
	}
}
