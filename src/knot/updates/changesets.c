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

static int handle_soa(knot_rrset_t **soa, const knot_rrset_t *rrset)
{
	assert(soa);
	assert(rrset);

	if (*soa != NULL) {
		knot_rrset_free(soa, NULL);
	}

	*soa = knot_rrset_copy(rrset, NULL);
	if (*soa == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*! \brief Adds RRSet to given zone. */
static int add_rr_to_contents(zone_contents_t *z, const knot_rrset_t *rrset)
{
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
static knot_rrset_t get_next_rr(changeset_iter_t *ch_it, hattrie_iter_t *t_it)
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

static void check_redundancy(zone_contents_t *counterpart, const knot_rrset_t *rr)
{
	zone_node_t *node = zone_contents_find_node_for_rr(counterpart, rr);
	if (node == NULL) {
		return;
	}

	if (!node_rrtype_exists(node, rr->type)) {
		return;
	}

	// Subtract the data from node's RRSet.
	knot_rdataset_t *rrs = node_rdataset(node, rr->type);
	int ret = knot_rdataset_subtract(rrs, &rr->rrs, NULL);
	if (ret != KNOT_EOK) {
		return;
	}

	if (knot_rdataset_size(rrs) == 0) {
		// Remove empty type.
		node_remove_rdataset(node, rr->type);

		if (node->rrset_count == 0) {
			// Remove empty node.
			zone_tree_t *t = knot_rrset_is_nsec3rel(rr) ?
								 counterpart->nsec3_nodes : counterpart->nodes;
			zone_tree_delete_empty_node(t, node);
		}
	}

	return;
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

int changeset_add_addition(changeset_t *ch, const knot_rrset_t *rrset, unsigned flags)
{
	if (!ch || !rrset) {
		return KNOT_EINVAL;
	}

	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		return handle_soa(&ch->soa_to, rrset);
	}

	/* Check if there's any removal and remove that, then add this
	 * addition anyway. Required to change TTLs. */
	if (flags & CHANGESET_CHECK) {
		/* If we delete the rrset, we need to hold a copy to add it later */
		rrset = knot_rrset_copy(rrset, NULL);
		if (rrset == NULL) {
			return KNOT_ENOMEM;
		}

		check_redundancy(ch->remove, rrset);
	}

	int ret = add_rr_to_contents(ch->add, rrset);

	if (flags & CHANGESET_CHECK) {
		knot_rrset_free((knot_rrset_t **)&rrset, NULL);
	}

	return ret;
}

int changeset_add_removal(changeset_t *ch, const knot_rrset_t *rrset, unsigned flags)
{
	if (!ch || !rrset) {
		return KNOT_EINVAL;
	}

	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		return handle_soa(&ch->soa_from, rrset);
	}

	/* Check if there's any addition and remove that, then add this
	 * removal anyway. */
	if (flags & CHANGESET_CHECK) {
		/* If we delete the rrset, we need to hold a copy to add it later */
		rrset = knot_rrset_copy(rrset, NULL);
		if (rrset == NULL) {
			return KNOT_ENOMEM;
		}

		check_redundancy(ch->add, rrset);
	}

	int ret = add_rr_to_contents(ch->remove, rrset);

	if (flags & CHANGESET_CHECK) {
		knot_rrset_free((knot_rrset_t **)&rrset, NULL);
	}

	return ret;
}

int changeset_remove_addition(changeset_t *ch, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		if (ch->soa_to != NULL) {
			knot_rrset_free(&ch->soa_to, NULL);
			ch->soa_to = NULL;
		}
		return KNOT_EOK;
	}

	zone_node_t *n = NULL;
	return zone_contents_remove_rr(ch->add, rrset, &n);
}

int changeset_remove_removal(changeset_t *ch, const knot_rrset_t *rrset)
{
	if (rrset->type == KNOT_RRTYPE_SOA) {
		/* Do not add SOAs into actual contents. */
		if (ch->soa_from != NULL) {
			knot_rrset_free(&ch->soa_from, NULL);
			ch->soa_from = NULL;
		}
		return KNOT_EOK;
	}

	zone_node_t *n = NULL;
	return zone_contents_remove_rr(ch->remove, rrset, &n);
}

int changeset_merge(changeset_t *ch1, const changeset_t *ch2)
{
	changeset_iter_t itt;
	changeset_iter_add(&itt, ch2, false);

	knot_rrset_t rrset = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rrset)) {
		int ret = changeset_add_addition(ch1, &rrset, CHANGESET_CHECK);
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
		int ret = changeset_add_removal(ch1, &rrset, CHANGESET_CHECK);
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
