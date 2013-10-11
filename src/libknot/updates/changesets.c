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
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "libknot/updates/changesets.h"
#include "libknot/common.h"
#include "common/descriptor.h"
#include "common/mempattern.h"
#include "common/mempool.h"
#include "libknot/rrset.h"
#include "libknot/util/debug.h"
#include "libknot/rdata.h"

static int knot_changeset_rrsets_match(const knot_rrset_t *rrset1,
                                         const knot_rrset_t *rrset2)
{
	return knot_rrset_equal(rrset1, rrset2, KNOT_RRSET_COMPARE_HEADER)
	       && (knot_rrset_type(rrset1) != KNOT_RRTYPE_RRSIG
	           || knot_rdata_rrsig_type_covered(rrset1, 0)
	              == knot_rdata_rrsig_type_covered(rrset2, 0));
}

int knot_changesets_init(knot_changesets_t **changesets, uint32_t flags)
{
	// Create new changesets structure
	*changesets = xmalloc(sizeof(knot_changesets_t));
	memset(*changesets, 0, sizeof(knot_changesets_t));
	(*changesets)->flags = flags;

	// Initialize memory context for changesets (xmalloc'd)
	struct mempool *chs_pool = mp_new(sizeof(knot_changeset_t));
	(*changesets)->mmc_chs.ctx = chs_pool;
	(*changesets)->mmc_chs.alloc = (mm_alloc_t)mp_alloc;
	(*changesets)->mmc_chs.free = NULL;

	// Initialize memory context for RRs in changesets (xmalloc'd)
	struct mempool *rr_pool = mp_new(sizeof(knot_rr_ln_t));
	(*changesets)->mmc_rr.ctx = rr_pool;
	(*changesets)->mmc_rr.alloc = (mm_alloc_t)mp_alloc;
	(*changesets)->mmc_rr.free = NULL;

	// Init list with changesets
	init_list(&(*changesets)->sets);

	// Init changes structure
	(*changesets)->changes = xmalloc(sizeof(knot_changes_t));
	// Init changes' allocator (storing RRs)
	(*changesets)->changes->mem_ctx = (*changesets)->mmc_rr;
	// Init changes' lists
	init_list(&(*changesets)->changes->old_nodes);
	init_list(&(*changesets)->changes->old_nsec3);
	init_list(&(*changesets)->changes->new_rrsets);
	init_list(&(*changesets)->changes->old_rrsets);

	return KNOT_EOK;
}

knot_changesets_t *knot_changesets_create(uint32_t flags)
{
	knot_changesets_t *ch = NULL;
	int ret = knot_changesets_init(&ch, flags);
	if (ret != KNOT_EOK) {
		return NULL;
	} else {
		return ch;
	}
}

knot_changeset_t *knot_changesets_create_changeset(knot_changesets_t *ch)
{
	if (ch == NULL) {
		return NULL;
	}

	// Create set changesets' memory allocator
	knot_changeset_t *set = ch->mmc_chs.alloc(ch->mmc_chs.ctx,
	                                          sizeof(knot_changeset_t));
	if (set == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(set, 0, sizeof(knot_changeset_t));
	set->flags = ch->flags;

	// Init set's memory context (Allocator from changests structure is used)
	set->mem_ctx = ch->mmc_rr;

	// Init local lists
	init_list(&set->add);
	init_list(&set->remove);

	// Insert into list of sets
	add_tail(&ch->sets, (node_t *)set);

	++ch->count;

	return set;
}

knot_changeset_t *knot_changesets_get_last(const knot_changesets_t *chs)
{
	if (chs == NULL || EMPTY_LIST(chs->sets)) {
		return NULL;
	}

	return (knot_changeset_t *)(TAIL(chs->sets));
}

const knot_rrset_t *knot_changeset_last_rr(const knot_changeset_t *ch,
                                           knot_changeset_part_t part)
{
	if (ch == NULL) {
		return NULL;
	}

	if (part == KNOT_CHANGESET_ADD) {
		knot_rr_ln_t *n = TAIL(ch->add);
		return n ? n->rr : NULL;
	} else if (part == KNOT_CHANGESET_REMOVE) {
		knot_rr_ln_t *n = TAIL(ch->remove);
		return n ? n->rr : NULL;
	}

	return NULL;
}

void knot_changeset_remove_last_rr(knot_changeset_t *ch,
                                   knot_changeset_part_t part)
{
	if (ch == NULL) {
		return;
	}

	if (part == KNOT_CHANGESET_ADD) {
		knot_rr_ln_t *n = TAIL(ch->add);
		rem_node((node_t *)n);
	} else if (part == KNOT_CHANGESET_REMOVE) {
		knot_rr_ln_t *n = TAIL(ch->remove);
		rem_node((node_t *)n);
	}
}

int knot_changeset_add_rrset(knot_changeset_t *chgs, knot_rrset_t *rrset,
                             knot_changeset_part_t part)
{
	// Create wrapper node for list
	knot_rr_ln_t *rr_node =
		chgs->mem_ctx.alloc(chgs->mem_ctx.ctx, sizeof(knot_rr_ln_t));
	if (rr_node == NULL) {
		// This will not happen with mp_alloc, but allocator can change
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	rr_node->rr = rrset;

	if (part == KNOT_CHANGESET_ADD) {
		add_tail(&chgs->add, (node_t *)rr_node);
	} else {
		add_tail(&chgs->remove, (node_t *)rr_node);
	}

	return KNOT_EOK;
}

int knot_changeset_add_rr(knot_changeset_t *chgs, knot_rrset_t *rr,
                          knot_changeset_part_t part)
{
	// Just check the last RRSet. If the RR belongs to it, merge it,
	// otherwise just add the RR to the end of the list
	list_t *l = part == KNOT_CHANGESET_ADD ? &(chgs->add) : &(chgs->remove);
	knot_rrset_t *tail_rr =
		EMPTY_LIST(*l) ? NULL : ((knot_rr_ln_t *)(TAIL(*l)))->rr;

	if (tail_rr && knot_changeset_rrsets_match(tail_rr, rr)) {
		// Create changesets exactly as they came, with possibly
		// duplicate records
		if (knot_rrset_merge(tail_rr, rr) != KNOT_EOK) {
			return KNOT_ERROR;
		}

		knot_rrset_deep_free(&rr, 1);
		return KNOT_EOK;
	} else {
		return knot_changeset_add_rrset(chgs, rr, part);
	}
}

int knot_changes_add_rrset(knot_changes_t *ch, knot_rrset_t *rrset,
                           knot_changes_part_t part)
{
	if (ch == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	knot_rr_ln_t *rr_node =
		ch->mem_ctx.alloc(ch->mem_ctx.ctx, sizeof(knot_rr_ln_t));
	if (rr_node == NULL) {
		// This will not happen with mp_alloc, but allocator can change
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	rr_node->rr = rrset;

	if (part == KNOT_CHANGES_NEW) {
		add_tail(&ch->new_rrsets, (node_t *)rr_node);
	} else {
		assert(part == KNOT_CHANGES_OLD);
		add_tail(&ch->old_rrsets, (node_t *)rr_node);
	}

	return KNOT_EOK;
}

int knot_changes_add_node(knot_changes_t *ch, knot_node_t *kn_node,
                          knot_changes_part_t part)
{
	if (ch == NULL || kn_node == NULL) {
		return KNOT_EINVAL;
	}

	// Using the same allocator for node and rr's, sizes are equal.
	knot_node_ln_t *list_node =
		ch->mem_ctx.alloc(ch->mem_ctx.ctx, sizeof(knot_node_ln_t));
	if (list_node == NULL) {
		// This will not happen with mp_alloc, but allocator can change
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	list_node->node = kn_node;

	if (part == KNOT_CHANGES_NORMAL_NODE) {
		add_tail(&ch->old_nodes, (node_t *)list_node);
	} else {
		assert(part == KNOT_CHANGES_NSEC3_NODE);
		add_tail(&ch->old_nsec3, (node_t *)list_node);
	}

	return KNOT_EOK;
}

static void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                                     uint32_t *chg_serial, knot_rrset_t *soa)
{
	*chg_soa = soa;
	*chg_serial = knot_rdata_soa_serial(soa);
}

void knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
                            knot_changeset_part_t part)
{
	switch (part) {
	case KNOT_CHANGESET_ADD:
		knot_changeset_store_soa(&changeset->soa_to,
		                          &changeset->serial_to, soa);
		break;
	case KNOT_CHANGESET_REMOVE:
		knot_changeset_store_soa(&changeset->soa_from,
		                          &changeset->serial_from, soa);
		break;
	default:
		assert(0);
	}
}

bool knot_changeset_is_empty(const knot_changeset_t *changeset)
{
	if (changeset == NULL) {
		return true;
	}

	return (changeset->soa_to == NULL &&
	        EMPTY_LIST(changeset->add) && EMPTY_LIST(changeset->remove));
}

size_t knot_changeset_size(const knot_changeset_t *changeset)
{
	if (!changeset || knot_changeset_is_empty(changeset)) {
		return 0;
	}

	return list_size(&changeset->add) + list_size(&changeset->remove);
}

int knot_changeset_apply(knot_changeset_t *changeset,
                         knot_changeset_part_t part,
                         int (*func)(knot_rrset_t *, void *), void *data)
{
	if (changeset == NULL || func == NULL) {
		return KNOT_EINVAL;
	}

	knot_rr_ln_t *rr_node = NULL;
	if (part == KNOT_CHANGESET_ADD) {
		WALK_LIST(rr_node, changeset->add) {
			int res = func(rr_node->rr, data);
			if (res != KNOT_EOK) {
				return res;
			}
		}
	} else if (part == KNOT_CHANGESET_REMOVE) {
		WALK_LIST(rr_node, changeset->remove) {
			int res = func(rr_node->rr, data);
			if (res != KNOT_EOK) {
				return res;
			}
		}
	}

	return KNOT_EOK;
}

int knot_changeset_merge(knot_changeset_t *ch1, knot_changeset_t *ch2)
{
	if (ch1 == NULL || ch2 == NULL || ch1->data != NULL ||
	    ch2->data != NULL) {
		return KNOT_EINVAL;
	}

	// Connect lists in changesets together
	add_tail_list(&ch1->add, &ch2->add);
	add_tail_list(&ch1->remove, &ch2->remove);

	// Use soa_to and serial from the second changeset
	// soa_to from the first changeset is redundant, delete it
	knot_rrset_deep_free(&ch1->soa_to, 1);
	ch1->soa_to = ch2->soa_to;
	ch1->serial_to = ch2->serial_to;

	return KNOT_EOK;
}

static void knot_free_changeset(knot_changeset_t *changeset)
{
	if (changeset == NULL) {
		return;
	}

	// Delete RRSets in lists, in case there are any left
	knot_rr_ln_t *rr_node;
	WALK_LIST(rr_node, changeset->add) {
		knot_rrset_deep_free(&rr_node->rr, 1);
	}
	WALK_LIST(rr_node, changeset->remove) {
		knot_rrset_deep_free(&rr_node->rr, 1);
	}

	knot_rrset_deep_free(&changeset->soa_from, 1);
	knot_rrset_deep_free(&changeset->soa_to, 1);

	// Delete binary data
	free(changeset->data);
}

void knot_changesets_free(knot_changesets_t **changesets)
{
	if (changesets == NULL || *changesets == NULL) {
		return;
	}

	if (!EMPTY_LIST((*changesets)->sets)) {
		knot_changeset_t *chg = NULL;
		WALK_LIST(chg, (*changesets)->sets) {
			knot_free_changeset(chg);
		}
	}

	// Free pool with sets themselves
	mp_delete((*changesets)->mmc_chs.ctx);
	// Free pool with RRs in sets / changes
	mp_delete((*changesets)->mmc_rr.ctx);

	knot_rrset_deep_free(&(*changesets)->first_soa, 1);

	free((*changesets)->changes);
	free(*changesets);
	*changesets = NULL;
}
