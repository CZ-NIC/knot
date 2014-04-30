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
#include "libknot/rdata/soa.h"
#include "common/debug.h"

static int knot_changesets_init(knot_changesets_t *changesets)
{
	if (changesets == NULL) {
		return KNOT_EINVAL;
	}

	// Create new changesets structure
	memset(changesets, 0, sizeof(knot_changesets_t));

	// Initialize memory context for changesets (xmalloc'd)
	struct mempool *chs_pool = mp_new(sizeof(knot_changeset_t));
	changesets->mmc_chs.ctx = chs_pool;
	changesets->mmc_chs.alloc = (mm_alloc_t)mp_alloc;
	changesets->mmc_chs.free = NULL;

	// Initialize memory context for RRs in changesets (xmalloc'd)
	struct mempool *rr_pool = mp_new(sizeof(knot_rr_ln_t));
	changesets->mmc_rr.ctx = rr_pool;
	changesets->mmc_rr.alloc = (mm_alloc_t)mp_alloc;
	changesets->mmc_rr.free = NULL;

	// Init list with changesets
	init_list(&changesets->sets);

	return KNOT_EOK;
}

knot_changesets_t *knot_changesets_create(unsigned count)
{
	knot_changesets_t *ch = malloc(sizeof(knot_changesets_t));
	int ret = knot_changesets_init(ch);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	for (unsigned i = 0; i < count; ++i) {
		knot_changeset_t *change = knot_changesets_create_changeset(ch);
		if (change == NULL) {
			knot_changesets_free(&ch);
			return NULL;
		}
	}

	return ch;
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
		return NULL;
	}
	memset(set, 0, sizeof(knot_changeset_t));

	// Init set's memory context (Allocator from changests structure is used)
	set->mem_ctx = ch->mmc_rr;

	// Init local lists
	init_list(&set->add);
	init_list(&set->remove);

	// Init change lists
	init_list(&set->new_data);
	init_list(&set->old_data);

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

bool knot_changesets_empty(const knot_changesets_t *chs)
{
	knot_changeset_t *last = knot_changesets_get_last(chs);
	if (last == NULL) {
		return true;
	}

	return knot_changeset_is_empty(last);
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

static void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                                     uint32_t *chg_serial, knot_rrset_t *soa)
{
	*chg_soa = soa;
	*chg_serial = knot_soa_serial(&soa->rrs);
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
	if (ch1 == NULL || ch2 == NULL || ch1->data != NULL || ch2->data != NULL) {
		return KNOT_EINVAL;
	}

	// Connect lists in changesets together
	add_tail_list(&ch1->add, &ch2->add);
	add_tail_list(&ch1->remove, &ch2->remove);

	// Use soa_to and serial from the second changeset
	// soa_to from the first changeset is redundant, delete it
	knot_rrset_free(&ch1->soa_to, NULL);
	knot_rrset_free(&ch2->soa_from, NULL);
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
		knot_rrset_free(&rr_node->rr, NULL);
	}
	WALK_LIST(rr_node, changeset->remove) {
		knot_rrset_free(&rr_node->rr, NULL);
	}

	knot_rrset_free(&changeset->soa_from, NULL);
	knot_rrset_free(&changeset->soa_to, NULL);

	// Delete binary data
	free(changeset->data);
}

static void knot_changesets_deinit(knot_changesets_t *changesets)
{
	if (!EMPTY_LIST(changesets->sets)) {
		knot_changeset_t *chg = NULL;
		WALK_LIST(chg, changesets->sets) {
			knot_free_changeset(chg);
		}
	}

	// Free pool with sets themselves
	mp_delete(changesets->mmc_chs.ctx);
	// Free pool with RRs in sets / changes
	mp_delete(changesets->mmc_rr.ctx);

	knot_rrset_free(&changesets->first_soa, NULL);
}

void knot_changesets_free(knot_changesets_t **changesets)
{
	if (changesets == NULL || *changesets == NULL) {
		return;
	}

	knot_changesets_deinit(*changesets);

	free(*changesets);
	*changesets = NULL;
}

int knot_changesets_clear(knot_changesets_t *changesets)
{
	if (changesets == NULL) {
		return KNOT_EINVAL;
	}

	knot_changesets_deinit(changesets);
	return knot_changesets_init(changesets);
}

