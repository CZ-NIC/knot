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

static int knot_changesets_init(changesets_t *chs)
{
	assert(chs != NULL);

	// Create new changesets structure
	memset(chs, 0, sizeof(changesets_t));

	// Initialize memory context for changesets (xmalloc'd)
	struct mempool *chs_pool = mp_new(sizeof(changeset_t));
	chs->mmc_chs.ctx = chs_pool;
	chs->mmc_chs.alloc = (mm_alloc_t)mp_alloc;
	chs->mmc_chs.free = NULL;

	// Initialize memory context for RRs in changesets (xmalloc'd)
	struct mempool *rr_pool = mp_new(sizeof(knot_rr_ln_t));
	chs->mmc_rr.ctx = rr_pool;
	chs->mmc_rr.alloc = (mm_alloc_t)mp_alloc;
	chs->mmc_rr.free = NULL;

	if (chs_pool == NULL || rr_pool == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	// Init list with changesets
	init_list(&chs->sets);

	return KNOT_EOK;
}

changesets_t *changesets_create(unsigned count)
{
	changesets_t *ch = malloc(sizeof(changesets_t));
	if (ch == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}

	int ret = knot_changesets_init(ch);
	if (ret != KNOT_EOK) {
		changesets_free(&ch, NULL);
		return NULL;
	}

	for (unsigned i = 0; i < count; ++i) {
		changeset_t *change = changesets_create_changeset(ch);
		if (change == NULL) {
			changesets_free(&ch, NULL);
			return NULL;
		}
	}

	return ch;
}

changeset_t *changesets_create_changeset(changesets_t *chs)
{
	if (chs == NULL) {
		return NULL;
	}

	// Create set changesets' memory allocator
	changeset_t *set = chs->mmc_chs.alloc(chs->mmc_chs.ctx,
	                                      sizeof(changeset_t));
	if (set == NULL) {
		ERR_ALLOC_FAILED;
		return NULL;
	}
	memset(set, 0, sizeof(changeset_t));

	// Init set's memory context (Allocator from changests structure is used)
	set->mem_ctx = chs->mmc_rr;

	// Init local lists
	init_list(&set->add);
	init_list(&set->remove);

	// Init change lists
	init_list(&set->new_data);
	init_list(&set->old_data);

	// Insert into list of sets
	add_tail(&chs->sets, (node_t *)set);

	++chs->count;

	return set;
}

changeset_t *changesets_get_last(const changesets_t *chs)
{
	if (chs == NULL || EMPTY_LIST(chs->sets)) {
		return NULL;
	}

	return (changeset_t *)(TAIL(chs->sets));
}

bool changesets_empty(const changesets_t *chs)
{
	if (chs == NULL || EMPTY_LIST(chs->sets)) {
		return true;
	}

	changeset_t *ch = NULL;
	WALK_LIST(ch, chs->sets) {
		if (!changeset_is_empty(ch)) {
			return false;
		}
	}

	return true;
}

int changeset_add_rrset(changeset_t *ch, knot_rrset_t *rrset,
                        changeset_part_t part)
{
	// Create wrapper node for list
	knot_rr_ln_t *rr_node =
		ch->mem_ctx.alloc(ch->mem_ctx.ctx, sizeof(knot_rr_ln_t));
	if (rr_node == NULL) {
		// This will not happen with mp_alloc, but allocator can change
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	rr_node->rr = rrset;

	if (part == CHANGESET_ADD) {
		add_tail(&ch->add, (node_t *)rr_node);
	} else {
		add_tail(&ch->remove, (node_t *)rr_node);
	}

	return KNOT_EOK;
}

bool changeset_is_empty(const changeset_t *ch)
{
	if (ch == NULL) {
		return true;
	}

	return (ch->soa_to == NULL &&
	        EMPTY_LIST(ch->add) && EMPTY_LIST(ch->remove));
}

size_t changeset_size(const changeset_t *ch)
{
	if (!ch || changeset_is_empty(ch)) {
		return 0;
	}

	return list_size(&ch->add) + list_size(&ch->remove);
}

int changeset_apply(changeset_t *ch, changeset_part_t part,
                    int (*func)(knot_rrset_t *, void *), void *data)
{
	if (ch == NULL || func == NULL) {
		return KNOT_EINVAL;
	}

	knot_rr_ln_t *rr_node = NULL;
	if (part == CHANGESET_ADD) {
		WALK_LIST(rr_node, ch->add) {
			int res = func(rr_node->rr, data);
			if (res != KNOT_EOK) {
				return res;
			}
		}
	} else if (part == CHANGESET_REMOVE) {
		WALK_LIST(rr_node, ch->remove) {
			int res = func(rr_node->rr, data);
			if (res != KNOT_EOK) {
				return res;
			}
		}
	}

	return KNOT_EOK;
}

int changeset_merge(changeset_t *ch1, changeset_t *ch2)
{
	if (ch1 == NULL || ch2 == NULL || ch1->data != NULL
	    || ch2->data != NULL) {
		return KNOT_EINVAL;
	}

	// Connect lists in changesets together
	add_tail_list(&ch1->add, &ch2->add);
	add_tail_list(&ch1->remove, &ch2->remove);

	// Use soa_to and serial from the second changeset
	// soa_to from the first changeset is redundant, delete it
	knot_rrset_free(&ch1->soa_to, NULL);
	ch1->soa_to = ch2->soa_to;

	return KNOT_EOK;
}

static void knot_free_changeset(changeset_t *ch, mm_ctx_t *rr_mm)
{
	if (ch == NULL) {
		return;
	}

	// Delete RRSets in lists, in case there are any left
	knot_rr_ln_t *rr_node;
	WALK_LIST(rr_node, ch->add) {
		knot_rrset_free(&rr_node->rr, rr_mm);
	}
	WALK_LIST(rr_node, ch->remove) {
		knot_rrset_free(&rr_node->rr, rr_mm);
	}

	knot_rrset_free(&ch->soa_from, rr_mm);
	knot_rrset_free(&ch->soa_to, rr_mm);

	// Delete binary data
	free(ch->data);
}

static void knot_changesets_deinit(changesets_t *ch, mm_ctx_t *rr_mm)
{
	if (!EMPTY_LIST(ch->sets)) {
		changeset_t *chg = NULL;
		WALK_LIST(chg, ch->sets) {
			knot_free_changeset(chg, rr_mm);
		}
	}

	// Free pool with sets themselves
	mp_delete(ch->mmc_chs.ctx);
	// Free pool with RRs in sets / changes
	mp_delete(ch->mmc_rr.ctx);

	knot_rrset_free(&ch->first_soa, rr_mm);
}

void changesets_free(changesets_t **chs, mm_ctx_t *rr_mm)
{
	if (chs == NULL || *chs == NULL) {
		return;
	}

	knot_changesets_deinit(*chs, rr_mm);

	free(*chs);
	*chs = NULL;
}

