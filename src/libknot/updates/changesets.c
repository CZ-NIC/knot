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

#include "updates/changesets.h"
#include "libknot/common.h"
#include "common/descriptor.h"
#include "rrset.h"
#include "util/debug.h"

static const size_t KNOT_CHANGESET_COUNT = 5;
static const size_t KNOT_CHANGESET_STEP = 5;
static const size_t KNOT_CHANGESET_RRSET_COUNT = 5;
static const size_t KNOT_CHANGESET_RRSET_STEP = 5;

/*----------------------------------------------------------------------------*/

static int knot_changeset_check_count(knot_rrset_t ***rrsets, size_t count,
                                        size_t *allocated)
{
	/* Check if allocated is sufficient. */
	if (count <= *allocated) {
		return KNOT_EOK;
	}

	/* How many steps is needed to content count? */
	size_t extra = (count - *allocated) % KNOT_CHANGESET_RRSET_STEP;
	extra = (extra + 1) * KNOT_CHANGESET_RRSET_STEP;

	/* Reallocate memory block. */
	const size_t item_len = sizeof(knot_rrset_t *);
	const size_t new_count = *allocated + extra;
	void *tmp = realloc(*rrsets, new_count * item_len);
	if (tmp == NULL) {
		return KNOT_ENOMEM;
	}
	*rrsets = tmp;
	/* Init new data. */
	memset(*rrsets + *allocated, 0, extra * item_len);
	*allocated = new_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_changeset_rrsets_match(const knot_rrset_t *rrset1,
                                         const knot_rrset_t *rrset2)
{
	return knot_rrset_equal(rrset1, rrset2, KNOT_RRSET_COMPARE_HEADER)
	       && (knot_rrset_type(rrset1) != KNOT_RRTYPE_RRSIG
	           || knot_rrset_rdata_rrsig_type_covered(rrset1)
	              == knot_rrset_rdata_rrsig_type_covered(rrset2));
}

/*----------------------------------------------------------------------------*/

int knot_changeset_allocate(knot_changesets_t **changesets,
                            uint32_t flags)
{
	// create new changesets
	*changesets = (knot_changesets_t *)(malloc(sizeof(knot_changesets_t)));
	if (*changesets == NULL) {
		return KNOT_ENOMEM;
	}

	memset(*changesets, 0, sizeof(knot_changesets_t));
	(*changesets)->flags = flags;

	if (knot_changesets_check_size(*changesets) != KNOT_EOK) {
		free(*changesets);
		*changesets = NULL;
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_rrset(knot_rrset_t ***rrsets,
                              size_t *count, size_t *allocated,
                              knot_rrset_t *rrset)
{
	int ret = knot_changeset_check_count(rrsets, *count + 1, allocated);
	if (ret != KNOT_EOK) {
		return ret;
	}

	(*rrsets)[*count] = rrset;
	*count = *count + 1;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_rr(knot_rrset_t ***rrsets, size_t *count,
                           size_t *allocated, knot_rrset_t *rr)
{
	// try to find the RRSet in the list of RRSets, but search backwards
	// as it is probable that the last RRSet is the one to which the RR
	// belongs

	// Just check the last RRSet. If the RR belongs to it, merge it,
	// otherwise just add the RR to the end of the list

	if (*count > 0
	    && knot_changeset_rrsets_match((*rrsets)[*count - 1], rr)) {
		// Create changesets exactly as they came, with possibly
		// duplicate records
		if (knot_rrset_merge((*rrsets)[*count - 1],
		                     rr) != KNOT_EOK) {
			return KNOT_ERROR;
		}

		knot_rrset_deep_free(&rr, 1, 0);
		return KNOT_EOK;
	} else {
		return knot_changeset_add_rrset(rrsets, count, allocated, rr);
	}
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_new_rr(knot_changeset_t *changeset,
                               knot_rrset_t *rrset,
                               knot_changeset_part_t part)
{
	knot_rrset_t ***rrsets = NULL;
	size_t *count = NULL;
	size_t *allocated = NULL;

	switch (part) {
	case KNOT_CHANGESET_ADD:
		rrsets = &changeset->add;
		count = &changeset->add_count;
		allocated = &changeset->add_allocated;
		break;
	case KNOT_CHANGESET_REMOVE:
		rrsets = &changeset->remove;
		count = &changeset->remove_count;
		allocated = &changeset->remove_allocated;
		break;
	default:
		assert(0);
	}

	assert(rrsets != NULL);
	assert(count != NULL);
	assert(allocated != NULL);

	int ret = knot_changeset_add_rr(rrsets, count, allocated, rrset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

knot_rrset_t *knot_changeset_remove_rr(knot_rrset_t **rrsets, size_t *count,
                                       int pos)
{
	if (pos >= *count || *count == 0) {
		return NULL;
	}

	knot_rrset_t *removed = rrsets[pos];

	// shift all RRSets from pos+1 one cell to the left
	for (int i = pos; i < *count - 1; ++i) {
		rrsets[i] = rrsets[i + 1];
	}

	// just to be sure, set the last previously occupied position to NULL
	rrsets[*count - 1] = NULL;
	*count -= 1;

	return removed;
}

/*----------------------------------------------------------------------------*/

void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                               uint32_t *chg_serial, knot_rrset_t *soa)
{
	*chg_soa = soa;
	*chg_serial = knot_rrset_rdata_soa_serial(soa);
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
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

	/*! \todo Remove return value? */
	return KNOT_EOK;
}

/*---------------------------------------------------------------------------*/

int knot_changesets_check_size(knot_changesets_t *changesets)
{
	/* Check if allocated is sufficient. */
	if (changesets->count < changesets->allocated) {
		return KNOT_EOK;
	}

	/* How many steps is needed to content count? */
	size_t extra = (changesets->count - changesets->allocated)
	                % KNOT_CHANGESET_STEP;
	extra = (extra + 1) * KNOT_CHANGESET_STEP;

	/* Allocate new memory block. */
	const size_t item_len = sizeof(knot_changeset_t);
	size_t new_count = (changesets->allocated + extra);
	knot_changeset_t *sets = malloc(new_count * item_len);
	if (sets == NULL) {
		return KNOT_ENOMEM;
	}

	/* Clear new memory block and copy old data. */
	memset(sets, 0, new_count * item_len);
	memcpy(sets, changesets->sets, changesets->allocated * item_len);

	/* Set type to all newly allocated changesets. */
	for (int i = changesets->allocated; i < new_count; ++i) {
		sets[i].flags = changesets->flags;
	}

	/* Replace old changesets. */
	free(changesets->sets);
	changesets->sets = sets;
	changesets->allocated = new_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_changeset_set_flags(knot_changeset_t *changeset,
                             uint32_t flags)
{
	changeset->flags = flags;
}

/*----------------------------------------------------------------------------*/

uint32_t knot_changeset_flags(knot_changeset_t *changeset)
{
	return changeset->flags;
}

/*----------------------------------------------------------------------------*/

int knot_changeset_is_empty(const knot_changeset_t *changeset)
{
	if (changeset == NULL) {
		return 0;
	}

	return (changeset->add_count == 0 && changeset->remove_count == 0);
}

/*----------------------------------------------------------------------------*/

void knot_free_changeset(knot_changeset_t **changeset)
{
	assert((*changeset)->add_allocated >= (*changeset)->add_count);
	assert((*changeset)->remove_allocated >= (*changeset)->remove_count);
	assert((*changeset)->allocated >= (*changeset)->size);

	int j;
	for (j = 0; j < (*changeset)->add_count; ++j) {
		knot_rrset_deep_free(&(*changeset)->add[j], 1, 1);
	}
	free((*changeset)->add);

	for (j = 0; j < (*changeset)->remove_count; ++j) {
		knot_rrset_deep_free(&(*changeset)->remove[j], 1, 1);
	}
	free((*changeset)->remove);

	knot_rrset_deep_free(&(*changeset)->soa_from, 1, 1);
	knot_rrset_deep_free(&(*changeset)->soa_to, 1, 1);

	free((*changeset)->data);


	*changeset = NULL;
}

/*----------------------------------------------------------------------------*/

void knot_free_changesets(knot_changesets_t **changesets)
{
	if (changesets == NULL || *changesets == NULL) {
		return;
	}

	assert((*changesets)->allocated >= (*changesets)->count);

	for (int i = 0; i < (*changesets)->count; ++i) {
		knot_changeset_t *ch = &(*changesets)->sets[i];
		knot_free_changeset(&ch);
	}

	free((*changesets)->sets);

	knot_rrset_deep_free(&(*changesets)->first_soa, 1, 1);

	assert((*changesets)->changes == NULL);

	free(*changesets);
	*changesets = NULL;
}

/*----------------------------------------------------------------------------*/
/* knot_changes_t manipulation                                                */
/*----------------------------------------------------------------------------*/

int knot_changes_rrsets_reserve(knot_rrset_t ***rrsets,
                              int *count, int *allocated, int to_add)
{
	if (rrsets == NULL || count == NULL || allocated == NULL) {
		return KNOT_EINVAL;
	}

	if (*count + to_add <= *allocated) {
		return KNOT_EOK;
	}

	int new_count = (*allocated == 0) ? 2 : *allocated * 2;
	while (new_count < *count + to_add) {
		new_count *= 2;
	}

	/* Allocate new memory block. */
	knot_rrset_t **rrsets_new = malloc(new_count * sizeof(knot_rrset_t *));
	if (rrsets_new == NULL) {
		return KNOT_ENOMEM;
	}

	/* Initialize new memory and copy old data. */
	memset(rrsets_new, 0, new_count * sizeof(knot_rrset_t *));
	memcpy(rrsets_new, *rrsets, (*allocated) * sizeof(knot_rrset_t *));

	/* Free old nodes and switch pointers. */
	free(*rrsets);
	*rrsets = rrsets_new;
	*allocated = new_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_changes_nodes_reserve(knot_node_t ***nodes,
                             int *count, int *allocated)
{
	if (nodes == NULL || count == NULL || allocated == NULL) {
		return KNOT_EINVAL;
	}

	if (*count + 2 <= *allocated) {
		return KNOT_EOK;
	}

	int new_count = (*allocated == 0) ? 2 : *allocated * 2;

	/* Allocate new memory block. */
	const size_t node_len = sizeof(knot_node_t *);
	knot_node_t **nodes_new = malloc(new_count * node_len);
	if (nodes_new == NULL) {
		return KNOT_ENOMEM;
	}

	/* Clear memory block and copy old data. */
	memset(nodes_new, 0, new_count * node_len);
	memcpy(nodes_new, *nodes, (*allocated) * node_len);

	/* Free old nodes and switch pointers. */
	free(*nodes);
	*nodes = nodes_new;
	*allocated = new_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_changes_rdata_reserve(knot_rrset_t ***rdatas,
                               int count, int *allocated, int to_add)
{
	if (rdatas == NULL || allocated == NULL) {
		return KNOT_EINVAL;
	}

	if (count + to_add <= *allocated) {
		return KNOT_EOK;
	}

	int new_count = (*allocated == 0) ? 2 : *allocated * 2;
	while (new_count < count + to_add) {
		new_count *= 2;
	}

	/* Allocate new memory block. */
	knot_rrset_t **rdatas_new = malloc(new_count * sizeof(knot_rrset_t *));
	if (rdatas_new == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Initialize new memory and copy old data. */
	memset(rdatas_new, 0, new_count * sizeof(knot_rrset_t *));
	memcpy(rdatas_new, *rdatas, (*allocated) * sizeof(knot_rrset_t *));

	/* Free old rdatas and switch pointers. */
	free(*rdatas);
	*rdatas = rdatas_new;
	*allocated = new_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

/*!< \note Always adds the whole RRSet = all rdata. */
void knot_changes_add_rdata(knot_rrset_t **rdatas, int *count,
                            knot_rrset_t *rrset)
{
	if (rdatas == NULL || count == NULL || rrset == NULL || rrset->rdata_count == 0) {
		return;
	}

	rdatas[*count] = rrset;
	*count += 1;
}

/*----------------------------------------------------------------------------*/

int knot_changes_add_old_rrsets(knot_rrset_t **rrsets, int count,
                                knot_changes_t *changes, int add_rdata)
{
	if (rrsets == NULL || changes == NULL) {
		return KNOT_EINVAL;
	}

	if (count == 0) {
		return KNOT_EOK;
	}

	/* Reserve twice the space, to have enough space for RRSIGs if
	 * there are some.
	 */
	int ret = knot_changes_rrsets_reserve(&changes->old_rrsets,
	                                      &changes->old_rrsets_count,
	                                      &changes->old_rrsets_allocated,
	                                      2 * count);
	if (ret != KNOT_EOK) {
//		dbg_xfrin("Failed to reserve changes rrsets.\n");
		return ret;
	}

	/* Mark RRsets and RDATA for removal. */
	for (unsigned i = 0; i < count; ++i) {
		if (rrsets[i] == NULL) {
			continue;
		}

		knot_rrset_t *rrsigs = knot_rrset_get_rrsigs(rrsets[i]);

		if (add_rdata) {

			/* RDATA count in the RRSet. */
			int rdata_count = 1;

			if (rrsigs != NULL) {
				/* Increment the RDATA count by the count of
				 * RRSIGs. */
				rdata_count += 1;
			}

			/* Remove old RDATA. */
			ret = knot_changes_rdata_reserve(&changes->old_rdata,
			                          changes->old_rdata_count,
			                          &changes->old_rdata_allocated,
			                          rdata_count);
			if (ret != KNOT_EOK) {
//				dbg_xfrin("Failed to reserve changes rdata.\n");
				return ret;
			}

			knot_changes_add_rdata(changes->old_rdata,
			                       &changes->old_rdata_count,
			                       rrsets[i]);

			knot_changes_add_rdata(changes->old_rdata,
			                       &changes->old_rdata_count,
			                       rrsigs);
		}

		/* Disconnect RRsigs from rrset. */
		knot_rrset_set_rrsigs(rrsets[i], NULL);
		changes->old_rrsets[changes->old_rrsets_count++] = rrsets[i];
		if (rrsigs) {
			changes->old_rrsets[changes->old_rrsets_count++] = rrsigs;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_changes_add_new_rrsets(knot_rrset_t **rrsets, int count,
                                knot_changes_t *changes, int add_rdata)
{
	if (rrsets == NULL || changes == NULL) {
		return KNOT_EINVAL;
	}

	if (count == 0) {
		return KNOT_EOK;
	}

	int ret = knot_changes_rrsets_reserve(&changes->new_rrsets,
	                                      &changes->new_rrsets_count,
	                                      &changes->new_rrsets_allocated,
	                                      count);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Mark RRsets and RDATA for removal. */
	for (unsigned i = 0; i < count; ++i) {
		if (rrsets[i] == NULL) {
			continue;
		}

		if (add_rdata) {
			ret = knot_changes_rdata_reserve(&changes->new_rdata,
			                          changes->new_rdata_count,
			                          &changes->new_rdata_allocated,
			                          1);
			if (ret != KNOT_EOK) {
				return ret;
			}

			knot_changes_add_rdata(changes->new_rdata,
			                       &changes->new_rdata_count,
			                       rrsets[i]);
		}

		changes->new_rrsets[changes->new_rrsets_count++] = rrsets[i];
	}

	return KNOT_EOK;
}
