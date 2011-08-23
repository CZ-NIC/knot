/*  Copyright (C) 2011 CZ.NIC Labs

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

#include "updates/changesets.h"

#include "rrset.h"
#include "util/error.h"

static const size_t KNOT_CHANGESET_COUNT = 5;
static const size_t KNOT_CHANGESET_STEP = 5;
static const size_t KNOT_CHANGESET_RRSET_COUNT = 5;
static const size_t KNOT_CHANGESET_RRSET_STEP = 5;

/*----------------------------------------------------------------------------*/

static int knot_changeset_check_count(knot_rrset_t ***rrsets, size_t count,
                                        size_t *allocated)
{
	// this should also do for the initial case (*rrsets == NULL)
	if (count == *allocated) {
		knot_rrset_t **rrsets_new = (knot_rrset_t **)calloc(
			*allocated + KNOT_CHANGESET_RRSET_STEP,
			sizeof(knot_rrset_t *));
		if (rrsets_new == NULL) {
			return KNOT_ENOMEM;
		}

		memcpy(rrsets_new, *rrsets, count);

		knot_rrset_t **rrsets_old = *rrsets;
		*rrsets = rrsets_new;
		*allocated += KNOT_CHANGESET_RRSET_STEP;
		free(rrsets_old);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_changeset_rrsets_match(const knot_rrset_t *rrset1,
                                         const knot_rrset_t *rrset2)
{
	return knot_rrset_compare(rrset1, rrset2, KNOT_RRSET_COMPARE_HEADER)
	       && (knot_rrset_type(rrset1) != KNOT_RRTYPE_RRSIG
	           || knot_rdata_rrsig_type_covered(
	                    knot_rrset_rdata(rrset1))
	              == knot_rdata_rrsig_type_covered(
	                    knot_rrset_rdata(rrset2)));
}

/*----------------------------------------------------------------------------*/

int knot_changeset_allocate(knot_changesets_t **changesets)
{
	// create new changesets
	*changesets = (knot_changesets_t *)(malloc(sizeof(knot_changesets_t)));
	memset(*changesets, 0, sizeof(knot_changesets_t));

	if (*changesets == NULL) {
		return KNOT_ENOMEM;
	}

	assert((*changesets)->allocated == 0);
	assert((*changesets)->count == 0);
	assert((*changesets)->sets == NULL);

	return knot_changesets_check_size(*changesets);
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_rrset(knot_rrset_t ***rrsets,
                              size_t *count, size_t *allocated,
                              knot_rrset_t *rrset)
{
	int ret = knot_changeset_check_count(rrsets, *count, allocated);
	if (ret != KNOT_EOK) {
		return ret;
	}

	(*rrsets)[(*count)++] = rrset;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_rr(knot_rrset_t ***rrsets, size_t *count,
                           size_t *allocated, knot_rrset_t *rr)
{
	// try to find the RRSet in the list of RRSets
	int i = 0;

	while (i < *count && !knot_changeset_rrsets_match((*rrsets)[i], rr)) {
		++i;
	}

	if (i < *count) {
		// found RRSet to merge the new one into
		if (knot_rrset_merge((void **)&(*rrsets)[i],
		                       (void **)&rr) != KNOT_EOK) {
			return KNOT_ERROR;
		}

		// remove the RR
		knot_rrset_deep_free(&rr, 1, 1, 1);

		return KNOT_EOK;
	} else {
		return knot_changeset_add_rrset(rrsets, count, allocated, rr);
	}
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_new_rr(knot_changeset_t *changeset,
                               knot_rrset_t *rrset,
                               xfrin_changeset_part_t part)
{
	knot_rrset_t ***rrsets = NULL;
	size_t *count = NULL;
	size_t *allocated = NULL;

	switch (part) {
	case XFRIN_CHANGESET_ADD:
		rrsets = &changeset->add;
		count = &changeset->add_count;
		allocated = &changeset->add_allocated;
		break;
	case XFRIN_CHANGESET_REMOVE:
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

void knot_changeset_store_soa(knot_rrset_t **chg_soa,
                               uint32_t *chg_serial, knot_rrset_t *soa)
{
	*chg_soa = soa;
	*chg_serial = knot_rdata_soa_serial(knot_rrset_rdata(soa));
}

/*----------------------------------------------------------------------------*/

int knot_changeset_add_soa(knot_changeset_t *changeset, knot_rrset_t *soa,
                            xfrin_changeset_part_t part)
{
	switch (part) {
	case XFRIN_CHANGESET_ADD:
		knot_changeset_store_soa(&changeset->soa_to,
		                          &changeset->serial_to, soa);
		break;
	case XFRIN_CHANGESET_REMOVE:
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
	if (changesets->allocated == changesets->count) {
		knot_changeset_t *sets = (knot_changeset_t *)calloc(
			changesets->allocated + KNOT_CHANGESET_STEP,
			sizeof(knot_changeset_t));
		if (sets == NULL) {
			return KNOT_ENOMEM;
		}

		/*! \todo realloc() may be more effective. */
		memcpy(sets, changesets->sets, changesets->count);
		knot_changeset_t *old_sets = changesets->sets;
		changesets->sets = sets;
		changesets->count += KNOT_CHANGESET_STEP;
		free(old_sets);
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

void knot_free_changeset(knot_changeset_t **changeset)
{
	assert((*changeset)->add_allocated >= (*changeset)->add_count);
	assert((*changeset)->remove_allocated >= (*changeset)->remove_count);
	assert((*changeset)->allocated >= (*changeset)->size);

	int j;
	for (j = 0; j < (*changeset)->add_count; ++j) {
		knot_rrset_deep_free(&(*changeset)->add[j], 1, 1, 1);
	}
	free((*changeset)->add);

	for (j = 0; j < (*changeset)->remove_count; ++j) {
		knot_rrset_deep_free(&(*changeset)->add[j], 1, 1, 1);
	}
	free((*changeset)->remove);

	knot_rrset_deep_free(&(*changeset)->soa_from, 1, 1, 1);
	knot_rrset_deep_free(&(*changeset)->soa_to, 1, 1, 1);

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
	free(*changesets);
	*changesets = NULL;
}

/*---------------------------------------------------------------------------*/


