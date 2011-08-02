#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "dnslib/changesets.h"

#include "dnslib/rrset.h"
#include "dnslib/error.h"

static const size_t DNSLIB_CHANGESET_COUNT = 5;
static const size_t DNSLIB_CHANGESET_STEP = 5;
static const size_t DNSLIB_CHANGESET_RRSET_COUNT = 5;
static const size_t DNSLIB_CHANGESET_RRSET_STEP = 5;

/*----------------------------------------------------------------------------*/

static int dnslib_changeset_check_count(dnslib_rrset_t ***rrsets, size_t count,
                                        size_t *allocated)
{
	// this should also do for the initial case (*rrsets == NULL)
	if (count == *allocated) {
		dnslib_rrset_t **rrsets_new = (dnslib_rrset_t **)calloc(
			*allocated + DNSLIB_CHANGESET_RRSET_STEP,
			sizeof(dnslib_rrset_t *));
		if (rrsets_new == NULL) {
			return DNSLIB_ENOMEM;
		}

		memcpy(rrsets_new, *rrsets, count);

		dnslib_rrset_t **rrsets_old = *rrsets;
		*rrsets = rrsets_new;
		*allocated += DNSLIB_CHANGESET_RRSET_STEP;
		free(rrsets_old);
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

static int dnslib_changeset_rrsets_match(const dnslib_rrset_t *rrset1,
                                         const dnslib_rrset_t *rrset2)
{
	return dnslib_rrset_compare(rrset1, rrset2, DNSLIB_RRSET_COMPARE_HEADER)
	       && (dnslib_rrset_type(rrset1) != DNSLIB_RRTYPE_RRSIG
	           || dnslib_rdata_rrsig_type_covered(
	                    dnslib_rrset_rdata(rrset1))
	              == dnslib_rdata_rrsig_type_covered(
	                    dnslib_rrset_rdata(rrset2)));
}

/*----------------------------------------------------------------------------*/

int dnslib_changeset_allocate(dnslib_changesets_t **changesets)
{
	// create new changesets
	*changesets = (dnslib_changesets_t *)(
			calloc(1, sizeof(dnslib_changesets_t)));

	if (*changesets == NULL) {
		return DNSLIB_ENOMEM;
	}

	assert((*changesets)->allocated == 0);
	assert((*changesets)->count == 0);
	assert((*changesets)->sets = NULL);

	return dnslib_changesets_check_size(*changesets);
}

/*----------------------------------------------------------------------------*/

int dnslib_changeset_add_rrset(dnslib_rrset_t ***rrsets,
                              size_t *count, size_t *allocated,
                              dnslib_rrset_t *rrset)
{
	int ret = dnslib_changeset_check_count(rrsets, *count, allocated);
	if (ret != DNSLIB_EOK) {
		return ret;
	}

	(*rrsets)[(*count)++] = rrset;

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

int dnslib_changeset_add_rr(dnslib_rrset_t ***rrsets, size_t *count,
                           size_t *allocated, dnslib_rrset_t *rr)
{
	// try to find the RRSet in the list of RRSets
	int i = 0;

	while (i < *count && !dnslib_changeset_rrsets_match((*rrsets)[i], rr)) {
		++i;
	}

	if (i < *count) {
		// found RRSet to merge the new one into
		if (dnslib_rrset_merge((void **)&(*rrsets)[i],
		                       (void **)&rr) != DNSLIB_EOK) {
			return DNSLIB_ERROR;
		}

		// remove the RR
		dnslib_rrset_deep_free(&rr, 1, 1, 1);

		return DNSLIB_EOK;
	} else {
		return dnslib_changeset_add_rrset(rrsets, count, allocated, rr);
	}
}

/*----------------------------------------------------------------------------*/

int dnslib_changeset_add_new_rr(dnslib_changeset_t *changeset,
                               dnslib_rrset_t *rrset,
                               xfrin_changeset_part_t part)
{
	dnslib_rrset_t ***rrsets = NULL;
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

	int ret = dnslib_changeset_add_rr(rrsets, count, allocated, rrset);
	if (ret != DNSLIB_EOK) {
		return ret;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

void dnslib_changeset_store_soa(dnslib_rrset_t **chg_soa,
                               uint32_t *chg_serial, dnslib_rrset_t *soa)
{
	*chg_soa = soa;
	*chg_serial = dnslib_rdata_soa_serial(dnslib_rrset_rdata(soa));
}

/*----------------------------------------------------------------------------*/

int dnslib_changeset_add_soa(dnslib_changeset_t *changeset, dnslib_rrset_t *soa,
                            xfrin_changeset_part_t part)
{
	switch (part) {
	case XFRIN_CHANGESET_ADD:
		dnslib_changeset_store_soa(&changeset->soa_to,
		                          &changeset->serial_to, soa);
		break;
	case XFRIN_CHANGESET_REMOVE:
		dnslib_changeset_store_soa(&changeset->soa_from,
		                          &changeset->serial_from, soa);
		break;
	default:
		assert(0);
	}

	/*! \todo Remove return value? */
	return DNSLIB_EOK;
}

/*---------------------------------------------------------------------------*/

int dnslib_changesets_check_size(dnslib_changesets_t *changesets)
{
	if (changesets->allocated == changesets->count) {
		dnslib_changeset_t *sets = (dnslib_changeset_t *)calloc(
			changesets->allocated + DNSLIB_CHANGESET_STEP,
			sizeof(dnslib_changeset_t));
		if (sets == NULL) {
			return DNSLIB_ENOMEM;
		}

		/*! \todo realloc() may be more effective. */
		memcpy(sets, changesets->sets, changesets->count);
		dnslib_changeset_t *old_sets = changesets->sets;
		changesets->sets = sets;
		changesets->count += DNSLIB_CHANGESET_STEP;
		free(old_sets);
	}

	return DNSLIB_EOK;
}

/*----------------------------------------------------------------------------*/

void dnslib_free_changesets(dnslib_changesets_t **changesets)
{
	if (changesets == NULL || *changesets == NULL) {
		return;
	}

	assert((*changesets)->allocated >= (*changesets)->count);

	for (int i = 0; i < (*changesets)->count; ++i) {
		dnslib_changeset_t *ch = &(*changesets)->sets[i];

		assert(ch->add_allocated >= ch->add_count);
		assert(ch->remove_allocated >= ch->remove_count);
		assert(ch->allocated >= ch->size);

		int j;
		for (j = 0; i < ch->add_count; ++j) {
			dnslib_rrset_deep_free(&ch->add[j], 1, 1, 1);
		}
		free(ch->add);

		for (j = 0; i < ch->remove_count; ++j) {
			dnslib_rrset_deep_free(&ch->add[j], 1, 1, 1);
		}
		free(ch->remove);

		dnslib_rrset_deep_free(&ch->soa_from, 1, 1, 1);
		dnslib_rrset_deep_free(&ch->soa_to, 1, 1, 1);

		free(ch->data);
	}

	free((*changesets)->sets);
	free(*changesets);
	*changesets = NULL;
}

/*---------------------------------------------------------------------------*/


