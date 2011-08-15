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

#include <assert.h>

#include "updates/ddns.h"
#include "updates/changesets.h"
#include "util/debug.h"
#include "packet/packet.h"
#include "util/error.h"
#include "consts.h"

/*----------------------------------------------------------------------------*/

static void knot_ddns_prereqs_free(knot_ddns_prereq_t **prereq)
{
	/*! \todo Implement. */
}

/*----------------------------------------------------------------------------*/
// Copied from XFR - maybe extract somewhere else
static int knot_ddns_prereq_check_rrsets(knot_rrset_t ***rrsets,
                                         size_t *count, size_t *allocated)
{
	int new_count = 0;
	if (*count == *allocated) {
		new_count = *allocated * 2;
	}

	knot_rrset_t **rrsets_new =
		(knot_rrset_t **)calloc(new_count, sizeof(knot_rrset_t *));
	if (rrsets_new == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(rrsets_new, *rrsets, *count);
	*rrsets = rrsets_new;
	*allocated = new_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_prereq_check_dnames(knot_dname_t ***dnames,
                                         size_t *count, size_t *allocated)
{
	int new_count = 0;
	if (*count == *allocated) {
		new_count = *allocated * 2;
	}

	knot_dname_t **dnames_new =
		(knot_dname_t **)calloc(new_count, sizeof(knot_dname_t *));
	if (dnames_new == NULL) {
		return KNOT_ENOMEM;
	}

	memcpy(dnames_new, *dnames, *count);
	*dnames = dnames_new;
	*allocated = new_count;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_prereq_rrset(const knot_rrset_t *rrset,
                                      knot_rrset_t ***rrsets,
                                      size_t *count, size_t *allocd)
{
	// check if such RRSet is not already there and merge if needed
	int ret;
	for (int i = 0; i < *count; ++i) {
		if (knot_rrset_compare(rrset, (*rrsets)[i],
		                       KNOT_RRSET_COMPARE_HEADER) == 0) {
			ret = knot_rrset_merge((void **)&((*rrsets)[i]),
			                       (void **)&rrset);
			if (ret != KNOT_EOK) {
				return ret;
			} else {
				return KNOT_EOK;
			}
		}
	}

	// if we are here, the RRSet was not found
	ret = knot_ddns_prereq_check_rrsets(rrsets, count, allocd);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t *new_rrset = NULL;
	ret = knot_rrset_deep_copy(rrset, &new_rrset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	(*rrsets)[(*count)++] = new_rrset;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_prereq_dname(const knot_dname_t *dname,
                                      knot_dname_t ***dnames,
                                      size_t *count, size_t *allocd)
{
	// we do not have to check if the name is not already there
	// if it is, we will just check it twice in the zone

	int ret = knot_ddns_prereq_check_dnames(dnames, count, allocd);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_dname_t *dname_new = knot_dname_deep_copy(dname);
	if (dname_new == NULL) {
		return KNOT_ENOMEM;
	}

	(*dnames)[(*count)++] = dname_new;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_prereq(knot_ddns_prereq_t *prereqs,
                                const knot_rrset_t *rrset, uint16_t qclass)
{
	assert(prereqs != NULL);
	assert(rrset != NULL);

	if (knot_rrset_ttl(rrset) != 0) {
		return KNOT_EMALF;
	}

	int ret;

	if (knot_rrset_class(rrset) == KNOT_CLASS_ANY) {
		if (knot_rrset_rdata(rrset) != NULL) {
			return KNOT_EMALF;
		}
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_ANY) {
			ret = knot_ddns_add_prereq_dname(
				knot_rrset_owner(rrset), &prereqs->in_use,
				&prereqs->in_use_count,
				&prereqs->in_use_allocd);
		} else {
			ret = knot_ddns_add_prereq_rrset(rrset,
			                                &prereqs->exist,
			                                &prereqs->exist_count,
			                                &prereqs->exist_allocd);
		}
	} else if (knot_rrset_class(rrset) == KNOT_CLASS_NONE) {
		if (knot_rrset_rdata(rrset) != NULL) {
			return KNOT_EMALF;
		}
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_ANY) {
			ret = knot_ddns_add_prereq_dname(
				knot_rrset_owner(rrset), &prereqs->not_in_use,
				&prereqs->not_in_use_count,
				&prereqs->not_in_use_allocd);
		} else {
			ret = knot_ddns_add_prereq_rrset(rrset,
			                            &prereqs->not_exist,
			                            &prereqs->not_exist_count,
			                            &prereqs->not_exist_allocd);
		}
	} else if (knot_rrset_class(rrset) == qclass) {
		ret = knot_ddns_add_prereq_rrset(rrset,
		                                 &prereqs->exist_full,
		                                 &prereqs->exist_full_count,
		                                 &prereqs->exist_full_allocd);
	} else {
		return KNOT_EMALF;
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_update(knot_changeset_t *changeset,
                         const knot_rrset_t *rrset, uint16_t qclass)
{
	assert(changeset != NULL);
	assert(rrset != NULL);

	int ret;

	// create a copy of the RRSet
	/*! \todo If the packet was not parsed all at once, we could save this
	 *        copy.
	 */
	knot_rrset_t *rrset_copy;
	ret = knot_rrset_deep_copy(rrset, &rrset_copy);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (knot_rrset_class(rrset) == qclass) {
		// this RRSet should be added to the zone
		ret = knot_changeset_add_rr(&changeset->add,
		                            &changeset->add_count,
		                            &changeset->add_allocated,
		                            rrset_copy);
	} else {
		// this RRSet marks removal of something from zone
		// what should be removed is distinguished when applying
		ret = knot_changeset_add_rr(&changeset->remove,
		                            &changeset->remove_count,
		                            &changeset->remove_allocated,
		                            rrset_copy);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int knot_ddns_check_zone(const knot_zone_t *zone, knot_packet_t *query,
                         uint8_t *rcode)
{
	/*! \todo Check also CLASS. */
	return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

int knot_ddns_process_prereqs(knot_packet_t *query,
                              knot_ddns_prereq_t **prereqs, uint8_t *rcode)
{
	/*! \todo Consider not parsing the whole packet at once, but
	 *        parsing one RR at a time - could save some memory and time.
	 */

	if (query == NULL || prereqs == NULL || rcode == NULL) {
		return KNOT_EBADARG;
	}

	// allocate space for the prerequisities
	*prereqs = (knot_ddns_prereq_t *)calloc(1, sizeof(knot_ddns_prereq_t));
	CHECK_ALLOC_LOG(*prereqs, KNOT_ENOMEM);

	int ret;

	for (int i = 0; i < knot_packet_answer_rrset_count(query); ++i) {
		// we must copy the RRSets, because all those stored in the
		// packet will be destroyed
		ret = knot_ddns_add_prereq(*prereqs,
		                           knot_packet_answer_rrset(query, i),
		                           knot_packet_qclass(query));
		if (ret != KNOT_EOK) {
			debug_knot_ddns("Failed to add prerequisity RRSet:%s\n",
			                knot_strerror(ret));
			*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
			                             : KNOT_RCODE_SERVFAIL;
			knot_ddns_prereqs_free(prereqs);
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ddns_check_prereqs(const knot_zone_contents_t *zone,
                            knot_ddns_prereq_t **prereqs, uint8_t *rcode)
{
	return KNOT_ENOTSUP;
}

/*----------------------------------------------------------------------------*/

int knot_ddns_process_update(knot_packet_t *query,
                             knot_changeset_t **changeset, uint8_t *rcode)
{
	// just put all RRSets from query's Authority section
	// it will be distinguished when applying to the zone

	if (query == NULL || changeset == NULL || rcode == NULL) {
		return KNOT_EBADARG;
	}

	*changeset = (knot_changeset_t *)calloc(1, sizeof(knot_changeset_t));
	CHECK_ALLOC_LOG(*changeset, KNOT_ENOMEM);

	int ret;

	for (int i = 0; i < knot_packet_authority_rrset_count(query); ++i) {
		ret = knot_ddns_add_update(*changeset,
		                          knot_packet_authority_rrset(query, i),
		                          knot_packet_qclass(query));

		if (ret != KNOT_EOK) {
			debug_knot_ddns("Failed to add update RRSet:%s\n",
			                knot_strerror(ret));
			*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
			                             : KNOT_RCODE_SERVFAIL;
			knot_free_changeset(changeset);
			return ret;
		}
	}

	return KNOT_EOK;
}

