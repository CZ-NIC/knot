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

#include <assert.h>

#include "updates/ddns.h"
#include "updates/changesets.h"
#include "util/debug.h"
#include "packet/packet.h"
#include "consts.h"
#include "common/mempattern.h"

/*----------------------------------------------------------------------------*/
// Copied from XFR - maybe extract somewhere else
static int knot_ddns_prereq_check_rrsets(knot_rrset_t ***rrsets,
                                         size_t *count, size_t *allocated)
{
	/* This is really confusing, it's ptr -> array of "knot_rrset_t*" */
	char *arr = (char*)*rrsets;
	int ret = 0;
	ret = mreserve(&arr, sizeof(knot_rrset_t*), *count + 1, 0, allocated);
	if (ret < 0) {
		return KNOT_ENOMEM;
	}
	
	*rrsets = (knot_rrset_t**)arr;

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_prereq_check_dnames(knot_dname_t ***dnames,
                                         size_t *count, size_t *allocated)
{
	/* This is really confusing, it's ptr -> array of "knot_dname_t*" */
	char *arr = (char*)*dnames;
	int ret = 0;
	ret = mreserve(&arr, sizeof(knot_dname_t*), *count + 1, 0, allocated);
	if (ret < 0) {
		return KNOT_ENOMEM;
	}
	
	*dnames = (knot_dname_t**)arr;

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
	ret = knot_rrset_deep_copy(rrset, &new_rrset, 0);
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

static int knot_ddns_check_remove_rr(knot_changeset_t *changeset,
                                     const knot_rrset_t *rr)
{
	dbg_ddns_verb("Removing possible redundant RRs from changeset.\n");
	for (int i = 0; i < changeset->add_count; ++i) {
		// Removing RR(s) from this owner
		if (knot_dname_compare(knot_rrset_owner(rr),
		                       knot_rrset_owner(changeset->add[i])) == 0) {
			// Removing one or all RRSets
			if (knot_rrset_class(rr) == KNOT_CLASS_ANY) {
				dbg_ddns_detail("Removing one or all "
				                "RRSets\n");
				if (knot_rrset_type(rr)
				    == knot_rrset_type(changeset->add[i])
				    || knot_rrset_type(rr) == KNOT_RRTYPE_ANY) {
					knot_rrset_t *remove =
						knot_changeset_remove_rr(
						    changeset->add,
						    &changeset->add_count, i);
					dbg_ddns_detail("Removed RRSet from "
					                "chgset:\n");
					knot_rrset_dump(remove, 0);
					knot_rrset_deep_free(&remove, 1, 1, 1);
				}
			} else if (knot_rrset_type(rr)
			           == knot_rrset_type(changeset->add[i])){
				/* All other classes are checked in
				 * knot_ddns_check_update().
				 */
				assert(knot_rrset_class(rr) == KNOT_CLASS_NONE);

				// Removing specific RR from a RRSet
				knot_rdata_t *rdata = knot_rrset_remove_rdata(
				                        changeset->add[i],
				                        knot_rrset_rdata(rr));

				dbg_ddns_detail("Removed RR from chgset: \n");
				knot_rdata_dump(rdata, knot_rrset_type(rr), 0);

				knot_rdata_deep_free(&rdata,
				         knot_rrset_type(changeset->add[i]), 1);
				// if the RRSet is empty, remove from changeset
				if (knot_rrset_rdata_rr_count(changeset->add[i])
				    == 0) {
					knot_rrset_t *remove =
						knot_changeset_remove_rr(
						    changeset->add,
						    &changeset->add_count, i);
					dbg_ddns_detail("RRSet empty, removing."
					                "\n");
					knot_rrset_deep_free(&remove, 1, 1, 1);
				}
			}
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_update(knot_changeset_t *changeset,
                         const knot_rrset_t *rrset, uint16_t qclass)
{
	assert(changeset != NULL);
	assert(rrset != NULL);

	int ret;

	// create a copy of the RRSet
	/*! \todo ref #937 If the packet was not parsed all at once, we could save this
	 *        copy.
	 */
	knot_rrset_t *rrset_copy = NULL;
	ret = knot_rrset_deep_copy(rrset, &rrset_copy, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (knot_rrset_class(rrset) == qclass) {
		// this RRSet should be added to the zone
		dbg_ddns_detail(" * adding RR %p\n", rrset_copy);
		ret = knot_changeset_add_rr(&changeset->add,
		                            &changeset->add_count,
		                            &changeset->add_allocated,
		                            rrset_copy);
	} else {
		// this RRSet marks removal of something from zone

		/* To imitate in-order processing of UPDATE RRs, we must check
		 * If this REMOVE RR does not affect any of the previous
		 * ADD RRs in this update. If yes, they must be removed from
		 * the changeset.
		 *
		 * See https://git.nic.cz/redmine/issues/937#note-14 and below.
		 */

		// TODO: finish, disabled for now

		dbg_ddns_detail(" * removing RR %p\n", rrset_copy);

		ret = knot_ddns_check_remove_rr(changeset, rrset_copy);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&rrset_copy, 1, 1, 1);
			return ret;
		}

		ret = knot_changeset_add_rr(&changeset->remove,
		                            &changeset->remove_count,
		                            &changeset->remove_allocated,
		                            rrset_copy);
	}

	return ret;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_check_exist(const knot_zone_contents_t *zone,
                                 const knot_rrset_t *rrset, knot_rcode_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(knot_rrset_rdata(rrset) == NULL);
	assert(knot_rrset_type(rrset) != KNOT_RRTYPE_ANY);
	assert(knot_rrset_ttl(rrset) == 0);
	assert(knot_rrset_class(rrset) == KNOT_CLASS_ANY);

	if (!knot_dname_is_subdomain(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EBADZONE;
	}

	const knot_node_t *node;
	node = knot_zone_contents_find_node(zone, knot_rrset_owner(rrset));
	if (node == NULL) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_ENONODE;
	} else if (knot_node_rrset(node, knot_rrset_type(rrset)) == NULL) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_ENORRSET;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_check_exist_full(const knot_zone_contents_t *zone,
                                      const knot_rrset_t *rrset, 
                                      knot_rcode_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(knot_rrset_rdata(rrset) == NULL);
	assert(knot_rrset_type(rrset) != KNOT_RRTYPE_ANY);
	assert(knot_rrset_ttl(rrset) == 0);
	assert(knot_rrset_class(rrset) == KNOT_CLASS_ANY);

	if (!knot_dname_is_subdomain(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EBADZONE;
	}

	const knot_node_t *node;
	const knot_rrset_t *found;

	node = knot_zone_contents_find_node(zone, knot_rrset_owner(rrset));
	if (node == NULL) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else if ((found = knot_node_rrset(node, knot_rrset_type(rrset)))
	            == NULL) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else {
		// do not have to compare the header, it is already done
		assert(knot_rrset_type(found) == knot_rrset_type(rrset));
		assert(knot_dname_compare(knot_rrset_owner(found),
		                          knot_rrset_owner(rrset)) == 0);
		if (knot_rrset_compare_rdata(found, rrset) <= 0) {
			*rcode = KNOT_RCODE_NXRRSET;
			return KNOT_EPREREQ;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_check_not_exist(const knot_zone_contents_t *zone,
                                     const knot_rrset_t *rrset, 
                                     knot_rcode_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(knot_rrset_rdata(rrset) == NULL);
	assert(knot_rrset_type(rrset) != KNOT_RRTYPE_ANY);
	assert(knot_rrset_ttl(rrset) == 0);
	assert(knot_rrset_class(rrset) == KNOT_CLASS_NONE);

	if (!knot_dname_is_subdomain(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EBADZONE;
	}

	const knot_node_t *node;
	const knot_rrset_t *found;

	node = knot_zone_contents_find_node(zone, knot_rrset_owner(rrset));
	if (node == NULL) {
		return KNOT_EOK;
	} else if ((found = knot_node_rrset(node, knot_rrset_type(rrset)))
	            == NULL) {
		return KNOT_EOK;
	}
	
	/* RDATA is always empty for simple RRset checks. */

	*rcode = KNOT_RCODE_YXRRSET;
	return KNOT_EPREREQ;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_check_in_use(const knot_zone_contents_t *zone,
                                  const knot_dname_t *dname, 
                                  knot_rcode_t *rcode)
{
	assert(zone != NULL);
	assert(dname != NULL);
	assert(rcode != NULL);

	if (!knot_dname_is_subdomain(dname,
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EBADZONE;
	}

	const knot_node_t *node;

	node = knot_zone_contents_find_node(zone, dname);
	if (node == NULL) {
		*rcode = KNOT_RCODE_NXDOMAIN;
		return KNOT_EPREREQ;
	} else if (knot_node_rrset_count(node) == 0) {
		*rcode = KNOT_RCODE_NXDOMAIN;
		return KNOT_EPREREQ;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_check_not_in_use(const knot_zone_contents_t *zone,
                                      const knot_dname_t *dname, 
                                      knot_rcode_t *rcode)
{
	assert(zone != NULL);
	assert(dname != NULL);
	assert(rcode != NULL);

	if (!knot_dname_is_subdomain(dname,
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EBADZONE;
	}

	const knot_node_t *node;

	node = knot_zone_contents_find_node(zone, dname);
	if (node == NULL) {
		return KNOT_EOK;
	} else if (knot_node_rrset_count(node) == 0) {
		return KNOT_EOK;
	}

	*rcode = KNOT_RCODE_YXDOMAIN;
	return KNOT_EPREREQ;
}

/*----------------------------------------------------------------------------*/
/* API functions                                                              */
/*----------------------------------------------------------------------------*/

int knot_ddns_check_zone(const knot_zone_contents_t *zone, 
                         const knot_packet_t *query, knot_rcode_t *rcode)
{
	if (zone == NULL || query == NULL || rcode == NULL) {
		*rcode = KNOT_RCODE_SERVFAIL;
		return KNOT_EINVAL;
	}

	if (knot_packet_qtype(query) != KNOT_RRTYPE_SOA) {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	// check zone CLASS
	if (knot_zone_contents_class(zone) !=
	    knot_packet_qclass(query)) {
		*rcode = KNOT_RCODE_NOTAUTH;
		return KNOT_ENOZONE;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ddns_process_prereqs(const knot_packet_t *query,
                              knot_ddns_prereq_t **prereqs, knot_rcode_t *rcode)
{
	/*! \todo Consider not parsing the whole packet at once, but
	 *        parsing one RR at a time - could save some memory and time.
	 */

	if (query == NULL || prereqs == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}
	
	dbg_ddns("Processing prerequisities.\n");

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
			dbg_ddns("Failed to add prerequisity RRSet:%s\n",
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
                            knot_ddns_prereq_t **prereqs, knot_rcode_t *rcode)
{
	int i, ret;
	
	dbg_ddns("Checking 'exist' prerequisities.\n");

	for (i = 0; i < (*prereqs)->exist_count; ++i) {
		ret = knot_ddns_check_exist(zone, (*prereqs)->exist[i], rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	dbg_ddns("Checking 'exist full' prerequisities.\n");
	for (i = 0; i < (*prereqs)->exist_full_count; ++i) {
		ret = knot_ddns_check_exist_full(zone,
		                                (*prereqs)->exist_full[i],
		                                 rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	dbg_ddns("Checking 'not exist' prerequisities.\n");
	for (i = 0; i < (*prereqs)->not_exist_count; ++i) {
		ret = knot_ddns_check_not_exist(zone, (*prereqs)->not_exist[i],
		                                rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	dbg_ddns("Checking 'in use' prerequisities.\n");
	for (i = 0; i < (*prereqs)->in_use_count; ++i) {
		ret = knot_ddns_check_in_use(zone, (*prereqs)->in_use[i],
		                             rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	dbg_ddns("Checking 'not in use' prerequisities.\n");
	for (i = 0; i < (*prereqs)->not_in_use_count; ++i) {
		ret = knot_ddns_check_not_in_use(zone,
		                                 (*prereqs)->not_in_use[i],
		                                 rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_check_update(const knot_rrset_t *rrset,
                                  const knot_packet_t *query, 
                                  knot_rcode_t *rcode)
{
	/* Accept both subdomain and dname match. */
	dbg_ddns("Checking UPDATE packet.\n");
	const knot_dname_t *owner = knot_rrset_owner(rrset);
	const knot_dname_t *qname = knot_packet_qname(query);
	int is_sub = knot_dname_is_subdomain(owner, qname);
	if (!is_sub && knot_dname_compare(owner, qname) != 0) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EBADZONE;
	}

	if (knot_rrset_class(rrset) == knot_packet_qclass(query)) {
		if (knot_rrtype_is_metatype(knot_rrset_type(rrset))) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (knot_rrset_class(rrset) == KNOT_CLASS_ANY) {
		if (knot_rrset_rdata(rrset) != NULL
		    || (knot_rrtype_is_metatype(knot_rrset_type(rrset))
		        && knot_rrset_type(rrset) != KNOT_RRTYPE_ANY)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (knot_rrset_class(rrset) == KNOT_CLASS_NONE) {
		if (knot_rrset_ttl(rrset) != 0
		    || knot_rrtype_is_metatype(knot_rrset_type(rrset))) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

int knot_ddns_process_update(const knot_zone_contents_t *zone,
			     const knot_packet_t *query,
                             knot_changeset_t *changeset, knot_rcode_t *rcode)
{
	// just put all RRSets from query's Authority section
	// it will be distinguished when applying to the zone

	if (query == NULL || changeset == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	
	/* Copy base SOA query. */
	const knot_rrset_t *soa = knot_node_rrset(knot_zone_contents_apex(zone),
						  KNOT_RRTYPE_SOA);
	knot_rrset_t *soa_begin = NULL;
	ret = knot_rrset_deep_copy(soa, &soa_begin, 0);
	if (ret == KNOT_EOK) {
		knot_changeset_store_soa(&changeset->soa_from, &changeset->serial_from,
					 soa_begin);
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	dbg_ddns("Processing UPDATE section.\n");
	for (int i = 0; i < knot_packet_authority_rrset_count(query); ++i) {

		const knot_rrset_t *rrset =
				knot_packet_authority_rrset(query, i);

		ret = knot_ddns_check_update(rrset, query, rcode);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to check update RRSet:%s\n",
			                knot_strerror(ret));
			return ret;
		}

		ret = knot_ddns_add_update(changeset, rrset,
		                          knot_packet_qclass(query));

		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add update RRSet:%s\n",
			                knot_strerror(ret));
			*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
			                             : KNOT_RCODE_SERVFAIL;
			return ret;
		}
	}
	
	/* Ending SOA. */
	knot_rrset_t *soa_end = NULL;
	ret = knot_rrset_deep_copy(soa, &soa_end, 1);
	
	/* Increment and write back. */
	knot_rdata_t *rd = knot_rrset_get_rdata(soa_end);
	int64_t sn = knot_rdata_soa_serial(rd);
	if (sn > -1) {
		knot_rdata_soa_serial_set(rd, (uint32_t)sn + 1);
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
	}
	knot_changeset_store_soa(&changeset->soa_to, &changeset->serial_to,
				 soa_end);

	return ret;
}

/*----------------------------------------------------------------------------*/

void knot_ddns_prereqs_free(knot_ddns_prereq_t **prereq)
{
	dbg_ddns("Freeing prerequisities.\n");
	
	int i;

	for (i = 0; i < (*prereq)->exist_count; ++i) {
		knot_rrset_deep_free(&(*prereq)->exist[i], 1, 1, 1);
	}
	free((*prereq)->exist);

	for (i = 0; i < (*prereq)->exist_full_count; ++i) {
		knot_rrset_deep_free(&(*prereq)->exist_full[i], 1, 1, 1);
	}
	free((*prereq)->exist_full);

	for (i = 0; i < (*prereq)->not_exist_count; ++i) {
		knot_rrset_deep_free(&(*prereq)->not_exist[i], 1, 1, 1);
	}
	free((*prereq)->not_exist);

	for (i = 0; i < (*prereq)->in_use_count; ++i) {
		knot_dname_free(&(*prereq)->in_use[i]);
	}
	free((*prereq)->in_use);

	for (i = 0; i < (*prereq)->not_in_use_count; ++i) {
		knot_dname_free(&(*prereq)->not_in_use[i]);
	}
	free((*prereq)->not_in_use);

	free(*prereq);
	*prereq = NULL;
}
