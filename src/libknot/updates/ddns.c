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
#include "nameserver/name-server.h"  // ns_serial_compare() - TODO: extract

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
                                const knot_rrset_t *rrset, uint16_t qclass,
                                knot_rrset_t **rrset_copy)
{
	assert(changeset != NULL);
	assert(rrset != NULL);
	assert(rrset_copy != NULL);

	int ret;

	// create a copy of the RRSet
	/*! \todo ref #937 If the packet was not parsed all at once, we could save this
	 *        copy.
	 */
	*rrset_copy = NULL;
	ret = knot_rrset_deep_copy(rrset, rrset_copy, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (knot_rrset_class(rrset) == qclass) {
		// this RRSet should be added to the zone
		dbg_ddns_detail(" * adding RR %p\n", *rrset_copy);
		ret = knot_changeset_add_rr(&changeset->add,
		                            &changeset->add_count,
		                            &changeset->add_allocated,
		                            *rrset_copy);
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

		dbg_ddns_detail(" * removing RR %p\n", *rrset_copy);

		ret = knot_ddns_check_remove_rr(changeset, *rrset_copy);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(rrset_copy, 1, 1, 1);
			return ret;
		}

		ret = knot_changeset_add_rr(&changeset->remove,
		                            &changeset->remove_count,
		                            &changeset->remove_allocated,
		                            *rrset_copy);
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
	knot_rrset_t *soa_end = NULL;
	ret = knot_rrset_deep_copy(soa, &soa_begin, 0);
	if (ret == KNOT_EOK) {
		knot_changeset_store_soa(&changeset->soa_from,
		                         &changeset->serial_from, soa_begin);
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	/* Current SERIAL */
	int64_t sn = knot_rdata_soa_serial(knot_rrset_rdata(soa_begin));
	int64_t sn_new;
	/* Incremented SERIAL
	 * We must set it now to be able to compare SERIAL from SOAs in the
	 * UPDATE to it. Although we do not have the new SOA yet.
	 */
	if (sn > -1) {
		sn_new = (uint32_t)sn + 1;
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	const knot_rrset_t *rrset = NULL;
	knot_rrset_t *rrset_copy = NULL;

	dbg_ddns("Processing UPDATE section.\n");
	for (int i = 0; i < knot_packet_authority_rrset_count(query); ++i) {

		rrset = knot_packet_authority_rrset(query, i);

		ret = knot_ddns_check_update(rrset, query, rcode);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to check update RRSet:%s\n",
			                knot_strerror(ret));
			return ret;
		}

		ret = knot_ddns_add_update(changeset, rrset,
		                          knot_packet_qclass(query),
		                          &rrset_copy);

		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add update RRSet:%s\n",
			                knot_strerror(ret));
			*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
			                             : KNOT_RCODE_SERVFAIL;
			return ret;
		}

		/* Check if the added record is SOA. If yes, check the SERIAL.
		 * If this record should cause the SOA to be replaced in the
		 * zone, use it as the ending SOA.
		 *
		 * Also handle cases where there are multiple SOAs to be added
		 * in the same UPDATE. The one with the largest SERIAL should
		 * be used.
		 *
		 * TODO: If there are more SOAs in the UPDATE one after another,
		 *       the ddns_add_update() function will merge them into a
		 *       RRSet. This should be handled somehow.
		 */
		if (knot_rrset_type(rrset) == KNOT_RRTYPE_SOA
		    && ns_serial_compare(knot_rdata_soa_serial(
		                                 knot_rrset_rdata(rrset)),
		                         sn_new) > 0) {
			sn_new = knot_rdata_soa_serial(knot_rrset_rdata(rrset));
			soa_end = (knot_rrset_t *)rrset_copy;
		}
	}
	
	/* Ending SOA */
	if (soa_end == NULL) {
		/* If not set */
		assert(sn_new == (uint32_t)sn + 1);
		ret = knot_rrset_deep_copy(soa, &soa_end, 1);
		knot_rdata_t *rd = knot_rrset_get_rdata(soa_end);
		knot_rdata_soa_serial_set(rd, sn_new);
	}

	knot_changeset_store_soa(&changeset->soa_to,
	                         &changeset->serial_to,
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

/*----------------------------------------------------------------------------*/
/* New DDNS processing                                                      - */
/*----------------------------------------------------------------------------*/

static int knot_ddns_check_remove_rr2(knot_changeset_t *changeset,
                                      const knot_dname_t *owner,
                                      uint16_t type, const knot_rdata_t *rdata,
                                      knot_rrset_t ***removed,
                                      int *removed_count)
{
	assert(changeset != NULL);
	assert(removed != NULL);
	assert(removed_count != NULL);

	*removed = (knot_rrset_t **)malloc(changeset->add_count
	                                  * sizeof(knot_rrset_t *));
	if (*removed == NULL) {
		return KNOT_ENOMEM;
	}

	*removed_count = 0;
	knot_rrset_t *remove = NULL;

	/*
	 * We assume that each RR in the ADD section of the changeset is in its
	 * own RRSet. It should be as this is how they are stored there by the
	 * ddns_process_add() function.
	 */

	dbg_ddns_verb("Removing possible redundant RRs from changeset.\n");
	for (int i = 0; i < changeset->add_count; ++i) {
		// Removing RR(s) from this owner
		if (knot_dname_compare(knot_rrset_owner(changeset->add[i]),
		                       owner) == 0) {
			// Removing one or all RRSets
			if (rdata == NULL
			    && (type == knot_rrset_type(changeset->add[i])
			        || type == KNOT_RRTYPE_ANY)) {
				dbg_ddns_detail("Removing one or all RRSets\n");
					remove = knot_changeset_remove_rr(
					              changeset->add,
					              &changeset->add_count, i);
			} else if (type == knot_rrset_type(changeset->add[i])) {
				// Removing specific RR
				assert(rdata != NULL);

				knot_rrtype_descriptor_t *desc =
					knot_rrtype_descriptor_by_type(type);

				// We must check if the RDATA match
				if (knot_rdata_compare(rdata,
				         knot_rrset_rdata(changeset->add[i]),
				         desc->wireformat)) {
					remove = knot_changeset_remove_rr(
					              changeset->add,
					              &changeset->add_count, i);
				}
			}

			dbg_ddns_detail("Removed RRSet from chgset:\n");
			knot_rrset_dump(remove, 0);
			(*removed)[(*removed_count)++] = remove;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_rr_is_nsec3(const knot_rrset_t *rr)
{
	assert(rr != NULL);

	if ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
	    || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
	        && knot_rdata_rrsig_type_covered(knot_rrset_rdata(rr))
	            == KNOT_RRTYPE_NSEC3))
	{
		dbg_ddns_detail("This is NSEC3-related RRSet.\n");
		return 1;
	} else {
		return 0;
	}
}

/*----------------------------------------------------------------------------*/
/*! \note Copied from xfrin_add_new_node(). */
static knot_node_t *knot_ddns_add_new_node(knot_zone_contents_t *zone,
                                           knot_dname_t *owner, int is_nsec3)
{
	assert(zone != NULL);
	assert(owner != NULL);

	knot_node_t *node = knot_node_new(owner, NULL, 0);
	if (node == NULL) {
		dbg_xfrin("Failed to create a new node.\n");
		return NULL;
	}

	int ret = 0;

	// insert the node into zone structures and create parents if
	// necessary
	if (is_nsec3) {
		ret = knot_zone_contents_add_nsec3_node(zone, node, 1, 0, 1);
	} else {
		ret = knot_zone_contents_add_node(zone, node, 1, 0, 1);
	}
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to add new node to zone contents.\n");
		return NULL;
	}

	/*!
	 * \note It is not needed to set the previous node, we will do this
	 *       in adjusting after the transfer.
	 */
	assert(zone->zone != NULL);
	knot_node_set_zone(node, zone->zone);

	return node;
}

/*----------------------------------------------------------------------------*/

static knot_node_t *knot_ddns_get_node(knot_zone_contents_t *zone,
                                       const knot_rrset_t *rr)
{
	assert(zone != NULL);
	assert(rr != NULL);

	knot_node_t *node = NULL;
	knot_dname_t *owner = knot_rrset_get_owner(rr);

	dbg_ddns_detail("Searching for node...\n");
	if (knot_ddns_rr_is_nsec3(rr)) {
		node = knot_zone_contents_get_nsec3_node(zone, owner);
	} else {
		node = knot_zone_contents_get_node(zone, owner);
	}

	return node;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_add(const knot_rrset_t *rr,
                                 knot_node_t *node,
                                 knot_zone_contents_t *zone,
                                 knot_changeset_t *changeset,
                                 knot_changes_t *changes, uint16_t qclass,
                                 knot_rrset_t **rr_copy)
{
	assert(rr != NULL);
	assert(zone != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);
	assert(rr_copy != NULL);

	if (node == NULL) {
		// create new node, connect it properly to the
		// zone nodes
		dbg_ddns_detail("Node not found. Creating new.\n");
		node = knot_ddns_add_new_node(zone, knot_rrset_get_owner(rr),
		                              knot_ddns_rr_is_nsec3(rr));
		if (node == NULL) {
			dbg_xfrin("Failed to create new node in zone.\n");
		}
	}

	// Here we could probably use the code from xfrin_apply_add()

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_rr(const knot_rrset_t *rr,
                                    knot_node_t *node,
                                    knot_zone_contents_t *zone,
                                    knot_changeset_t *changeset,
                                    knot_changes_t *changes, uint16_t qclass)
{
	assert(rr != NULL);
	assert(zone != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_rrset(uint16_t type,
                                       const knot_rdata_t *rdata,
                                       knot_node_t *node,
                                       knot_changeset_t *changeset,
                                       knot_changes_t *changes)
{
	assert(node != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);

	if (type == KNOT_RRTYPE_NS) {
		// Ignore this RR
		return KNOT_EOK;
	}

	// this should be ruled out before
	assert(type != KNOT_RRTYPE_SOA);

	/* 1) Remove the RRSet from the node. */
	knot_rrset_t *removed = knot_node_remove_rrset(node, type);

	// no such RR
	if (removed == NULL) {
		// ignore
		return KNOT_EOK;
	}

	/* 2) Store it to 'changes' for later deallocation. */
	int ret = knot_changes_add_rrsets_with_rdata(&removed, 1, changes);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to add removed RRSet to 'changes': %s.\n",
		         knot_strerror(ret));
		return ret;
	}

	/* 3) Copy the RRSet, so that it can be stored to the changeset. */
	knot_rrset_t *removed_copy = NULL;
	ret = knot_rrset_deep_copy(removed, &removed_copy, 1);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy the removed RRSet: %s.\n",
		         knot_strerror(ret))
		return ret;
	}

	/* 4) But we must check if some of the RRs were not previously added
	 *    by the same UPDATE. If yes, these must be removed from the ADD
	 *    section of the changeset and also from this RRSet copy (so they
	 *    are neither stored in the REMOVE section of the changeset).
	 */
	knot_rrset_t **from_chgset = NULL;
	int from_chgset_count = 0;

	/* 4 a) Remove redundant RRs from the ADD section of the changeset. */
	ret = knot_ddns_check_remove_rr2(changeset, knot_node_owner(node), type,
	                                 rdata, &from_chgset,
	                                 &from_chgset_count);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to remove possible redundant RRs from ADD "
		         "section: %s.\n", knot_strerror(ret))
		knot_rrset_deep_free(&removed_copy, 1, 1, 1);
		return ret;
	}

	/* 4 b) Remove these RRs from the copy of the RRSet removed from zone.*/
	knot_rdata_t *rem = NULL;
	for (int i = 0; i < from_chgset_count; ++i) {
		rem = knot_rrset_remove_rdata(removed_copy, knot_rrset_rdata(
		                                               from_chgset[i]));
		// And delete it right away, no use for that
		knot_rdata_deep_free(&rem, knot_rrset_type(from_chgset[i]), 1);

	}

	/* 5) Store the remaining RRSet to the changeset. Do not try to merge
	 *    to some previous RRSet, there should be none.
	 */

	ret = knot_changeset_add_rrset(&changeset->remove,
	                               &changeset->remove_count,
	                               &changeset->remove_allocated,
	                               removed_copy);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to store the RRSet copy to changeset: %s.\n",
		         knot_strerror(ret))
		knot_rrset_deep_free(&removed_copy, 1, 1, 1);
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_all(knot_node_t *node,
                                     knot_changeset_t *changeset,
                                     knot_changes_t *changes)
{
	assert(changeset != NULL);
	assert(changes != NULL);

	/*
	 * This basically means to call knot_ddns_process_rem_rrset() for every
	 * type present in the node.
	 */
	int ret = 0;
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	int is_apex = knot_node_rrset(node, KNOT_RRTYPE_SOA) != NULL;

	dbg_ddns_verb("Removing all RRSets.\n");
	for (int i = 0; i < knot_node_rrset_count(node); ++i) {
		// If the node is apex, skip NS and SOA
		if (is_apex &&
		    (knot_rrset_type(rrsets[i]) == KNOT_RRTYPE_SOA
		     || knot_rrset_type(rrsets[i]) == KNOT_RRTYPE_NS)) {
			continue;
		}

		ret = knot_ddns_process_rem_rrset(knot_rrset_type(rrsets[i]),
		                                NULL, node, changeset, changes);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to remove RRSet: %s\n",
			         knot_strerror(ret));
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rr(const knot_rrset_t *rr,
                                knot_zone_contents_t *zone,
                                knot_changeset_t *changeset,
                                knot_changes_t *changes, uint16_t qclass,
                                knot_rrset_t **rr_copy)
{
	assert(rr != NULL);
	assert(zone != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);
	assert(rr_copy != NULL);

	/* 1) Find node that will be affected. */
	knot_node_t *node = knot_ddns_get_node(zone, rr);

	/* 2) Decide what to do. */

	if (knot_rrset_class(rr) == knot_zone_contents_class(zone)) {
		return knot_ddns_process_add(rr, node, zone, changeset,
		                             changes, qclass, rr_copy);
	} else if (knot_rrset_class(rr) == KNOT_CLASS_NONE) {
		return knot_ddns_process_rem_rr(rr, node, zone, changeset,
		                                changes, qclass);
	} else if (knot_rrset_class(rr) == KNOT_CLASS_ANY) {
		if (knot_rrset_type(rr) == KNOT_RRTYPE_ANY) {
			return knot_ddns_process_rem_all(node, changeset,
			                                 changes);
		} else {
			return knot_ddns_process_rem_rrset(knot_rrset_type(rr),
			                                   NULL, node,
			                                   changeset, changes);
		}
	} else {
		assert(0);
		return KNOT_ERROR;
	}
}

/*----------------------------------------------------------------------------*/
/*
 * NOTES:
 * - 'zone' must be a copy of the current zone.
 * - changeset must be allocated
 * - changes must be allocated
 *
 * All this is done in the first parts of xfrin_apply_changesets() - extract
 * to separate function, if possible.
 *
 * If anything fails, rollback must be done. The xfrin_rollback_update() may
 * be good for this.
 */
int knot_ddns_process_update2(knot_zone_contents_t *zone,
                              const knot_packet_t *query,
                              knot_changeset_t *changeset,
                              knot_changes_t *changes,
                              knot_rcode_t *rcode)
{
	if (zone == NULL || query == NULL || changeset == NULL || rcode == NULL
	    || changes == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* Copy base SOA RR. */
	const knot_rrset_t *soa = knot_node_rrset(knot_zone_contents_apex(zone),
						  KNOT_RRTYPE_SOA);
	knot_rrset_t *soa_begin = NULL;
	knot_rrset_t *soa_end = NULL;
	ret = knot_rrset_deep_copy(soa, &soa_begin, 0);
	if (ret == KNOT_EOK) {
		knot_changeset_store_soa(&changeset->soa_from,
		                         &changeset->serial_from, soa_begin);
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	/* Current SERIAL */
	int64_t sn = knot_rdata_soa_serial(knot_rrset_rdata(soa_begin));
	int64_t sn_new;

	/* Incremented SERIAL
	 * We must set it now to be able to compare SERIAL from SOAs in the
	 * UPDATE to it. Although we do not have the new SOA yet.
	 */
	if (sn > -1) {
		sn_new = (uint32_t)sn + 1;
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	/* Process all RRs the Authority (Update) section. */

	const knot_rrset_t *rr = NULL;
	knot_rrset_t *rr_copy = NULL;

	dbg_ddns("Processing UPDATE section.\n");
	for (int i = 0; i < knot_packet_authority_rrset_count(query); ++i) {

		rr = knot_packet_authority_rrset(query, i);

		/* Check if the entry is correct. */
		ret = knot_ddns_check_update(rr, query, rcode);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to check update RRSet:%s\n",
			                knot_strerror(ret));
			return ret;
		}

		/* Check if the record is SOA. If yes, check the SERIAL.
		 * If this record should cause the SOA to be replaced in the
		 * zone, use it as the ending SOA.
		 *
		 * Also handle cases where there are multiple SOAs to be added
		 * in the same UPDATE. The one with the largest SERIAL should
		 * be used.
		 *
		 * TODO: If there are more SOAs in the UPDATE one after another,
		 *       the ddns_add_update() function will merge them into a
		 *       RRSet. This should be handled somehow.
		 *
		 * If the serial is not larger than the current zone serial,
		 * ignore the record and continue. This will ensure that the
		 * RR processing function receives only SOA RRs that should be
		 * added to the zone (replacing the old one).
		 */
		if (knot_rrset_type(rr) == KNOT_RRTYPE_SOA
		    && (knot_rrset_class(rr) == KNOT_CLASS_NONE
		        || knot_rrset_class(rr) == KNOT_CLASS_ANY
		        || ns_serial_compare(knot_rdata_soa_serial(
		                        knot_rrset_rdata(rr)), sn_new) <= 0)) {
			// This ignores also SOA removals
			continue;
		}

		ret = knot_ddns_process_rr(rr, zone, changeset, changes,
		                           knot_packet_qclass(query),
		                           &rr_copy);

		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to process update RR:%s\n",
			         knot_strerror(ret));
			*rcode = (ret == KNOT_EMALF) ? KNOT_RCODE_FORMERR
			                             : KNOT_RCODE_SERVFAIL;
			return ret;
		}

		// we need the RR copy, that's why this code is here
		if (knot_rrset_type(rr) == KNOT_RRTYPE_SOA) {
			int64_t sn_rr = knot_rdata_soa_serial(
			                        knot_rrset_rdata(rr));
			assert(ns_serial_compare(sn_rr, sn_new) <= 0);
			sn_new = sn_rr;
			soa_end = (knot_rrset_t *)rr_copy;
		}
	}

	/* Ending SOA */
	if (soa_end == NULL) {
		/* If not set */
		assert(sn_new == (uint32_t)sn + 1);
		ret = knot_rrset_deep_copy(soa, &soa_end, 1);
		knot_rdata_t *rd = knot_rrset_get_rdata(soa_end);
		knot_rdata_soa_serial_set(rd, sn_new);
	}

	knot_changeset_store_soa(&changeset->soa_to,
	                         &changeset->serial_to,
	                         soa_end);

	return ret;
}
