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
#include "updates/xfr-in.h"

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
		if (knot_rrset_match(rrset, (*rrsets)[i],
		                       KNOT_RRSET_COMPARE_HEADER) == 1) {
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

	node = knot_zone_contents_find_node(zone, knot_rrset_owner(rrset));
	if (node == NULL) {
		return KNOT_EOK;
	} else if (knot_node_rrset(node, knot_rrset_type(rrset)) == NULL) {
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
		if (rcode != NULL) {
			*rcode = KNOT_RCODE_SERVFAIL;
		}
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
                                      size_t *removed_count)
{
	assert(changeset != NULL);
	assert(removed != NULL);
	assert(removed_count != NULL);

	*removed_count = 0;
	*removed = (knot_rrset_t **)malloc(changeset->add_count
	                                  * sizeof(knot_rrset_t *));
	if (*removed == NULL) {
		return KNOT_ENOMEM;
	}

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

static void knot_ddns_check_add_rr(knot_changeset_t *changeset,
                                   const knot_rrset_t *rr,
                                   knot_rrset_t **removed)
{
	assert(changeset != NULL);
	assert(rr != NULL);
	assert(removed != NULL);

	*removed = NULL;
	
	dbg_ddns_verb("Removing possible redundant RRs from changeset.\n");
	for (int i = 0; i < changeset->remove_count; ++i)  {
		/* Just check exact match, the changeset contains only 
		 * whole RRs that have been removed.
		 */
		if (knot_rrset_match(rr, changeset->remove[i],
		                     KNOT_RRSET_COMPARE_WHOLE) == 1) {
			*removed = knot_changeset_remove_rr(
			                        changeset->remove,
			                        &changeset->remove_count, i);
			dbg_ddns_detail("Removed RRSet from chgset:\n");
			knot_rrset_dump(*removed, 0);
			break;
		}
	}
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_rr_is_nsec3(const knot_rrset_t *rr)
{
	assert(rr != NULL);

	if ((knot_rrset_type(rr) == KNOT_RRTYPE_NSEC3)
	    || (knot_rrset_type(rr) == KNOT_RRTYPE_RRSIG
	        && knot_rrset_rdata(rr) 
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
		knot_node_free(&node);
		return NULL;
	}

	/*!
	 * \note It is not needed to set the previous node, we will do this
	 *       in adjusting after the transfer.
	 */
	assert(zone->zone != NULL);
	//knot_node_set_zone(node, zone->zone);
	assert(node->zone == zone->zone);

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

static int knot_ddns_process_add_cname(knot_node_t *node, 
                                       const knot_rrset_t *rr,
                                       knot_changeset_t *changeset,
                                       knot_changes_t *changes)
{
	assert(node != NULL);
	assert(rr != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);
	
	dbg_ddns_detail("Adding CNAME RR.\n");
	
	int ret = 0;
	
	/* Get the current CNAME RR from the node. */
	knot_rrset_t *removed = knot_node_get_rrset(node, KNOT_RRTYPE_CNAME);
	
	if (removed != NULL) {
		/* If they are identical, ignore. */
		if (knot_rrset_match(removed, rr, KNOT_RRSET_COMPARE_WHOLE)
		    == 1) {
			dbg_ddns_verb("CNAME identical to one in the node.\n");
			return 1;
		}
		
		/*! \note
		 * Together with the removed CNAME we remove also its RRSIGs as
		 * they would not be valid for the new CNAME anyway.
		 *
		 * \todo Document!!
		 */
		
		/* b) Store it to 'changes', together with its RRSIGs. */
		ret = knot_changes_add_old_rrsets(&removed, 1, changes, 1);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add removed RRSet to "
			         "'changes': %s\n", knot_strerror(ret));
			return ret;
		}

		/* c) And remove it from the node. */
		(void)knot_node_remove_rrset(node, KNOT_RRTYPE_CNAME);
		
		/* d) Check if this CNAME was not previously added by
		 *    the UPDATE. If yes, remove it from the ADD 
		 *    section and do not add it to the REMOVE section.
		 */
		knot_rrset_t **from_chgset = NULL;
		size_t from_chgset_count = 0;
		ret = knot_ddns_check_remove_rr2(
		                   changeset, knot_rrset_owner(removed),
		                   KNOT_RRTYPE_CNAME, knot_rrset_rdata(removed),
		                   &from_chgset, &from_chgset_count);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to remove possible redundant "
			         "RRs from ADD section: %s.\n", 
			         knot_strerror(ret));
			free(from_chgset);
			return ret;
		}
	
		assert(from_chgset_count <= 1);
	
		if (from_chgset_count == 1) {
			/* Just delete the RRSet. */
			knot_rrset_deep_free(&(from_chgset[0]), 1, 1, 1);
			/* Okay, &(from_chgset[0]) is basically equal to just
			 * from_chgset, but it's more clear this way that we are
			 * deleting the first RRSet in the array ;-)
			 */
		} else {
			/* Otherwise copy the removed CNAME and add it 
			 * to the REMOVE section.
			 */
			knot_rrset_t *removed_copy;
			ret = knot_rrset_deep_copy(removed, 
			                           &removed_copy, 1);
			if (ret != KNOT_EOK) {
				dbg_ddns("Failed to copy removed RRSet:"
				         " %s\n", knot_strerror(ret));
				free(from_chgset);
				return ret;
			}
			
			ret = knot_changeset_add_rrset(
				&changeset->remove,
				&changeset->remove_count,
				&changeset->remove_allocated,
				removed_copy);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&removed_copy, 
				                     1, 1, 1);
				dbg_ddns("Failed to add removed CNAME "
				         "to changeset: %s\n",
				         knot_strerror(ret));
				free(from_chgset);
				return ret;
			}
		}
		free(from_chgset);
	} else if (knot_node_rrset_count(node) != 0) {
		/* 2) Other occupied node => ignore. */
		return 1;
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_add_soa(knot_node_t *node, 
                                     const knot_rrset_t *rr,
                                     knot_changes_t *changes)
{
	assert(node != NULL);
	assert(rr != NULL);
	assert(changes != NULL);
	
	dbg_ddns_detail("Adding SOA RR.\n");
	
	int ret = 0;
	
	/*
	 * Just remove the SOA from the node, together with its RRSIGs. 
	 * Adding the RR is done in the caller function. Note that only SOA
	 * with larger SERIAL than the current one will get to these functions,
	 * so we don't have to check the SERIALS again. But an assert won't
	 * hurt.
	 */
	
	/* Get the current SOA RR from the node. */
	knot_rrset_t *removed = knot_node_get_rrset(node, KNOT_RRTYPE_SOA);
	
	if (removed != NULL) {
		dbg_ddns_detail("Found SOA in the node.\n");
		/* If they are identical, ignore. */
		if (knot_rrset_match(removed, rr, KNOT_RRSET_COMPARE_WHOLE)
		    == 1) {
			dbg_ddns_detail("Old and new SOA identical.\n");
			return 1;
		}
		
		/* Check that the serial is indeed larger than the current one*/
		assert(ns_serial_compare(knot_rdata_soa_serial(
		                                 knot_rrset_rdata(removed)),
		                         knot_rdata_soa_serial(
		                                 knot_rrset_rdata(rr))) < 0);
		
		/* 1) Store it to 'changes', together with its RRSIGs. */
		ret = knot_changes_add_old_rrsets(
		                        &removed, 1, changes, 1);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add removed RRSet to "
			         "'changes': %s\n", knot_strerror(ret));
			return ret;
		}

		/* 2) And remove it from the node. */
		(void)knot_node_remove_rrset(node, KNOT_RRTYPE_SOA);
		
		/* No changeset processing needed in this case. */
	} else {
		dbg_ddns_detail("No SOA in node, ignoring.\n");
		/* If there is no SOA in the node, ignore. */
		return 1;
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_rr_new_normal(knot_node_t *node, knot_rrset_t *rr_copy,
                                       knot_changes_t *changes)
{
	assert(node != NULL);
	assert(rr_copy != NULL);
	assert(changes != NULL);
	
	dbg_ddns_verb("Adding normal RR.\n");
	
	/* Add the RRSet to 'changes'. */
	int ret = knot_changes_add_new_rrsets(&rr_copy, 1, changes, 1);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rr_copy, 1, 1, 1);
		dbg_ddns("Failed to store copy of the added RR: "
		         "%s\n", knot_strerror(ret));
		return ret;
	}
	
	/* Add the RRSet to the node. */
	ret = knot_node_add_rrset(node, rr_copy, 0);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to add RR to node: %s\n", knot_strerror(ret));
		return ret;
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_rr_new_rrsig(knot_node_t *node, knot_rrset_t *rr_copy,
                                      knot_changes_t *changes, 
                                      uint16_t type_covered)
{
	assert(node != NULL);
	assert(rr_copy != NULL);
	assert(changes != NULL);
	
	dbg_ddns_verb("Adding RRSIG RR.\n");
	
	/* Create RRSet to be covered by the RRSIG. */
	knot_rrset_t *covered_rrset = knot_rrset_new(
	                        knot_rrset_get_owner(rr_copy), type_covered,
	                        knot_rrset_class(rr_copy),
	                        knot_rrset_ttl(rr_copy));
	if (covered_rrset == NULL) {
		dbg_ddns("Failed to create RRSet to be covered"
			 " by the UPDATE RRSIG RR.\n");
		knot_rrset_deep_free(&rr_copy, 1, 1, 1);
		return KNOT_ENOMEM;
	}
	
	/* Add the RRSet to the node. */
	int ret = knot_node_add_rrset(node, covered_rrset, 0);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to add the RRSet to be covered to the node: %s"
		         ".\n", knot_strerror(ret));
		knot_rrset_deep_free(&rr_copy, 1, 1, 1);
		knot_rrset_deep_free(&covered_rrset, 1, 1, 1);
		return KNOT_ENOMEM;
	}
	
	/* Add the RRSet to 'changes'. */
	ret = knot_changes_add_new_rrsets(&covered_rrset, 1, changes, 0);
	if (ret != KNOT_EOK) {
		dbg_xfrin("Failed to add new RRSet (covered) to list: %s.\n",
		          knot_strerror(ret));
		knot_rrset_deep_free(&rr_copy, 1, 1, 1);
		knot_rrset_deep_free(&covered_rrset, 1, 1, 1);
		return ret;
	}

	/* Add the RRSIG RRSet to 'changes'. */
	ret = knot_changes_add_new_rrsets(&rr_copy, 1, changes, 1);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rr_copy, 1, 1, 1);
		dbg_ddns("Failed to store copy of the added RRSIG: %s\n",
			 knot_strerror(ret));
		return ret;
	}
	
	/* Add the RRSIG RRSet to the covered RRSet. */
	ret = knot_rrset_add_rrsigs(covered_rrset, rr_copy, 
	                            KNOT_RRSET_DUPL_SKIP);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to add RRSIG RR to the covered RRSet.\n");
		return ret;
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_rr_merge_normal(knot_rrset_t *node_rrset_copy,
                                         knot_rrset_t **rr_copy)
{
	assert(node_rrset_copy != NULL);
	assert(rr_copy != NULL);
	assert(*rr_copy != NULL);
	
	dbg_ddns_verb("Merging normal RR to existing RRSet.\n");
	
	/* In case the RRSet is empty (and only remained there because 
	 * of the RRSIGs) it may happen that the TTL may be different 
	 * than that of he new RRs. Update the TTL according to the 
	 * first RR.
	 */	
	if (knot_rrset_rdata(node_rrset_copy) == NULL
	    && knot_rrset_ttl(node_rrset_copy) 
	       != knot_rrset_ttl(*rr_copy)) {
		knot_rrset_set_ttl(node_rrset_copy, 
		                   knot_rrset_ttl(*rr_copy));
	}

	int rdata_in_copy = knot_rrset_rdata_rr_count(*rr_copy);
	int ret = knot_rrset_merge_no_dupl((void **)&node_rrset_copy, 
	                                   (void **)rr_copy);
	dbg_ddns_detail("Merge returned: %d\n", ret);

	if (ret < 0) {
		dbg_ddns("Failed to merge UPDATE RR to node RRSet: %s."
		         "\n", knot_strerror(ret));
		return ret;
	}

	knot_rrset_free(rr_copy);

	if (rdata_in_copy == ret) {
		/* All RDATA have been removed, because they were duplicates
		 * or there were none (0). In general this means, that no
		 * change was made.
		 */
		return 1;
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_rr_merge_rrsig(knot_rrset_t *node_rrset_copy,
                                        knot_rrset_t **rr_copy,
                                        knot_changes_t *changes)
{
	assert(node_rrset_copy != NULL);
	assert(rr_copy != NULL);
	assert(*rr_copy != NULL);
	assert(changes != NULL);
	
	dbg_ddns_verb("Adding RRSIG RR to existing RRSet.\n");
	
	knot_rrset_t *rrsigs_old = knot_rrset_get_rrsigs(node_rrset_copy);
	int ret = 0;
	
	if (rrsigs_old != NULL) {
		/* If there is an RRSIG RRSet already, copy it too. */
		knot_rrset_t *rrsigs_copy = NULL;
		ret = xfrin_copy_old_rrset(rrsigs_old, &rrsigs_copy,
		                           changes, 1);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy RRSIG RRSet: "
			         "%s\n", knot_strerror(ret));
			return ret;
		}
		
		/* Replace the RRSIGs by the copy. */
		ret = knot_rrset_set_rrsigs(node_rrset_copy, rrsigs_copy);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to replace RRSIGs in "
			         "the RRSet: %s\n", 
			         knot_strerror(ret));
			return ret;
		}
		
		/* Merge the UPDATE RR to the copied RRSIG
		 * RRSet.
		 */
		dbg_ddns_detail("Merging RRSIG to the one in the RRSet.\n");

		int rdata_in_copy = knot_rrset_rdata_rr_count(*rr_copy);
		ret = knot_rrset_merge_no_dupl(
		    (void **)&rrsigs_copy, (void **)rr_copy);
		if (ret < 0) {
			dbg_xfrin("Failed to merge UPDATE RRSIG to copy: %s.\n",
			          knot_strerror(ret));
			return KNOT_ERROR;
		}
		
		knot_rrset_free(rr_copy);

		if (rdata_in_copy == ret) {
			/* All RDATA have been removed, because they were
			 * duplicates or there were none (0). In general this
			 * means, that no change was made.
			 */
			return 1;
		}
	} else {
		/* If there is no RRSIG RRSet yet, just add the
		 * UPDATE RR to the copied covered RRSet.
		 */
		/* Add the RRSet to 'changes'. */
		ret = knot_changes_add_new_rrsets(rr_copy, 1, changes, 1);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to store copy of the added RR: %s\n",
			         knot_strerror(ret));
			return ret;
		}
		
		/* Add the RRSet to the covered RRSet. */
		ret = knot_rrset_add_rrsigs(node_rrset_copy, *rr_copy,
		                            KNOT_RRSET_DUPL_SKIP);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add RRSIG RR to the"
			         " covered RRSet.\n");
			return ret;
		}
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \todo We should check, how it's possible that IXFR is not leaking due to the
 * same issue with merge. Or maybe it is, we should try it!!
 */

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_rr(knot_node_t *node, const knot_rrset_t *rr,
                            knot_changes_t *changes, knot_rrset_t **rr_copy)
{
	assert(node != NULL);
	assert(rr != NULL);
	assert(changes != NULL);
	assert(rr_copy != NULL);
	
	/* Copy the RRSet from the packet. */
	//knot_rrset_t *rr_copy;
	int ret = knot_rrset_deep_copy(rr, rr_copy, 1);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy RR: %s\n", knot_strerror(ret));
		return ret;
	}
	
	uint16_t type = knot_rrset_type(rr);
	uint16_t type_covered = (type == KNOT_RRTYPE_RRSIG) 
	                ? knot_rdata_rrsig_type_covered(knot_rrset_rdata(rr))
	                : type;
	
	/* If the RR belongs to a RRSet already present in the node, we must
	 * take this RRSet from the node, copy it, and merge this RR into it.
	 *
	 * This code is more or less copied from xfr-in.c.
	 */
	knot_rrset_t *node_rrset_copy = NULL;
	ret = xfrin_copy_rrset(node, type_covered, &node_rrset_copy, changes, 
	                       0);
	
	if (node_rrset_copy == NULL) {
		/* No such RRSet in the node. Add the whole UPDATE RRSet. */
		dbg_ddns_detail("Adding whole UPDATE RR to the zone.\n");
		if (type_covered != type) {
			/* Adding RRSIG. */
			ret = knot_ddns_add_rr_new_rrsig(node, *rr_copy, 
			                                 changes, type_covered);
		} else {
			ret = knot_ddns_add_rr_new_normal(node, *rr_copy, 
			                                  changes);
		}
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add new RR to node.\n");
			return ret;
		}
	} else {
		/* We have copied the RRSet from the node. */
dbg_ddns_exec_detail(
		dbg_ddns_detail("Merging RR to an existing RRSet.\n");
		knot_rrset_dump(node_rrset_copy, 1);
		dbg_ddns_detail("New RR:\n");
		knot_rrset_dump(*rr_copy, 0);
);
		
		if (type_covered != type) {
			/* Adding RRSIG. */
			ret = knot_ddns_add_rr_merge_rrsig(node_rrset_copy,
			                                   rr_copy, changes);
		} else {
			ret = knot_ddns_add_rr_merge_normal(node_rrset_copy,
			                                    rr_copy);
		}

dbg_ddns_exec_detail(
		dbg_ddns_detail("After merge:\n");
		knot_rrset_dump(node_rrset_copy, 1);
);

		if (ret < KNOT_EOK) {
			dbg_ddns("Failed to merge UPDATE RR to node RRSet.\n");
			knot_rrset_deep_free(rr_copy, 1, 1, 1);
			knot_rrset_deep_free(&node_rrset_copy, 1, 1, 1);
			return ret;
		}
		
		// save the new RRSet together with the new RDATA to 'changes'
		// do not overwrite 'ret', it have to be returned
		int r = knot_changes_add_new_rrsets(&node_rrset_copy, 1,
		                                    changes, 1);
		if (r != KNOT_EOK) {
			dbg_ddns("Failed to store RRSet copy to 'changes'\n");
			knot_rrset_deep_free(&node_rrset_copy, 1, 1, 1);
			return r;
		}
	}
	
	assert(ret >= 0);
	return ret;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_final_soa_to_chgset(const knot_rrset_t *soa,
                                         knot_changeset_t *changeset)
{
	assert(soa != NULL);
	assert(changeset != NULL);
	
	knot_rrset_t *soa_copy = NULL;
	int ret = knot_rrset_deep_copy(soa, &soa_copy, 1);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy SOA RR to the changeset: "
			 "%s\n", knot_strerror(ret));
		return ret;
	}
	
	knot_changeset_store_soa(&changeset->soa_to,
	                         &changeset->serial_to,
	                         soa_copy);
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_add_rr_to_chgset(const knot_rrset_t *rr,
                                      knot_changeset_t *changeset)
{
	assert(rr != NULL);
	assert(changeset != NULL);
	
	int ret = 0;
	knot_rrset_t *chgset_rr = NULL;
	knot_ddns_check_add_rr(changeset, rr, &chgset_rr);
	if (chgset_rr == NULL) {
		ret = knot_rrset_deep_copy(rr, &chgset_rr, 1);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy RR to the changeset: "
				 "%s\n", knot_strerror(ret));
			return ret;
		}
		/* No such RR in the changeset, add it. */
		ret = knot_changeset_add_rrset(&changeset->add,
		                               &changeset->add_count,
		                               &changeset->add_allocated,
		                               chgset_rr);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&chgset_rr, 1, 1, 1);
			dbg_ddns("Failed to add RR to changeset: %s.\n",
				 knot_strerror(ret));
			return ret;
		}
	} else {
		knot_rrset_deep_free(&chgset_rr, 1, 1, 1);
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_add(const knot_rrset_t *rr,
                                 knot_node_t *node,
                                 knot_zone_contents_t *zone,
                                 knot_changeset_t *changeset,
                                 knot_changes_t *changes,
                                 knot_rrset_t **rr_copy)
{
	assert(rr != NULL);
	assert(zone != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);
	assert(rr_copy != NULL);
	
	dbg_ddns_verb("Adding RR.\n");

	if (node == NULL) {
		// create new node, connect it properly to the
		// zone nodes
		dbg_ddns_detail("Node not found. Creating new.\n");
		node = knot_ddns_add_new_node(zone, knot_rrset_get_owner(rr),
		                              knot_ddns_rr_is_nsec3(rr));
		if (node == NULL) {
			dbg_xfrin("Failed to create new node in zone.\n");
			return KNOT_ERROR;
		}
	}
	
	uint16_t type = knot_rrset_type(rr);
	*rr_copy = NULL;
	int ret = 0;
	
	/*
	 * First, rule out special cases: CNAME, SOA and adding to CNAME node.
	 */
	if (type == KNOT_RRTYPE_CNAME) {
		/* 1) CNAME */
		ret = knot_ddns_process_add_cname(node, rr, changeset, changes);
	} else if (type == KNOT_RRTYPE_SOA) {
		/* 2) SOA */
		ret = knot_ddns_process_add_soa(node, rr, changes);
	} else if (knot_node_rrset(node, KNOT_RRTYPE_CNAME) != NULL) {
		/*
		 * Adding RR to CNAME node. Ignore the UPDATE RR.
		 *
		 * TODO: This may or may not be according to the RFC, it's quite
		 * unclear (see 3.4.2.2)
		 */
		return KNOT_EOK;
	}
	
	if (ret == 1) {
		dbg_ddns_detail("Ignoring the added RR.\n");
		// Ignore
		return KNOT_EOK;
	} else if (ret != KNOT_EOK) {
		dbg_ddns_detail("Adding RR failed.\n");
		return ret;
	}
	
	/*
	 * In all other cases, the RR should just be added to the node.
	 */
	
	/* Add the RRSet to the node (RRSIGs handled in the function). */
	dbg_ddns_detail("Adding RR to the node.\n");
	ret = knot_ddns_add_rr(node, rr, changes, rr_copy);
	if (ret < 0) {
		dbg_ddns("Failed to add RR to the node.\n");
		return ret;
	}
	
	/*
	 * If adding SOA, it should not be stored in the changeset.
	 * (This is done in the calling function, and the SOA is stored in the
	 * soa_final field.)
	 */
	if (type == KNOT_RRTYPE_SOA) {
		return KNOT_EOK;
	}
	
	/* Add the RR to ADD section of the changeset. */
	/* If the RR was previously removed, do not add it to the 
	 * changeset, and remove the entry from the REMOVE section.
	 *
	 * If there was no change (i.e. all RDATA were duplicates), do not add
	 * the RR to the changeset.
	 */
	if (ret == KNOT_EOK) {
		dbg_ddns_detail("Adding RR to the changeset.\n");
		ret = knot_ddns_add_rr_to_chgset(rr, changeset);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add the UPDATE RR to the changeset."
			         "\n");
			return ret;
		}
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/
/*!
 * \todo Geez, this is soooooo long even I don't exactly know what it does...
 *       Refactor!
 */
static int knot_ddns_process_rem_rr(const knot_rrset_t *rr,
                                    knot_node_t *node,
                                    knot_zone_contents_t *zone,
                                    knot_changeset_t *changeset,
                                    knot_changes_t *changes, uint16_t qclass)
{
	assert(rr != NULL);
	assert(node != NULL);
	assert(zone != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);

	uint16_t type = knot_rrset_type(rr);
	dbg_ddns_verb("Removing one RR.\n");

	/*
	 * When doing changes to RRSets, we must:
	 * 1) Copy the RRSet (same as in IXFR changeset applying, maybe the
	 *    function xfrin_copy_rrset() may be used for this).
	 * 2) Remove the RDATA (in this case only one). Check if it is not the
	 *    last NS RR in the zone.
	 * 3) Store the removed RDATA in 'changes'.
	 * 4) If the RRSet is empty, remove it and store in 'changes'.
	 * 5) Check redundant RRs in changeset.
	 * 6) Store the RRSet containing the one RDATA in the changeset. We may
	 *    use the RRSet from the packet for this - copy it, set CLASS
	 *    and TTL.
	 *
	 * Special handling of RRSIGs is required in that the RRSet containing
	 * them must be copied as well. However, copying of RRSet copies also
	 * the RRSIGs, so copying the base RRSet is enough for both cases!
	 */

	assert(type != KNOT_RRTYPE_SOA);
	int is_apex = knot_node_rrset(node, KNOT_RRTYPE_SOA) != NULL;
	
	/* If removing NS from an apex and there is only one NS left, ignore
	 * this removal right away. We do not have to check if the RRs match:
	 * - if they don't match, the removal will be ignored
	 * - if they match, the last NS cannot be removed anyway.
	 */
	if (is_apex && type == KNOT_RRTYPE_NS
	    && knot_rrset_rdata_rr_count(knot_node_rrset(node, type)) == 1) {
		return KNOT_EOK;
	}

	/*
	 * 1) Copy the RRSet.
	 */
	uint16_t type_to_copy = (type != KNOT_RRTYPE_RRSIG) ? type
	                : knot_rdata_rrsig_type_covered(knot_rrset_rdata(rr));
	knot_rrset_t *rrset_copy = NULL;
	int ret = xfrin_copy_rrset(node, type_to_copy, &rrset_copy, changes, 1);
	if (ret < 0) {
		dbg_ddns("Failed to copy RRSet for removal: %s\n",
		         knot_strerror(ret));
		return ret;
	}

	if (rrset_copy == NULL) {
		dbg_ddns_verb("RRSet not found.\n");
		return KNOT_EOK;
	}
	
	/*
	 * Set some variables needed, according to the modified RR type.
	 */
	
	int rdata_count;
	knot_rrset_t *to_modify;
	if (type == KNOT_RRTYPE_RRSIG) {
		rdata_count = knot_rrset_rdata_rr_count(
		                        knot_rrset_rrsigs(rrset_copy));
		to_modify = knot_rrset_get_rrsigs(rrset_copy);
	} else {
		rdata_count = knot_rrset_rdata_rr_count(rrset_copy);
		to_modify = rrset_copy;
	}
	
	/*
	 * 1.5) Prepare place for the removed RDATA.
	 *      We don't know if there are some, but if this fails, at least we
	 *      haven't removed them yet.
	 */
	ret = knot_changes_rdata_reserve(&changes->old_rdata,
	                                 &changes->old_rdata_types,
	                                 changes->old_rdata_count,
	                                 &changes->old_rdata_allocated, 
	                                 rdata_count);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to reserve place for RDATA.\n");
		return ret;
	}

	/*
	 * 2) Remove the proper RDATA from the RRSet copy, or its RRSIGs.
	 */
	knot_rdata_t *removed = knot_rrset_remove_rdata(to_modify, 
	                                                knot_rrset_rdata(rr));

	/* No such RR in the RRSet. */
	if (removed == NULL) {
		dbg_ddns_detail("No such RR found to be removed.\n");
		return KNOT_EOK;
	}

	/* If we removed NS from apex, there should be at least one more. */
	assert(!is_apex || type != KNOT_RRTYPE_NS 
	       || knot_rrset_rdata(rrset_copy) != NULL);

	/*
	 * 3) Store the removed RDATA in 'changes'.
	 */
	knot_changes_add_rdata(changes->old_rdata, changes->old_rdata_types,
	                       &changes->old_rdata_count, removed, type);

	/*
	 * 4) If the RRSet is empty, remove it and store in 'changes'.
	 *    Do this also if the RRSIGs are empty. 
	 *    And if both are empty, remove both.
	 */
	if (type == KNOT_RRTYPE_RRSIG 
	    && knot_rrset_rdata(to_modify) == NULL) {
		/* Empty RRSIGs, remove the RRSIG RRSet */
		ret = knot_changes_rrsets_reserve(&changes->old_rrsets,
		                                 &changes->old_rrsets_count,
		                                 &changes->old_rrsets_allocated,
		                                 1);
		if (ret == KNOT_EOK) {
			knot_rrset_t *rrsig = knot_rrset_get_rrsigs(rrset_copy);
			dbg_xfrin_detail("Removed RRSIG RRSet (%p).\n", rrsig);
			
			assert(rrsig == to_modify);

			// add the removed RRSet to list of old RRSets
			changes->old_rrsets[changes->old_rrsets_count++]
			                = rrsig;
			
			// remove it from the RRSet
			knot_rrset_set_rrsigs(rrset_copy, NULL);
		} else {
			dbg_ddns("Failed to reserve space for empty RRSet.\n");
		}
	}
	
	/*! \note Copied from xfr-in.c - maybe extract to some function. */
	/*! \note This is not needed as rrset is already on the old_rrsets */
//	if (knot_rrset_rdata(rrset_copy) == NULL
//	    && knot_rrset_rrsigs(rrset_copy) == NULL) {
//		// The RRSet should not be empty if we were removing NSs from
//		// apex in case of DDNS
//		assert(!is_apex);

//		ret = knot_changes_rrsets_reserve(&changes->old_rrsets,
//		                                 &changes->old_rrsets_count,
//		                                 &changes->old_rrsets_allocated,
//		                                 1);
//		if (ret == KNOT_EOK) {
//			knot_rrset_t *tmp = knot_node_remove_rrset(node, type);
//			dbg_xfrin_detail("Removed whole RRSet (%p).\n", tmp);

//			assert(tmp == rrset_copy);

//			// add the removed RRSet to list of old RRSets
//			changes->old_rrsets[changes->old_rrsets_count++]
//			                = rrset_copy;
//		} else {
//			dbg_ddns("Failed to reserve space for empty RRSet.\n");
//		}
//	}

	/*
	 * 5) Check if the RR is not in the ADD section. If yes, remove it
	 *    from there and do not add it to the REMOVE section.
	 */
	knot_rrset_t **from_chgset = NULL;
	size_t from_chgset_count = 0;
	ret = knot_ddns_check_remove_rr2(changeset, knot_node_owner(node),
	                                 type, knot_rrset_rdata(rr),
	                                 &from_chgset, &from_chgset_count);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to remove possible redundant RRs from ADD "
		         "section: %s.\n", knot_strerror(ret));
		free(from_chgset);
		return ret;
	}

	assert(from_chgset_count <= 1);

	if (from_chgset_count == 1) {
		/* Just delete the RRSet. */
		knot_rrset_deep_free(&(from_chgset[0]), 1, 1, 1);

		/* Finish processing, no adding to changeset. */
		free(from_chgset);
		return KNOT_EOK;
	}
	
	free(from_chgset);

	/*
	 * 6) Store the RRSet containing the one RDATA in the changeset. We may
	 *    use the RRSet from the packet for this - copy it, set CLASS
	 *    and TTL.
	 */
	knot_rrset_t *to_chgset = NULL;
	ret = knot_rrset_deep_copy(rr, &to_chgset, 1);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy RRSet from packet to changeset.\n");
		return ret;
	}
	knot_rrset_set_class(to_chgset, qclass);
	knot_rrset_set_ttl(to_chgset, knot_rrset_ttl(to_modify));

	ret = knot_changeset_add_rrset(&changeset->remove,
	                               &changeset->remove_count,
	                               &changeset->remove_allocated,
	                               to_chgset);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to store the RRSet copy to changeset: %s.\n",
		         knot_strerror(ret));
		knot_rrset_deep_free(&to_chgset, 1, 1, 1);
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_rrsig(knot_node_t *node,
                                       knot_rrset_t *rrset,
                                       knot_changes_t *changes,
                                       knot_rrset_t **rrsig)
{
	assert(node != NULL);
	assert(rrset != NULL);
	assert(changes != NULL);
	
	knot_rrset_t *rrset_copy = NULL;
	
	/* Copy RRSet. */
	int ret = xfrin_copy_old_rrset(rrset, &rrset_copy, changes, 1);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy RRSet from node: %s.\n",
		         knot_strerror(ret));
		return ret;
	}
	
	/* Remove RRSIGs from the copy. */
	*rrsig = knot_rrset_get_rrsigs(rrset_copy);
	if (*rrsig != NULL) {
		knot_rrset_set_rrsigs(rrset_copy, NULL);
	}
	
	/* Put the copy to the node. */
	ret = knot_node_add_rrset(node, rrset_copy, 0);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to add RRSet copy to the node: %s\n",
		         knot_strerror(ret));
		knot_rrset_deep_free(&rrset_copy, 1, 1, 1);
		return ret;
	}
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_rrsigs(knot_node_t *node, 
                                        knot_changes_t *changes, 
                                        knot_rrset_t ***removed,
                                        size_t *removed_count)
{
	assert(node != NULL);
	assert(removed != NULL);
	assert(removed_count != NULL);
	assert(changes != NULL);
	
	/* If removing RRSIGs, we must remove them from all RRSets in 
	 * the node. This means to copy all RRSets and then remove the 
	 * RRSIGs from them.
	 */
	dbg_ddns_verb("Removing all RRSIGs from node.\n");
	
	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	if (rrsets == NULL) {
		// No RRSets in the node, nothing to remove
		return KNOT_EOK;
	}
	
	/* Allocate space for the removed RRSIGs. There may be as many as there
	 * are RRSets.
	 */
	short rrset_count = knot_node_rrset_count(node);
	
	*removed = malloc(rrset_count * sizeof(knot_rrset_t *));
	CHECK_ALLOC_LOG(*removed, KNOT_ENOMEM);
	*removed_count = 0;
	
	/* Remove all the RRSets from the node, so that we may insert the copies
	 * right away.
	 */
	knot_node_remove_all_rrsets(node);
	
	knot_rrset_t *rrsig = NULL;
	int ret = 0;
	for (int i = 0; i < rrset_count; ++i) {
		ret = knot_ddns_process_rem_rrsig(node, rrsets[i], changes,
		                                  &rrsig);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to remove RRSIG.\n");
			return ret;
		}
		/* Store the RRSIGs to the array of removed RRSets. */
		(*removed)[(*removed_count)++] = rrsig;
	}
	
	free(rrsets);
	
	
	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_rrset(uint16_t type,
                                       knot_node_t *node,
                                       knot_changeset_t *changeset,
                                       knot_changes_t *changes)
{
	assert(node != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);

	/*! \note
	 * We decided to automatically remove RRSIGs together with the removed
	 * RRSet as they are no longer valid or required anyway. 
	 *
	 * Also refer to RFC3007, section 4.3:
	 *   'When the contents of an RRset are updated, the server MAY delete 
	 *    all associated SIG records, since they will no longer be valid.'
	 *
	 * (Although we are compliant with this RFC only selectively. The next
	 * section says: 'If any changes are made, the server MUST, if 
	 * necessary, generate a new SOA record and new NXT records, and sign 
	 * these with the appropriate zone keys.' and we are definitely not 
	 * doing this...
	 *
	 * \todo Document!!
	 */

	// this should be ruled out before
	assert(type != KNOT_RRTYPE_SOA);

	if (knot_node_rrset(node, KNOT_RRTYPE_SOA) != NULL
	    && type == KNOT_RRTYPE_NS) {
		// if removing NS from apex, ignore
		return KNOT_EOK;
	}
	
	knot_rrset_t **removed = NULL;
	size_t removed_count = 0;
	int ret = 0;
	
	if (type == KNOT_RRTYPE_RRSIG) {
		/* Remove all RRSIGs from the node. */
		ret = knot_ddns_process_rem_rrsigs(node, changes, &removed,
		                                   &removed_count);
	} else {
		/* Remove the RRSet from the node. */
		removed = malloc(sizeof(knot_rrset_t *));
		if (!removed) {
			ERR_ALLOC_FAILED;
			return KNOT_ENOMEM;
		}

		dbg_ddns_detail("Removing RRSet of type: %d\n", type);
		
		*removed = knot_node_remove_rrset(node, type);
		removed_count = 1;
	}

	dbg_ddns_detail("Removed: %p (first item: %p), removed count: %d\n",
	                removed, (removed == NULL) ? "none" : *removed,
	                removed_count);

	// no such RR
	if (removed_count == 0 || removed == NULL) {
		// ignore
		return KNOT_EOK;
	}

	/* 2) Store them to 'changes' for later deallocation, together with
	 *    their RRSIGs. 
	 */
	ret = knot_changes_add_old_rrsets(removed, removed_count, changes, 1);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to add removed RRSet to 'changes': %s.\n",
		         knot_strerror(ret));
		free(removed);
		return ret;
	}

	/* 3) Copy the RRSets, so that they can be stored to the changeset. */
	knot_rrset_t **to_chgset = malloc(removed_count 
	                                  * sizeof(knot_rrset_t *));
	if (to_chgset == NULL) {
		dbg_ddns("Failed to allocate space for RRSets going to "
		         "changeset.\n");
		free(removed);
		return KNOT_ENOMEM;
	}
	
	for (int i = 0; i < removed_count; ++i) {
		ret = knot_rrset_deep_copy(removed[i], &to_chgset[i], 1);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy the removed RRSet: %s.\n",
			         knot_strerror(ret));
			for (int j = 0; j < i; ++j) {
				knot_rrset_deep_free(&to_chgset[j], 1, 1, 1);
			}
			free(to_chgset);
			free(removed);
			return ret;
		}
	}
	
	free(removed);

	/* 4) But we must check if some of the RRs were not previously added
	 *    by the same UPDATE. If yes, these must be removed from the ADD
	 *    section of the changeset and also from this RRSet copy (so they
	 *    are neither stored in the REMOVE section of the changeset).
	 */
	knot_rrset_t **from_chgset = NULL;
	size_t from_chgset_count = 0;

	/* 4 a) Remove redundant RRs from the ADD section of the changeset. */
	ret = knot_ddns_check_remove_rr2(changeset, knot_node_owner(node), type,
	                                 NULL, &from_chgset,
	                                 &from_chgset_count);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to remove possible redundant RRs from ADD "
		         "section: %s.\n", knot_strerror(ret));
		for (int i = 0; i < removed_count; ++i) {
			knot_rrset_deep_free(&to_chgset[i], 1, 1, 1);
		}
		free(from_chgset);
		free(to_chgset);
		return ret;
	}

	/* 4 b) Remove these RRs from the copy of the RRSets removed from zone*/
	knot_rdata_t *rem = NULL;
	for (int j = 0; j < removed_count; ++j) {
		/* In each RRSet removed from the node (each can have more
		 * RDATAs) ...
		 */
		for (int i = 0; i < from_chgset_count; ++i) {
			/* ...try to remove redundant RDATA. Each RRSet in
			 * 'from_chgset' contains only one RDATA.
			 */
			rem = knot_rrset_remove_rdata(to_chgset[j], 
			                              knot_rrset_rdata(
			                                  from_chgset[i]));
			/* And delete it right away, no use for that. */
			knot_rdata_deep_free(&rem, knot_rrset_type(
			                             from_chgset[i]), 1);
		}
	}
	
	/* The array is cleared, we may delete the redundant RRs. */
	for (int i = 0; i < from_chgset_count; ++i) {
		knot_rrset_deep_free(&from_chgset[i], 1, 1, 1);
	}
	free(from_chgset);

	/* 5) Store the remaining RRSet to the changeset. Do not try to merge
	 *    to some previous RRSet, there should be none.
	 */
	for (int i = 0; i < removed_count; ++i) {
		ret = knot_changeset_add_rrset(&changeset->remove,
		                               &changeset->remove_count,
		                               &changeset->remove_allocated,
		                               to_chgset[i]);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to store the RRSet copy to changeset: "
			         "%s.\n", knot_strerror(ret));
			for (int j = i; j < removed_count; ++j) {
				knot_rrset_deep_free(&to_chgset[j], 1, 1, 1);
			}
			free(to_chgset);
			return ret;
		}
	}
	
	free(to_chgset);

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_all(knot_node_t *node,
                                     knot_changeset_t *changeset,
                                     knot_changes_t *changes)
{
	assert(node != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);

	/*! \note
	 * This basically means to call knot_ddns_process_rem_rrset() for every
	 * type present in the node.
	 *
	 * In case of SOA and NS in apex, the RRSets should not be removed, but
	 * what about their RRSIGs??
	 *
	 * If the zone has to remain properly signed, the UPDATE will have to 
	 * contain at least new SOA and RRSIGs for it (as the auto-incremented
	 * SOA would not be signed). So it should not matter if we leave the 
	 * RRSIGs there or not. But in case of the NSs it's not that clear.
	 *
	 * For now, we will leave the RRSIGs there. It's easier to implement.
	 * 
	 * \todo Should document this!!
	 */
	int ret = 0;
	knot_rrset_t **rrsets = knot_node_get_rrsets(node);
	int count = knot_node_rrset_count(node);

	if (rrsets == NULL && count != 0) {
		dbg_ddns("Failed to fetch RRSets from node.\n");
		return KNOT_ENOMEM;
	}

	int is_apex = knot_node_rrset(node, KNOT_RRTYPE_SOA) != NULL;

	dbg_ddns_verb("Removing all RRSets (count: %d).\n", count);
	for (int i = 0; i < count; ++i) {
		// If the node is apex, skip NS and SOA
		if (is_apex &&
		    (knot_rrset_type(rrsets[i]) == KNOT_RRTYPE_SOA
		     || knot_rrset_type(rrsets[i]) == KNOT_RRTYPE_NS)) {
			/* Do not remove these RRSets, nor their RRSIGs. */
			continue;
		}

		ret = knot_ddns_process_rem_rrset(knot_rrset_type(rrsets[i]),
		                                  node, changeset, changes);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to remove RRSet: %s\n",
			         knot_strerror(ret));
			free(rrsets);
			return ret;
		}
	}
	
	free(rrsets);

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
		                             changes, rr_copy);
	} else if (node == NULL) {
		// Removing from non-existing node, just ignore the entry
		return KNOT_EOK;
	} else if (knot_rrset_class(rr) == KNOT_CLASS_NONE) {
		return knot_ddns_process_rem_rr(rr, node, zone, changeset,
		                                changes, qclass);
	} else if (knot_rrset_class(rr) == KNOT_CLASS_ANY) {
		if (knot_rrset_type(rr) == KNOT_RRTYPE_ANY) {
			return knot_ddns_process_rem_all(node, changeset,
			                                 changes);
		} else {
			return knot_ddns_process_rem_rrset(knot_rrset_type(rr),
			                                   node, changeset, 
			                                   changes);
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
		                        knot_rrset_rdata(rr)), sn_new) < 0)) {
			// This ignores also SOA removals
			dbg_ddns_verb("Ignoring SOA...\n");
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
			dbg_ddns_verb("Replacing SOA. Old serial: %d, new "
			              "serial: %d\n", sn_new, sn_rr);
			assert(ns_serial_compare(sn_rr, sn_new) >= 0);
			assert(rr_copy != NULL);
			sn_new = sn_rr;
			soa_end = (knot_rrset_t *)rr_copy;
		}
	}

	/* Ending SOA (not in the UPDATE) */
	if (soa_end == NULL) {
		/* If the changeset is empty, do not process anything further 
		 * and indicate this to the caller, so that the changeset is not
		 * saved and zone is not switched.
		 */
		if (knot_changeset_is_empty(changeset)) {
			return 1;
		}
		
		/* If not set, create new SOA. */
		assert(sn_new == (uint32_t)sn + 1);
		ret = knot_rrset_deep_copy(soa, &soa_end, 1);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy ending SOA: %s\n",
			         knot_strerror(ret));
			*rcode = KNOT_RCODE_SERVFAIL;
			return ret;
		}
		knot_rdata_t *rd = knot_rrset_get_rdata(soa_end);
		knot_rdata_soa_serial_set(rd, sn_new);
		
		/* And replace it in the zone. */
		ret = xfrin_replace_rrset_in_node(
		                        knot_zone_contents_get_apex(zone),
		                        soa_end, changes, zone);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy replace SOA in zone: %s\n",
			         knot_strerror(ret));
			*rcode = KNOT_RCODE_SERVFAIL;
			return ret;
		}
	}

	ret = knot_ddns_final_soa_to_chgset(soa_end, changeset);

	return ret;
}
