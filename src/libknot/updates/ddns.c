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
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include "libknot/updates/ddns.h"
#include "libknot/updates/changesets.h"
#include "libknot/rdata.h"
#include "libknot/util/debug.h"
#include "libknot/packet/packet.h"
#include "libknot/common.h"
#include "libknot/consts.h"
#include "common/mempattern.h"
#include "libknot/nameserver/name-server.h"  // ns_serial_compare() - TODO: extract
#include "libknot/updates/xfr-in.h"
#include "common/descriptor.h"

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
		if (knot_rrset_equal(rrset, (*rrsets)[i],
		                     KNOT_RRSET_COMPARE_HEADER)) {
			ret = knot_rrset_merge((*rrsets)[i], rrset);
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

	knot_dname_t *dname_new = knot_dname_copy(dname);
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
		dbg_ddns("ddns: add_prereq: Wrong TTL.\n");
		return KNOT_EMALF;
	}

	int ret;

	if (knot_rrset_class(rrset) == KNOT_CLASS_ANY) {
		if (knot_rrset_rdata_rr_count(rrset)) {
			dbg_ddns("ddns: add_prereq: Extra data\n");
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
		if (knot_rrset_rdata_rr_count(rrset)) {
			dbg_ddns("ddns: add_prereq: Extra data\n");
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
		dbg_ddns("ddns: add_prereq: Bad class.\n");
		return KNOT_EMALF;
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
	assert(knot_rrset_rdata_rr_count(rrset) == 0);
	assert(knot_rrset_type(rrset) != KNOT_RRTYPE_ANY);
	assert(knot_rrset_ttl(rrset) == 0);
	assert(knot_rrset_class(rrset) == KNOT_CLASS_ANY);

	if (!knot_dname_is_sub(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
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
	assert(knot_rrset_type(rrset) != KNOT_RRTYPE_ANY);
	assert(knot_rrset_ttl(rrset) == 0);

	if (!knot_dname_is_sub(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
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
		assert(knot_dname_cmp(knot_rrset_owner(found),
		                          knot_rrset_owner(rrset)) == 0);
		if (knot_rrset_rdata_equal(found, rrset) <= 0) {
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
	assert(knot_rrset_rdata_rr_count(rrset) == 0);
	assert(knot_rrset_type(rrset) != KNOT_RRTYPE_ANY);
	assert(knot_rrset_ttl(rrset) == 0);
	assert(knot_rrset_class(rrset) == KNOT_CLASS_NONE);

	if (!knot_dname_is_sub(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
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

	if (!knot_dname_is_sub(dname,
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
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

	if (!knot_dname_is_sub(dname,
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
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
		dbg_ddns_detail("Creating prereqs from following RRSet:\n");
		knot_rrset_dump(knot_packet_answer_rrset(query, i));
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
	int is_sub = knot_dname_is_sub(owner, qname);
	if (!is_sub && knot_dname_cmp(owner, qname) != 0) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}
	
	if (knot_rrtype_is_ddns_forbidden(rrset->type)) {
		*rcode = KNOT_RCODE_REFUSED;
		log_zone_error("Refusing to update DNSSEC-related record!\n");
		return KNOT_EDENIED;
	}

	if (knot_rrset_class(rrset) == knot_packet_qclass(query)) {
		if (knot_rrtype_is_metatype(knot_rrset_type(rrset))) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (knot_rrset_class(rrset) == KNOT_CLASS_ANY) {
		if (knot_rrset_rdata_rr_count(rrset)
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

void knot_ddns_prereqs_free(knot_ddns_prereq_t **prereq)
{
	dbg_ddns("Freeing prerequisities.\n");

	int i;

	for (i = 0; i < (*prereq)->exist_count; ++i) {
		knot_rrset_deep_free(&(*prereq)->exist[i], 1);
	}
	free((*prereq)->exist);

	for (i = 0; i < (*prereq)->exist_full_count; ++i) {
		knot_rrset_deep_free(&(*prereq)->exist_full[i], 1);
	}
	free((*prereq)->exist_full);

	for (i = 0; i < (*prereq)->not_exist_count; ++i) {
		knot_rrset_deep_free(&(*prereq)->not_exist[i], 1);
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
                                      const knot_rrset_t *rr,
                                      knot_rrset_t ***removed,
                                      size_t *removed_count)
{
	assert(changeset != NULL);
	assert(removed != NULL);
	assert(removed_count != NULL);

	/*!< \todo This seems like a waste of memory to me. Also, list_size takes a long time. */
	*removed_count = 0;
	*removed = (knot_rrset_t **)malloc(list_size(&changeset->add)
	                                  * sizeof(knot_rrset_t *));
	if (*removed == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	knot_rrset_t *remove = NULL;

	/*
	 * We assume that each RR in the ADD section of the changeset is in its
	 * own RRSet. It should be, as this is how they are stored there by the
	 * ddns_process_add() function.
	 */

	dbg_ddns_verb("Removing possible redundant RRs from changeset.\n");
	knot_rr_ln_t *rr_node = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(rr_node, nxt, changeset->add) {
		knot_rrset_t *rrset = rr_node->rr;
		// Removing RR(s) from this owner
dbg_ddns_exec_detail(
		char *name = knot_dname_to_str(rrset->owner);
		dbg_ddns_detail("ddns: remove_rr2: Removing RR of type=%u owned by %s\n",
		                knot_rrset_type(rrset), name);
		free(name);
);
		if (knot_dname_is_equal(knot_rrset_owner(rrset), owner)) {
			// Removing one or all RRSets
			if ((knot_rrset_rdata_rr_count(rr) == 0)
			    && (knot_rrset_type(rr) == knot_rrset_type(rrset)
			        || knot_rrset_type(rr) == KNOT_RRTYPE_ANY)) {
				dbg_ddns_detail("Removing one or all RRSets\n");
				remove = rrset;
				rem_node((node_t *)rr_node);
				(*removed)[(*removed_count)++] = remove;
			} else if (knot_rrset_type(rr) ==
			           knot_rrset_type(rrset)) {
				// Removing specific RR
				assert(knot_rrset_rdata_rr_count(rr) != 0);

				// We must check if the RDATA match
				if (knot_rrset_rdata_equal(rr,
				                           rrset)) {
					remove = rrset;
					rem_node((node_t *)rr_node);
					(*removed)[(*removed_count)++] = remove;
				}
			}
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
	knot_rr_ln_t *rr_node = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(rr_node, nxt, changeset->remove) {
		knot_rrset_t *rrset = rr_node->rr;
		assert(rrset);
		/* Just check exact match, the changeset contains only
		 * whole RRs that have been removed.
		 */
		if (knot_rrset_equal(rr, rrset,
		                     KNOT_RRSET_COMPARE_WHOLE) == 1) {
			*removed = rrset;
			rem_node((node_t *)rr_node);
			dbg_ddns_detail("Removed RRSet from chgset:\n");
			knot_rrset_dump(rrset);
			break;
		}
	}
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
	if (knot_rrset_is_nsec3rel(rr)) {
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
		if (knot_rrset_equal(removed, rr, KNOT_RRSET_COMPARE_WHOLE)
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
		ret = knot_changes_add_rrset(changes, removed, KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add removed RRSet to "
			         "'changes': %s\n", knot_strerror(ret));
			return ret;
		}

		if (removed->rrsigs) {
			ret = knot_changes_add_rrset(changes,
			                             removed->rrsigs,
			                             KNOT_CHANGES_OLD);
			if (ret != KNOT_EOK) {
				dbg_ddns("Failed to add removed RRSIGs to "
				         "'changes': %s\n", knot_strerror(ret));
				return ret;
			}
			/* Disconnect RRsigs from rrset. */
			knot_rrset_set_rrsigs(removed, NULL);
		}


		/* c) And remove it from the node. */
		UNUSED(knot_node_remove_rrset(node, KNOT_RRTYPE_CNAME));

		/* d) Check if this CNAME was not previously added by
		 *    the UPDATE. If yes, remove it from the ADD
		 *    section and do not add it to the REMOVE section.
		 */
		knot_rrset_t **from_chgset = NULL;
		size_t from_chgset_count = 0;
		ret = knot_ddns_check_remove_rr2(
		                   changeset, knot_rrset_owner(removed),
		                   removed, &from_chgset, &from_chgset_count);
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
			knot_rrset_deep_free(&(from_chgset[0]), 1);
			/* Okay, &(from_chgset[0]) is basically equal to just
			 * from_chgset, but it's more clear this way that we are
			 * deleting the first RRSet in the array ;-)
			 */
		} else {
			/* Otherwise copy the removed CNAME and add it
			 * to the REMOVE section.
			 */
			knot_rrset_t *removed_copy;
			ret = knot_rrset_deep_copy(removed, &removed_copy);
			if (ret != KNOT_EOK) {
				dbg_ddns("Failed to copy removed RRSet:"
				         " %s\n", knot_strerror(ret));
				free(from_chgset);
				return ret;
			}

			ret = knot_changeset_add_rrset(
				changeset, removed_copy, KNOT_CHANGESET_REMOVE);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&removed_copy,
				                     1);
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
		if (knot_rrset_equal(removed, rr, KNOT_RRSET_COMPARE_WHOLE)
		    == 1) {
			dbg_ddns_detail("Old and new SOA identical.\n");
			return 1;
		}

		/* Check that the serial is indeed larger than the current one*/
		assert(ns_serial_compare(knot_rdata_soa_serial(removed),
		                         knot_rdata_soa_serial(rr)) < 0);

		/* 1) Store it to 'changes', together with its RRSIGs. */
		ret = knot_changes_add_rrset(changes, removed, KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add removed RRSet to "
			         "'changes': %s\n", knot_strerror(ret));
			return ret;
		}

		if (removed->rrsigs) {
			ret = knot_changes_add_rrset(changes,
			                             removed->rrsigs,
			                             KNOT_CHANGES_OLD);
			if (ret != KNOT_EOK) {
				dbg_ddns("Failed to add removed RRSIGs to "
				         "'changes': %s\n", knot_strerror(ret));
				return ret;
			}
			/* Disconnect RRsigs from rrset. */
			knot_rrset_set_rrsigs(removed, NULL);
		}

		/* 2) And remove it from the node. */
		UNUSED(knot_node_remove_rrset(node, KNOT_RRTYPE_SOA));

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

	int ret = knot_changes_add_rrset(changes, rr_copy, KNOT_CHANGES_NEW);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rr_copy, 1);
		dbg_ddns("Failed to store copy of the added RR: "
		         "%s\n", knot_strerror(ret));
		return ret;
	}

	/* Add the RRSet to the node. */
	ret = knot_node_add_rrset_no_merge(node, rr_copy);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to add RR to node: %s\n", knot_strerror(ret));
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
	if (knot_rrset_rdata_rr_count(node_rrset_copy) == 0
	    && knot_rrset_ttl(node_rrset_copy)
	       != knot_rrset_ttl(*rr_copy)) {
		knot_rrset_set_ttl(node_rrset_copy,
		                   knot_rrset_ttl(*rr_copy));
	}

	int rdata_in_copy = knot_rrset_rdata_rr_count(*rr_copy);
	int merged = 0, deleted_rrs = 0;
	int ret = knot_rrset_merge_sort(node_rrset_copy, *rr_copy, &merged,
	                                &deleted_rrs);
	dbg_ddns_detail("Merge returned: %d\n", ret);

	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to merge UPDATE RR to node RRSet: %s."
		         "\n", knot_strerror(ret));
		return ret;
	}

	knot_rrset_deep_free(rr_copy, 1);


	if (rdata_in_copy == deleted_rrs) {
		/* All RDATA have been removed, because they were duplicates
		 * or there were none (0). In general this means, that no
		 * change was made.
		 */
		return 1;
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
	int ret = knot_rrset_deep_copy(rr, rr_copy);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy RR: %s\n", knot_strerror(ret));
		return ret;
	}

	/* If the RR belongs to a RRSet already present in the node, we must
	 * take this RRSet from the node, copy it, and merge this RR into it.
	 *
	 * This code is more or less copied from xfr-in.c.
	 */
	knot_rrset_t *node_rrset_copy = NULL;
	ret = xfrin_copy_rrset(node, rr->type, &node_rrset_copy, changes,
	                       0);

	if (node_rrset_copy == NULL) {
		/* No such RRSet in the node. Add the whole UPDATE RRSet. */
		dbg_ddns_detail("Adding whole UPDATE RR to the zone.\n");
		ret = knot_ddns_add_rr_new_normal(node, *rr_copy,
		                                  changes);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add new RR to node.\n");
			return ret;
		}
		dbg_ddns_detail("RRSet added successfully.\n");
	} else {
		/* We have copied the RRSet from the node. */
dbg_ddns_exec_detail(
		dbg_ddns_detail("Merging RR to an existing RRSet.\n");
		knot_rrset_dump(node_rrset_copy);
		dbg_ddns_detail("New RR:\n");
		knot_rrset_dump(*rr_copy);
);

		ret = knot_ddns_add_rr_merge_normal(node_rrset_copy, rr_copy);

dbg_ddns_exec_detail(
		dbg_ddns_detail("After merge:\n");
		knot_rrset_dump(node_rrset_copy);
);

		if (ret < KNOT_EOK) {
			dbg_ddns("Failed to merge UPDATE RR to node RRSet.\n");
			knot_rrset_deep_free(rr_copy, 1);
			knot_rrset_deep_free(&node_rrset_copy, 1);
			return ret;
		}

		// save the new RRSet together with the new RDATA to 'changes'
		// do not overwrite 'ret', it have to be returned
		int r = knot_changes_add_rrset(changes, node_rrset_copy,
		                               KNOT_CHANGES_NEW);
		if (r != KNOT_EOK) {
			dbg_ddns("Failed to store RRSet copy to 'changes'\n");
			knot_rrset_deep_free(&node_rrset_copy, 1);
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
	int ret = knot_rrset_deep_copy(soa, &soa_copy);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy SOA RR to the changeset: "
			 "%s\n", knot_strerror(ret));
		return ret;
	}

	knot_changeset_add_soa(changeset, soa_copy, KNOT_CHANGESET_ADD);

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
		ret = knot_rrset_deep_copy(rr, &chgset_rr);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy RR to the changeset: "
				 "%s\n", knot_strerror(ret));
			return ret;
		}
		/* No such RR in the changeset, add it. */
		ret = knot_changeset_add_rrset(changeset, chgset_rr,
		                               KNOT_CHANGESET_ADD);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&chgset_rr, 1);
			dbg_ddns("Failed to add RR to changeset: %s.\n",
				 knot_strerror(ret));
			return ret;
		}
	} else {
		knot_rrset_deep_free(&chgset_rr, 1);
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
		// create new node, connect it to the zone nodes
		dbg_ddns_detail("Node not found. Creating new.\n");
		int ret = knot_zone_contents_create_node(zone, rr, &node);
		if (ret != KNOT_EOK) {
			dbg_xfrin("Failed to create new node in zone.\n");
			return ret;
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
	knot_rrset_t *rrset_copy = NULL;
	int ret = xfrin_copy_rrset(node, type, &rrset_copy, changes, 1);
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

	knot_rrset_t *to_modify = rrset_copy;

	/*
	 * 2) Remove the proper RDATA from the RRSet copy
	 */
	knot_rrset_t *rr_remove = NULL;
	ret = knot_rrset_remove_rr_using_rrset(to_modify, rr, &rr_remove);
	if (ret != KNOT_EOK) {
		dbg_ddns("ddns: proces_rem_rr: Could not remove RDATA from"
		         " RRSet (%s).\n", knot_strerror(ret));
		return ret;
	}

	/* No such RR in the RRSet. */
	if (knot_rrset_rdata_rr_count(rr_remove) == 0) {
		knot_rrset_free(&rr_remove);
		dbg_ddns_detail("No such RR found to be removed.\n");
		return KNOT_EOK;
	}

	/* If we removed NS from apex, there should be at least one more. */
	assert(!is_apex || type != KNOT_RRTYPE_NS
	       || knot_rrset_rdata_rr_count(rrset_copy));

	/*
	 * 3) Store the removed data in 'changes'.
	 */
	ret = knot_changes_add_rrset(changes, rr_remove, KNOT_CHANGES_OLD);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&rr_remove, 1);
		dbg_ddns_detail("Failed to add data to changes.\n");
		return ret;
	}

	/*
	 * 4) If the RRSet is empty, remove it and store in 'changes'.
	 */
	if (knot_rrset_rdata_rr_count(to_modify) == 0) {
		// The RRSet should not be empty if we were removing NSs from
		// apex in case of DDNS
//		assert(!is_apex);
		// add the removed RRSet to list of old RRSets
		ret = knot_changes_add_rrset(changes, rrset_copy,
		                             KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add RRSet to changes.\n");
			return ret;
		}
		
		// Do the same with its RRSIGs (automatic drop)
		if (rrset_copy->rrsigs) {
			ret = knot_changes_add_rrset(changes,
			                             rrset_copy->rrsigs,
			                             KNOT_CHANGES_OLD);
			if (ret != KNOT_EOK) {
				dbg_ddns("Failed to add RRSet to changes.\n");
				return ret;
			}
		}
		knot_rrset_t *tmp = knot_node_remove_rrset(node, type);
		dbg_xfrin_detail("Removed whole RRSet (%p).\n", tmp);
		assert(tmp == rrset_copy);
	}

	/*
	 * 5) Check if the RR is not in the ADD section. If yes, remove it
	 *    from there and do not add it to the REMOVE section.
	 */
	knot_rrset_t **from_chgset = NULL;
	size_t from_chgset_count = 0;
	ret = knot_ddns_check_remove_rr2(changeset, knot_node_owner(node),
	                                 rr, &from_chgset, &from_chgset_count);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to remove possible redundant RRs from ADD "
		         "section: %s.\n", knot_strerror(ret));
		free(from_chgset);
		return ret;
	}

	assert(from_chgset_count <= 1);

	if (from_chgset_count == 1) {
		/* Just delete the RRSet. */
		knot_rrset_deep_free(&(from_chgset[0]), 1);

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
	ret = knot_rrset_deep_copy(rr, &to_chgset);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy RRSet from packet to changeset.\n");
		return ret;
	}
	knot_rrset_set_class(to_chgset, qclass);
	knot_rrset_set_ttl(to_chgset, knot_rrset_ttl(to_modify));

	ret = knot_changeset_add_rrset(changeset, to_chgset,
	                               KNOT_CHANGESET_REMOVE);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to store the RRSet copy to changeset: %s.\n",
		         knot_strerror(ret));
		knot_rrset_deep_free(&to_chgset, 1);
		return ret;
	}

	return KNOT_EOK;
}

/*----------------------------------------------------------------------------*/

static int knot_ddns_process_rem_rrset(const knot_rrset_t *rrset,
                                       knot_node_t *node,
                                       knot_changeset_t *changeset,
                                       knot_changes_t *changes)
{
	assert(node != NULL);
	assert(rrset != NULL);
	assert(changeset != NULL);
	assert(changes != NULL);

	uint16_t type = knot_rrset_type(rrset);

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

	/* Remove the RRSet from the node. */
	removed = malloc(sizeof(knot_rrset_t *));
	if (!removed) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	dbg_ddns_detail("Removing RRSet of type: %d\n", type);

	*removed = knot_node_remove_rrset(node, type);
	if (*removed != NULL) {
		removed_count = 1;
	} else {
		removed_count = 0;
	}

	dbg_ddns_detail("Removed: %p (first item: %p), removed count: %zu\n",
	                removed, (removed == NULL) ? (void *)"none" : *removed,
	                removed_count);

	// no such RR
	if (removed_count == 0) {
		// ignore
		free(removed);
		return KNOT_EOK;
	}

	/* 2) Store them to 'changes' for later deallocation, together with
	 *    their RRSIGs.
	 */
	for (uint i = 0; i < removed_count; ++i) {
		ret = knot_changes_add_rrset(changes, removed[i],
		                             KNOT_CHANGES_OLD);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to add removed "
			         "RRSet to 'changes': %s.\n",
			         knot_strerror(ret));
			free(removed);
			return ret;
		}

		if (removed[i]->rrsigs) {
			ret = knot_changes_add_rrset(changes,
			                             removed[i]->rrsigs,
			                             KNOT_CHANGES_OLD);
			if (ret != KNOT_EOK) {
				dbg_ddns("Failed to add removed RRSIGs to "
				         "'changes': %s\n", knot_strerror(ret));
				free(removed);
				return ret;
			}
			/* Disconnect RRsigs from rrset. */
			knot_rrset_set_rrsigs(removed[i], NULL);
		}
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
		ret = knot_rrset_deep_copy(removed[i], &to_chgset[i]);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy the removed RRSet: %s.\n",
			         knot_strerror(ret));
			for (int j = 0; j < i; ++j) {
				knot_rrset_deep_free(&to_chgset[j], 1);
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
	knot_dname_t *owner_copy = knot_dname_copy(rrset->owner);
	knot_rrset_t *empty_rrset =
		knot_rrset_new(owner_copy, type, rrset->rclass, rrset->ttl);
	if (empty_rrset == NULL) {
		free(to_chgset);
		knot_dname_free(&owner_copy);
		return KNOT_ENOMEM;
	}
	ret = knot_ddns_check_remove_rr2(changeset, knot_node_owner(node),
	                                 empty_rrset, &from_chgset,
	                                 &from_chgset_count);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to remove possible redundant RRs from ADD "
		         "section: %s.\n", knot_strerror(ret));
		for (int i = 0; i < removed_count; ++i) {
			knot_rrset_deep_free(&to_chgset[i], 1);
		}
		free(from_chgset);
		free(to_chgset);
		knot_rrset_free(&empty_rrset);
		return ret;
	}
	knot_rrset_free(&empty_rrset);

	/* 4 b) Remove these RRs from the copy of the RRSets removed from zone*/
	for (int j = 0; j < removed_count; ++j) {
		/* In each RRSet removed from the node (each can have more
		 * RDATAs) ...
		 */
		for (int i = 0; i < from_chgset_count; ++i) {
			/* ...try to remove redundant RDATA. Each RRSet in
			 * 'from_chgset' contains only one RDATA.
			 */
			ret = knot_rrset_remove_rr_using_rrset_del(to_chgset[j],
			                                  from_chgset[i]);
			if (ret != KNOT_EOK) {
				dbg_ddns("Failed to remove RR from RRSet"
				         "(%s).\n", knot_strerror(ret));
				free(from_chgset);
				free(to_chgset);
				return ret;
			}
		}
	}

	/* The array is cleared, we may delete the redundant RRs. */
	for (int i = 0; i < from_chgset_count; ++i) {
		knot_rrset_deep_free(&from_chgset[i], 1);
	}
	free(from_chgset);

	/* 5) Store the remaining RRSet to the changeset. Do not try to merge
	 *    to some previous RRSet, there should be none.
	 */
	for (int i = 0; i < removed_count; ++i) {
		ret = knot_changeset_add_rrset(changeset, to_chgset[i],
		                               KNOT_CHANGESET_REMOVE);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to store the RRSet copy to changeset: "
			         "%s.\n", knot_strerror(ret));
			for (int j = i; j < removed_count; ++j) {
				knot_rrset_deep_free(&to_chgset[j], 1);
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
		// If the node is apex, skip NS, SOA and DNSSEC records
		if (is_apex &&
		    (knot_rrset_type(rrsets[i]) == KNOT_RRTYPE_SOA
		     || knot_rrset_type(rrsets[i]) == KNOT_RRTYPE_NS
		     || knot_rrtype_is_ddns_forbidden(
		             knot_rrset_type(rrsets[i])))) {
			/* Do not remove these RRSets, nor their RRSIGs. */
			continue;
		}

		ret = knot_ddns_process_rem_rrset(rrsets[i], node, changeset,
		                                  changes);
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
			return knot_ddns_process_rem_rrset(rr, node, changeset,
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
int knot_ddns_process_update(knot_zone_contents_t *zone,
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
	ret = knot_rrset_deep_copy(soa, &soa_begin);
	if (ret == KNOT_EOK) {
		knot_changeset_add_soa(changeset, soa_begin,
		                       KNOT_CHANGESET_REMOVE);
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	/* Current SERIAL */
	int64_t sn = knot_rdata_soa_serial(soa_begin);
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
		        || ns_serial_compare(knot_rdata_soa_serial(rr),
		                             sn_new) < 0)) {
			// This ignores also SOA removals
			dbg_ddns_verb("Ignoring SOA...\n");
			continue;
		}

		dbg_ddns_verb("Processing RR %p...\n", rr);
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
			int64_t sn_rr = knot_rdata_soa_serial(rr);
			dbg_ddns_verb("Replacing SOA. Old serial: %"PRId64", "
			              "new serial: %"PRId64"\n", sn_new, sn_rr);
			assert(ns_serial_compare(sn_rr, sn_new) >= 0);
			assert(rr_copy != NULL);
			sn_new = sn_rr;
			soa_end = rr_copy;
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
		ret = knot_rrset_deep_copy_no_sig(soa, &soa_end);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy ending SOA: %s\n",
			         knot_strerror(ret));
			*rcode = KNOT_RCODE_SERVFAIL;
			return ret;
		}
		knot_rdata_soa_serial_set(soa_end, sn_new);

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
