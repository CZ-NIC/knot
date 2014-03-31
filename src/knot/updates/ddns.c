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
#include <stdlib.h>
#include <inttypes.h>

#include "knot/updates/ddns.h"
#include "knot/updates/changesets.h"
#include "knot/updates/xfr-in.h"
#include "knot/zone/semantic-check.h"
#include "libknot/rdata.h"
#include "common/debug.h"
#include "libknot/packet/pkt.h"
#include "libknot/common.h"
#include "libknot/consts.h"
#include "common/mempattern.h"
#include "common/descriptor.h"
#include "common/lists.h"

static bool rrset_empty(const knot_rrset_t *rrset)
{
	uint16_t rr_count = knot_rrset_rr_count(rrset);
	if (rr_count == 0) {
		return true;
	}
	if (rr_count == 1) {
		return knot_rrset_rr_size(rrset, 0) == 0;
	}
	return false;
}

static void rrset_list_clear(list_t *l)
{
	node_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		knot_rrset_free(&rrset, NULL);
		free(n);
	};
}

static int add_rr_to_list(list_t *l, const knot_rrset_t *rr)
{
	node_t *n;
	WALK_LIST(n, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		if (knot_rrset_equal(rr, rrset, KNOT_RRSET_COMPARE_HEADER)) {
			int ret = knot_rrset_merge_sort(rrset, rr, NULL,
			                                NULL, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
			return KNOT_EOK;
		}
	};

	knot_rrset_t *rr_copy = knot_rrset_cpy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}
	return ptrlist_add(l, rr_copy, NULL) != NULL ? KNOT_EOK : KNOT_ENOMEM;
}

static int knot_ddns_check_exist(const knot_zone_contents_t *zone,
                                 const knot_rrset_t *rrset, uint16_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(rrset->type != KNOT_RRTYPE_ANY);
	assert(rrset->rclass == KNOT_CLASS_ANY);

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
	} else if (!knot_node_rrtype_exists(node, rrset->type)) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_ENORRSET;
	}

	return KNOT_EOK;
}

static int knot_ddns_check_exist_full(const knot_zone_contents_t *zone,
                                      const knot_rrset_t *rrset,
                                      uint16_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(rrset->type != KNOT_RRTYPE_ANY);

	if (!knot_dname_is_sub(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	const knot_node_t *node;
	node = knot_zone_contents_find_node(zone, knot_rrset_owner(rrset));
	if (node == NULL) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else if (!knot_node_rrtype_exists(node, rrset->type)) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else {
		knot_rrset_t found = RRSET_INIT(node, rrset->type);
		// do not have to compare the header, it is already done
		assert(knot_rrset_type(&found) == rrset->type);
		assert(knot_dname_cmp(knot_rrset_owner(&found),
		                          knot_rrset_owner(rrset)) == 0);
		if (!knot_rrset_equal(&found, rrset, KNOT_RRSET_COMPARE_WHOLE)) {
			*rcode = KNOT_RCODE_NXRRSET;
			return KNOT_EPREREQ;
		}
	}

	return KNOT_EOK;
}

static int check_exists_in_list(list_t *l, const knot_zone_contents_t *zone,
                                uint16_t *rcode)
{
	node_t *n;
	WALK_LIST(n, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		int ret = knot_ddns_check_exist_full(zone, rrset, rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	};

	return KNOT_EOK;
}

static int knot_ddns_check_not_exist(const knot_zone_contents_t *zone,
                                     const knot_rrset_t *rrset,
                                     uint16_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(rrset->type != KNOT_RRTYPE_ANY);
	assert(rrset->rclass == KNOT_CLASS_NONE);

	if (!knot_dname_is_sub(knot_rrset_owner(rrset),
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	const knot_node_t *node;

	node = knot_zone_contents_find_node(zone, knot_rrset_owner(rrset));
	if (node == NULL) {
		return KNOT_EOK;
	} else if (!knot_node_rrtype_exists(node, rrset->type)) {
		return KNOT_EOK;
	}

	/* RDATA is always empty for simple RRset checks. */

	*rcode = KNOT_RCODE_YXRRSET;
	return KNOT_EPREREQ;
}

static int knot_ddns_check_in_use(const knot_zone_contents_t *zone,
                                  const knot_dname_t *dname,
                                  uint16_t *rcode)
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

static int knot_ddns_check_not_in_use(const knot_zone_contents_t *zone,
                                      const knot_dname_t *dname,
                                      uint16_t *rcode)
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

static int knot_ddns_check_prereq(const knot_rrset_t *rrset,
                                  uint16_t qclass,
                                  const knot_zone_contents_t *zone,
                                  uint16_t *rcode,
                                  list_t *rrset_list)
{
	if (knot_rrset_rr_ttl(rrset, 0) != 0) {
		dbg_ddns("ddns: add_prereq: Wrong TTL.\n");
		return KNOT_EMALF;
	}

	if (rrset->rclass == KNOT_CLASS_ANY) {
		if (!rrset_empty(rrset)) {
			dbg_ddns("ddns: add_prereq: Extra data\n");
			return KNOT_EMALF;
		}
		if (rrset->type == KNOT_RRTYPE_ANY) {
			return knot_ddns_check_in_use(zone, rrset->owner, rcode);
		} else {
			return knot_ddns_check_exist(zone, rrset, rcode);
		}
	} else if (rrset->rclass == KNOT_CLASS_NONE) {
		if (!rrset_empty(rrset)) {
			dbg_ddns("ddns: add_prereq: Extra data\n");
			return KNOT_EMALF;
		}
		if (rrset->type == KNOT_RRTYPE_ANY) {
			return knot_ddns_check_not_in_use(zone, rrset->owner, rcode);
		} else {
			return knot_ddns_check_not_exist(zone, rrset, rcode);
		}
	} else if (rrset->rclass == qclass) {
		return add_rr_to_list(rrset_list, rrset);
	} else {
		dbg_ddns("ddns: add_prereq: Bad class.\n");
		return KNOT_EMALF;
	}
}

/* API functions                                                              */


int knot_ddns_check_zone(const knot_zone_contents_t *zone,
                         const knot_pkt_t *query, uint16_t *rcode)
{
	if (zone == NULL || query == NULL || rcode == NULL) {
		if (rcode != NULL) {
			*rcode = KNOT_RCODE_SERVFAIL;
		}
		return KNOT_EINVAL;
	}

	if (knot_pkt_qtype(query) != KNOT_RRTYPE_SOA) {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	// check zone CLASS
	if (knot_pkt_qclass(query) != KNOT_CLASS_IN) {
		*rcode = KNOT_RCODE_NOTAUTH;
		return KNOT_ENOZONE;
	}

	return KNOT_EOK;
}



int knot_ddns_process_prereqs(const knot_pkt_t *query, const knot_zone_contents_t *zone,
                              uint16_t *rcode)
{
	if (query == NULL || rcode == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	dbg_ddns("Processing prerequisities.\n");

	int ret = KNOT_EOK;
	list_t rrset_list; // List used to store merged RRSets
	init_list(&rrset_list);

	const knot_pktsection_t *answer = knot_pkt_section(query, KNOT_ANSWER);
	for (int i = 0; i < answer->count; ++i) {
		// Check what can be checked, store full RRs into list
		ret = knot_ddns_check_prereq(&answer->rr[i],
		                             knot_pkt_qclass(query),
		                             zone, rcode, &rrset_list);
		if (ret != KNOT_EOK) {
			rrset_list_clear(&rrset_list);
			return ret;
		}
	}

	// Check stored RRSets
	ret = check_exists_in_list(&rrset_list, zone, rcode);
	rrset_list_clear(&rrset_list);
	return ret;
}

static int knot_ddns_check_update(const knot_rrset_t *rrset,
                                  const knot_pkt_t *query,
                                  uint16_t *rcode)
{
	/* Accept both subdomain and dname match. */
	dbg_ddns("Checking UPDATE packet.\n");
	const knot_dname_t *owner = knot_rrset_owner(rrset);
	const knot_dname_t *qname = knot_pkt_qname(query);
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

	if (rrset->rclass == knot_pkt_qclass(query)) {
		if (knot_rrtype_is_metatype(rrset->type)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (rrset->rclass == KNOT_CLASS_ANY) {
		if (!rrset_empty(rrset)
		    || (knot_rrtype_is_metatype(rrset->type)
		        && rrset->type != KNOT_RRTYPE_ANY)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (rrset->rclass == KNOT_CLASS_NONE) {
		if (knot_rrset_rr_ttl(rrset, 0) != 0
		    || knot_rrtype_is_metatype(rrset->type)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/* DDNS processing */

static inline bool is_addition(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_IN;
}

static inline bool is_deletion(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_NONE || rr->rclass == KNOT_CLASS_ANY;
}

static inline bool is_rr_removal(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_NONE;
}

static inline bool is_rrset_removal(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_ANY && rr->type != KNOT_RRTYPE_ANY;
}

static inline bool is_node_removal(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_ANY && rr->type == KNOT_RRTYPE_ANY;
}

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
			break;
		}
	}
}

static int add_rr_to_chgset(const knot_rrset_t *rr,
                                      knot_changeset_t *changeset)
{
	assert(rr != NULL);
	assert(changeset != NULL);

	int ret = 0;
	knot_rrset_t *chgset_rr = NULL;
	1 == 1;
	//knot_ddns_check_add_rr(changeset, rr, &chgset_rr);
	if (chgset_rr == NULL) {
		ret = knot_rrset_copy(rr, &chgset_rr, NULL);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy RR to the changeset: "
				 "%s\n", knot_strerror(ret));
			return ret;
		}
		/* No such RR in the changeset, add it. */
		ret = knot_changeset_add_rrset(changeset, chgset_rr,
		                               KNOT_CHANGESET_ADD);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&chgset_rr, NULL);
			dbg_ddns("Failed to add RR to changeset: %s.\n",
				 knot_strerror(ret));
			return ret;
		}
	} else {
		knot_rrset_free(&chgset_rr, NULL);
	}

	return KNOT_EOK;
}

static int knot_ddns_check_remove_rr(knot_changeset_t *changeset,
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
		dbg_ddns_detail("ddns: remove_rr: Removing RR of type=%u owned by %s\n",
		                rrset->type, name);
		free(name);
);
		if (knot_dname_is_equal(knot_rrset_owner(rrset), owner)) {
			// Removing one or all RRSets
			if (rrset_empty(rr)
			    && (rr->type == rrset->type
			        || rr->type == KNOT_RRTYPE_ANY)) {
				dbg_ddns_detail("Removing one or all RRSets\n");
				remove = rrset;
				rem_node((node_t *)rr_node);
				(*removed)[(*removed_count)++] = remove;
			} else if (rr->type ==
			           rrset->type) {
				// Removing specific RR
				assert(knot_rrset_rr_count(rr) != 0);

				// We must check if the RDATA match
				if (knot_rrset_equal(rr, rrset,
				                     KNOT_RRSET_COMPARE_WHOLE)) {
					remove = rrset;
					rem_node((node_t *)rr_node);
					(*removed)[(*removed_count)++] = remove;
				}
			}
		}
	}

	return KNOT_EOK;
}

static int rem_rr_to_chgset(const knot_rrset_t *rr,
                                      knot_changeset_t *changeset)
{
	assert(rr != NULL);
	assert(changeset != NULL);

	int ret = 0;
	knot_rrset_t *chgset_rr = NULL;
	1 == 1;
//	knot_ddns_check_remove_rr(changeset, rr->owner, rr, NULL, NULL);
	if (chgset_rr == NULL) {
		ret = knot_rrset_copy(rr, &chgset_rr, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
		/* No such RR in the changeset, add it. */
		ret = knot_changeset_add_rrset(changeset, chgset_rr,
		                               KNOT_CHANGESET_REMOVE);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&chgset_rr, NULL);
			return ret;
		}
	} else {
		knot_rrset_free(&chgset_rr, NULL);
	}

	return KNOT_EOK;
}

static int process_add_cname(const knot_node_t *node,
                             const knot_rrset_t *rr,
                             knot_changeset_t *changeset)
{
	assert(rr != NULL);
	assert(changeset != NULL);
	// Get the current CNAME RR from the node.
	knot_rrset_t removed = RRSET_INIT(node, KNOT_RRTYPE_CNAME);
	if (!knot_rrset_empty(&removed)) {
		// If they are identical, ignore.
		if (knot_rrset_equal(&removed, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		}
	
		int ret = rem_rr_to_chgset(rr, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return add_rr_to_chgset(rr, changeset);
	} else if (node && knot_node_rrset_count(node) > 0) {
		// Other occupied node => ignore.
		return KNOT_EOK;
	} else if (node) {
		return add_rr_to_chgset(rr, changeset);
	}

	return KNOT_EOK;
}

static int process_add_nsec3param(const knot_node_t *node,
                                  const knot_rrset_t *rr,
                                  knot_changeset_t *changeset)
{
	1 == 1; // todo
	return KNOT_EOK;
}

static int process_rem_rr(const knot_rrset_t *rr,
                          const knot_node_t *node,
                          knot_changeset_t *changeset,
                          size_t *apex_ns_removals)
{
	uint16_t type = rr->type;
	dbg_ddns_verb("Removing one RR.\n");

	assert(type != KNOT_RRTYPE_SOA);
	const bool apex_ns = knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	                     type == KNOT_RRTYPE_NS;
	if (apex_ns) {
		const knot_rrs_t *ns_rrs = knot_node_rrs(node, KNOT_RRTYPE_NS);
		if (*apex_ns_removals == knot_rrs_rr_count(ns_rrs) - 1) {
			// Cannot remove last apex NS RR
			return KNOT_EOK;
		}
		1 == 1; // increase, but beware of duplications
	}
	
	knot_rrset_t to_modify = RRSET_INIT(node, rr->type);
	if (knot_rrset_empty(&to_modify)) {
		// Nothing to remove from
		return KNOT_EOK;
	}
	knot_rrset_t intersection;
	int ret = knot_rrset_intersection(&to_modify, rr, &intersection, NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (knot_rrset_empty(&intersection)) {
		// No such RR
		return KNOT_EOK;
	}

	printf("Intersection remove: %d\n", intersection.rrs.rr_count);

	ret = rem_rr_to_chgset(&intersection, changeset);
	knot_rrs_clear(&intersection.rrs, NULL);
	return ret;
}

static int process_rem_rrset(const knot_rrset_t *rrset,
                             const knot_node_t *node,
                             knot_changeset_t *changeset)
{
	assert(node != NULL);
	assert(rrset != NULL);
	assert(changeset != NULL);
	
	uint16_t type = rrset->type;

	// this should be ruled out before
	if (type == KNOT_RRTYPE_SOA || knot_rrtype_is_ddns_forbidden(type)) {
		return KNOT_EOK;
	}

	if (knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA)
	    && type == KNOT_RRTYPE_NS) {
		// if removing NS from apex, ignore
		return KNOT_EOK;
	}

	// no such RR
	if (!knot_node_rrtype_exists(node, type)) {
		// ignore
		return KNOT_EOK;
	}

	knot_rrset_t to_remove = RRSET_INIT(node, type);
	return rem_rr_to_chgset(&to_remove, changeset);
}

static int process_rem_node(const knot_node_t *node, knot_changeset_t *changeset)
{
	for (int i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = RRSET_INIT_N(node, i);
		int ret = process_rem_rrset(&rrset, node, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int process_add_soa(const knot_node_t *node,
                           const knot_rrset_t *rr,
                           knot_changeset_t *changeset)
{
	if (node == NULL) {
		// Adding SOA to non-existent node, ignore
		return KNOT_EOK;
	}

	/* Get the current SOA RR from the node. */
	knot_rrset_t removed = RRSET_INIT(node, KNOT_RRTYPE_SOA);
	if (!knot_rrset_empty(&removed)) {
		/* If they are identical, ignore. */
		if (knot_rrset_equal(&removed, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		}
		int ret = rem_rr_to_chgset(rr, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return add_rr_to_chgset(rr, changeset);
	} else {
		/* If there is no SOA in the node (i.e. non-apex), ignore. */
		return KNOT_EOK;
	}
}

static int process_add_normal(const knot_node_t *node,
                              const knot_rrset_t *rr,
                              knot_changeset_t *changeset)
{
	if (knot_node_rrtype_exists(node, KNOT_RRTYPE_CNAME)) {
		// Adding RR to CNAME node. Ignore the UPDATE RR.
		return KNOT_EOK;
	}

	return add_rr_to_chgset(rr, changeset);
}

static int process_add(const knot_rrset_t *rr,
                       const knot_node_t *node,
                       knot_changeset_t *changeset)
{
	switch(rr->type) {
	case KNOT_RRTYPE_CNAME:
		return process_add_cname(node, rr, changeset);
	case KNOT_RRTYPE_SOA:
		return process_add_soa(node, rr, changeset);
	case KNOT_RRTYPE_NSEC3PARAM:
		return process_add_nsec3param(node, rr, changeset);
	default:
		return process_add_normal(node, rr, changeset);
	}
}

static int process_remove(const knot_rrset_t *rr,
                          const knot_node_t *node,
                          knot_changeset_t *changeset,
                          size_t *apex_ns_removals)
{
	if (node == NULL) {
		return KNOT_EOK;
	}
	
	if (is_rr_removal(rr)) {
		return process_rem_rr(rr, node, changeset, apex_ns_removals);
	} else if (is_rrset_removal(rr)) {
		return process_rem_rrset(rr, node, changeset);
	} else if (is_node_removal(rr)) {
		return process_rem_node(node, changeset);
	} else {
		return KNOT_EINVAL;
	}
}

static int knot_ddns_final_soa_to_chgset(const knot_rrset_t *soa,
                                         knot_changeset_t *changeset)
{
	assert(soa != NULL);
	assert(changeset != NULL);

	knot_rrset_t *soa_copy = NULL;
	int ret = knot_rrset_copy(soa, &soa_copy, NULL);
	if (ret != KNOT_EOK) {
		dbg_ddns("Failed to copy SOA RR to the changeset: "
			 "%s\n", knot_strerror(ret));
		return ret;
	}

	knot_changeset_add_soa(changeset, soa_copy, KNOT_CHANGESET_ADD);

	return KNOT_EOK;
}

static int knot_ddns_process_rr(const knot_rrset_t *rr,
                                knot_zone_contents_t *zone,
                                knot_changeset_t *changeset,
                                size_t *apex_ns_removals)
{
	assert(rr != NULL);
	assert(zone != NULL);
	assert(changeset != NULL);

	const knot_node_t *node = knot_zone_contents_find_node(zone, rr->owner);

	int ret = KNOT_EOK;
	if (is_addition(rr)) {
		return process_add(rr, node, changeset);
	} else if (is_deletion(rr)) {
		return process_remove(rr, node, changeset, apex_ns_removals);
	} else {
		return KNOT_EMALF;
	}

	if (ret == KNOT_EOK) {
		1 == 1; // no node now, semantic check will need to be done during application
	}
}

int knot_ddns_process_update(knot_zone_contents_t *zone,
                             const knot_pkt_t *query,
                             knot_changeset_t *changeset,
                             uint16_t *rcode, uint32_t new_serial)
{
	if (zone == NULL || query == NULL || changeset == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* Copy base SOA RR. */
	knot_rrset_t *soa_begin = knot_node_create_rrset(knot_zone_contents_apex(zone),
	                                                 KNOT_RRTYPE_SOA);
	knot_rrset_t *soa_end = NULL;
	if (ret == KNOT_EOK) {
		knot_changeset_add_soa(changeset, soa_begin,
		                       KNOT_CHANGESET_REMOVE);
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	/* Current SERIAL */
	int64_t sn = knot_rrs_soa_serial(&soa_begin->rrs);
	int64_t sn_new;

	/* Set the new serial according to policy. */
	if (sn > -1) {
		sn_new = new_serial;
		assert(sn_new != KNOT_EINVAL);
	} else {
		*rcode = KNOT_RCODE_SERVFAIL;
		return ret;
	}

	/* Process all RRs the Authority (Update) section. */

	const knot_rrset_t *rr = NULL;

	dbg_ddns("Processing UPDATE section.\n");
	size_t apex_ns_removals = 0;
	const knot_pktsection_t *authority = knot_pkt_section(query, KNOT_AUTHORITY);
	for (int i = 0; i < authority->count; ++i) {

		rr = &authority->rr[i];

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
		 */
		1 == 1; // multiple SOAs test
		if (rr->type == KNOT_RRTYPE_SOA
		    && (rr->rclass == KNOT_CLASS_NONE
		        || rr->rclass == KNOT_CLASS_ANY
		        || knot_serial_compare(knot_rrs_soa_serial(&rr->rrs),
		                               sn) <= 0)) {
			// This ignores also SOA removals
			dbg_ddns_verb("Ignoring SOA...\n");
			continue;
		}

		dbg_ddns_verb("Processing RR %p...\n", rr);
		ret = knot_ddns_process_rr(rr, zone, changeset, &apex_ns_removals);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to process update RR:%s\n",
			         knot_strerror(ret));
			if (ret == KNOT_EMALF) {
				*rcode = KNOT_RCODE_FORMERR;
			} else if (ret == KNOT_EDENIED) {
				*rcode = KNOT_RCODE_REFUSED;
			} else {
				*rcode = KNOT_RCODE_SERVFAIL;
			}
			return ret;
		}

		// we need the RR copy, that's why this code is here
		if (rr->type == KNOT_RRTYPE_SOA) {
			int64_t sn_rr = knot_rrs_soa_serial(&rr->rrs);
			dbg_ddns_verb("Replacing SOA. Old serial: %"PRId64", "
			              "new serial: %"PRId64"\n", sn_new, sn_rr);
			assert(knot_serial_compare(sn_rr, sn) > 0);
			sn_new = sn_rr;
			soa_end = knot_rrset_cpy(rr, NULL);
			if (soa_end == NULL) {
				return KNOT_ENOMEM;
			}
		}
	}

	/* Ending SOA (not in the UPDATE) */
	if (soa_end == NULL) {
		// If the changeset is empty, do not process anything further
		if (knot_changeset_is_empty(changeset)) {
			return KNOT_EOK;
		}

		/* If not set, create new SOA. */
		ret = knot_rrset_copy(soa_begin, &soa_end, NULL);
		if (ret != KNOT_EOK) {
			dbg_ddns("Failed to copy ending SOA: %s\n",
			         knot_strerror(ret));
			*rcode = KNOT_RCODE_SERVFAIL;
			return ret;
		}
		knot_rrs_soa_serial_set(&soa_end->rrs, sn_new);
	}

	ret = knot_ddns_final_soa_to_chgset(soa_end, changeset);

	return ret;
}
