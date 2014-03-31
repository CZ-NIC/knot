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

static bool should_replace(const knot_rrset_t *chg_rrset,
                           const knot_rrset_t *rrset)
{
	if (rrset->type != KNOT_RRTYPE_CNAME &&
	    rrset->type != KNOT_RRTYPE_NSEC3PARAM &&
	    rrset->type != KNOT_RRTYPE_SOA) {
		return false;
	} else {
		return chg_rrset->type == rrset->type;
	}
}

static int knot_ddns_check_add_rr(knot_changeset_t *changeset,
                                  knot_rrset_t *rr)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, changeset->remove) {
		knot_rrset_t *rrset = rr_node->rr;
		if (should_replace(rr, rrset)) {
			knot_rrset_free(&rrset, NULL);
			rrset = rr;
			return KNOT_EOK;
		} else if (knot_rrset_equal(rr, rrset, KNOT_RRSET_COMPARE_WHOLE)) {
			knot_rrset_free(&rr, NULL);
			return KNOT_EOK;
		}
	}

	return knot_changeset_add_rrset(changeset, rr, KNOT_CHANGESET_ADD);
}

static int add_rr_to_chgset(const knot_rrset_t *rr, knot_changeset_t *changeset)
{
	knot_rrset_t *rr_copy = knot_rrset_cpy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}

	return knot_ddns_check_add_rr(changeset, rr_copy);
}

static bool skip_record_removal(knot_changeset_t *changeset, knot_rrset_t *rr)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, changeset->remove) {
		knot_rrset_t *rrset = rr_node->rr;
		if (knot_rrset_equal(rr, rrset, KNOT_RRSET_COMPARE_WHOLE)) {
			// Removing the same RR, drop.
			knot_rrset_free(&rr, NULL);
			return true;
		}
	}

	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(rr_node, nxt, changeset->add) {
		knot_rrset_t *rrset = rr_node->rr;
		if (knot_rrset_equal(rrset, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			// Adding and removing identical RRs, drop both.
			knot_rrset_free(&rrset, NULL);
			knot_rrset_free(&rr, NULL);
			rem_node((node_t *)rr_node);
			return true;
		}
	}

	return false;
}

static int rem_rr_to_chgset(const knot_rrset_t *rr, knot_changeset_t *changeset,
                            size_t *apex_ns_rem)
{
	knot_rrset_t *rr_copy = knot_rrset_cpy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}

	if (skip_record_removal(changeset, rr_copy)) {
		return KNOT_EOK;
	}

	if (apex_ns_rem) {
		(*apex_ns_rem)++;
	}
	return knot_changeset_add_rrset(changeset, rr_copy, KNOT_CHANGESET_REMOVE);
}

static int rem_rrset_to_chgset(const knot_rrset_t *rrset,
                               knot_changeset_t *changeset,
                               size_t *apex_ns_rem)
{
	knot_rrset_t rr;
	knot_rrset_init(&rr, rrset->owner, rrset->type, rrset->rclass);
	for (uint16_t i = 0; i < rrset->rrs.rr_count; ++i) {
		int ret = knot_rrset_add_rr_from_rrset(&rr, rrset, i, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = rem_rr_to_chgset(&rr, changeset, apex_ns_rem);
		knot_rrs_clear(&rr.rrs, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int process_add_cname(const knot_node_t *node,
                             const knot_rrset_t *rr,
                             knot_changeset_t *changeset)
{
	knot_rrset_t cname = RRSET_INIT(node, KNOT_RRTYPE_CNAME);
	if (!knot_rrset_empty(&cname)) {
		// If they are identical, ignore.
		if (knot_rrset_equal(&cname, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		}
	
		int ret = rem_rr_to_chgset(rr, changeset, NULL);
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
	if (node == NULL || !knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Ignore non-apex additions
		return KNOT_EOK;
	}
	knot_rrset_t param = RRSET_INIT(node, KNOT_RRTYPE_NSEC3PARAM);
	if (!knot_rrset_empty(&param)) {
		// If they are identical, ignore.
		if (knot_rrset_equal(&param, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		}

		// Replace otherwise
		int ret = rem_rr_to_chgset(&param, changeset, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return add_rr_to_chgset(rr, changeset);
	} else {
		return add_rr_to_chgset(rr, changeset);
	}
}

static int process_rem_rr(const knot_rrset_t *rr,
                          const knot_node_t *node,
                          knot_changeset_t *changeset,
                          size_t *apex_ns_removals)
{
	uint16_t type = rr->type;
	const bool apex_ns = knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	                     type == KNOT_RRTYPE_NS;
	if (apex_ns) {
		const knot_rrs_t *ns_rrs = knot_node_rrs(node, KNOT_RRTYPE_NS);
		if (*apex_ns_removals == knot_rrs_rr_count(ns_rrs) - 1) {
			// Cannot remove last apex NS RR
			return KNOT_EOK;
		}
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

	ret = rem_rrset_to_chgset(&intersection, changeset,
	                          apex_ns ? apex_ns_removals : NULL);
	knot_rrs_clear(&intersection.rrs, NULL);
	return ret;
}

static int process_rem_rrset(const knot_rrset_t *rrset,
                             const knot_node_t *node,
                             knot_changeset_t *changeset)
{
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
	return rem_rrset_to_chgset(&to_remove, changeset, NULL);
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
	if (node == NULL || !knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Adding SOA to non-apex node, ignore
		return KNOT_EOK;
	}

	/* Get the current SOA RR from the node. */
	knot_rrset_t removed = RRSET_INIT(node, KNOT_RRTYPE_SOA);
	/* If they are identical, ignore. */
	if (knot_rrset_equal(&removed, rr, KNOT_RRSET_COMPARE_WHOLE)) {
		return KNOT_EOK;
	}
	return add_rr_to_chgset(rr, changeset);
}

static bool node_contains_rr(const knot_node_t *node,
                             const knot_rrset_t *rr)
{
	knot_rrset_t zone_rrset = RRSET_INIT(node, rr->type);
	if (!knot_rrset_empty(&zone_rrset)) {
		knot_rrset_t intersection;
		int ret = knot_rrset_intersection(&zone_rrset, rr,
		                                  &intersection, NULL);
		if (ret != KNOT_EOK) {
			return false;
		}
		const bool contains = !knot_rrset_empty(&intersection);
		knot_rrs_clear(&intersection.rrs, NULL);
		return contains;
	} else {
		return false;
	}
}

static void remove_rr_from_changeset(knot_changeset_t *changeset,
                                     const knot_rrset_t *rr)
{
	knot_rr_ln_t *rr_node = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(rr_node, nxt, changeset->remove) {
		knot_rrset_t *rrset = rr_node->rr;
		if (knot_rrset_equal(rrset, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			knot_rrset_free(&rrset, NULL);
			rem_node((node_t *)rr_node);
			return;
		}
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

	if (node && node_contains_rr(node, rr)) {
		remove_rr_from_changeset(changeset, rr);
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

static int knot_ddns_final_soa_to_chgset(knot_rrset_t *soa,
                                         knot_changeset_t *changeset)
{
	knot_changeset_add_soa(changeset, soa, KNOT_CHANGESET_ADD);

	return KNOT_EOK;
}

static int knot_ddns_process_rr(const knot_rrset_t *rr,
                                knot_zone_contents_t *zone,
                                knot_changeset_t *changeset,
                                size_t *apex_ns_removals)
{
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

static bool skip_soa(const knot_rrset_t *rr, int64_t sn)
{
	if (rr->type == KNOT_RRTYPE_SOA
	    && (rr->rclass == KNOT_CLASS_NONE
	        || rr->rclass == KNOT_CLASS_ANY
	        || knot_serial_compare(knot_rrs_soa_serial(&rr->rrs),
	                               sn) <= 0)) {
		return true;
	}

	return false;
}

static uint16_t ret_to_rcode(int ret)
{
	if (ret == KNOT_EMALF) {
		return KNOT_RCODE_FORMERR;
	} else if (ret == KNOT_EDENIED) {
		return KNOT_RCODE_REFUSED;
	} else {
		return KNOT_RCODE_SERVFAIL;
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
		if (skip_soa(rr, sn)) {
			continue;
		}

		dbg_ddns_verb("Processing RR %p...\n", rr);
		ret = knot_ddns_process_rr(rr, zone, changeset, &apex_ns_removals);
		if (ret != KNOT_EOK) {
			*rcode = ret_to_rcode(ret);
			return ret;
		}

		// we need the RR copy, that's why this code is here
		if (rr->type == KNOT_RRTYPE_SOA) {
			int64_t sn_rr = knot_rrs_soa_serial(&rr->rrs);
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
			*rcode = ret_to_rcode(ret);
			return ret;
		}
		knot_rrs_soa_serial_set(&soa_end->rrs, sn_new);
	}

	ret = knot_ddns_final_soa_to_chgset(soa_end, changeset);

	return ret;
}
