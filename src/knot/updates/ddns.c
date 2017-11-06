/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/log.h"
#include "knot/updates/ddns.h"
#include "knot/updates/changesets.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/serial.h"
#include "libknot/libknot.h"
#include "contrib/ucw/lists.h"

/* ----------------------------- prereq check ------------------------------- */

/*!< \brief Clears prereq RRSet list. */
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

/*!< \brief Adds RR to prereq RRSet list, merges RRs into RRSets. */
static int add_rr_to_list(list_t *l, const knot_rrset_t *rr)
{
	node_t *n;
	WALK_LIST(n, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		if (knot_rrset_equal(rr, rrset, KNOT_RRSET_COMPARE_HEADER)) {
			return knot_rdataset_merge(&rrset->rrs, &rr->rrs, NULL);
		}
	};

	knot_rrset_t *rr_copy = knot_rrset_copy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}
	return ptrlist_add(l, rr_copy, NULL) != NULL ? KNOT_EOK : KNOT_ENOMEM;
}

/*!< \brief Checks whether RRSet exists in the zone. */
static int check_rrset_exists(zone_update_t *update, const knot_rrset_t *rrset,
                              uint16_t *rcode)
{
	assert(rrset->type != KNOT_RRTYPE_ANY);

	const zone_node_t *node = zone_update_get_node(update, rrset->owner);
	if (node == NULL || !node_rrtype_exists(node, rrset->type)) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else {
		knot_rrset_t found = node_rrset(node, rrset->type);
		assert(!knot_rrset_empty(&found));
		if (knot_rrset_equal(&found, rrset, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		} else {
			*rcode = KNOT_RCODE_NXRRSET;
			return KNOT_EPREREQ;
		}
	}
}

/*!< \brief Checks whether RRSets in the list exist in the zone. */
static int check_stored_rrsets(list_t *l, zone_update_t *update,
                               uint16_t *rcode)
{
	node_t *n;
	WALK_LIST(n, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		int ret = check_rrset_exists(update, rrset, rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}
	};

	return KNOT_EOK;
}

/*!< \brief Checks whether node of given owner, with given type exists. */
static bool check_type(zone_update_t *update, const knot_rrset_t *rrset)
{
	assert(rrset->type != KNOT_RRTYPE_ANY);
	const zone_node_t *node = zone_update_get_node(update, rrset->owner);
	if (node == NULL || !node_rrtype_exists(node, rrset->type)) {
		return false;
	}

	return true;
}

/*!< \brief Checks whether RR type exists in the zone. */
static int check_type_exist(zone_update_t *update,
                            const knot_rrset_t *rrset, uint16_t *rcode)
{
	assert(rrset->rclass == KNOT_CLASS_ANY);
	if (check_type(update, rrset)) {
		return KNOT_EOK;
	} else {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	}
}

/*!< \brief Checks whether RR type is not in the zone. */
static int check_type_not_exist(zone_update_t *update,
                                const knot_rrset_t *rrset, uint16_t *rcode)
{
	assert(rrset->rclass == KNOT_CLASS_NONE);
	if (check_type(update, rrset)) {
		*rcode = KNOT_RCODE_YXRRSET;
		return KNOT_EPREREQ;
	} else {
		return KNOT_EOK;
	}
}

/*!< \brief Checks whether DNAME is in the zone. */
static int check_in_use(zone_update_t *update,
                        const knot_dname_t *dname, uint16_t *rcode)
{
	const zone_node_t *node = zone_update_get_node(update, dname);
	if (node == NULL || node->rrset_count == 0) {
		*rcode = KNOT_RCODE_NXDOMAIN;
		return KNOT_EPREREQ;
	} else {
		return KNOT_EOK;
	}
}

/*!< \brief Checks whether DNAME is not in the zone. */
static int check_not_in_use(zone_update_t *update,
                            const knot_dname_t *dname, uint16_t *rcode)
{
	const zone_node_t *node = zone_update_get_node(update, dname);
	if (node == NULL || node->rrset_count == 0) {
		return KNOT_EOK;
	} else {
		*rcode = KNOT_RCODE_YXDOMAIN;
		return KNOT_EPREREQ;
	}
}

/*!< \brief Returns true if rrset has 0 data or RDATA of size 0 (we need TTL).*/
static bool rrset_empty(const knot_rrset_t *rrset)
{
	uint16_t rr_count = rrset->rrs.rr_count;
	if (rr_count == 0) {
		return true;
	}
	if (rr_count == 1) {
		const knot_rdata_t *rr = knot_rdataset_at(&rrset->rrs, 0);
		return rr->len == 0;
	}
	return false;
}

/*< \brief Returns true if DDNS should deny updating DNSSEC-related record. */
static bool is_dnssec_protected(uint16_t type, bool is_apex)
{
	switch (type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
	case KNOT_RRTYPE_CDNSKEY:
	case KNOT_RRTYPE_CDS:
		return true;
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_NSEC3PARAM:
		return is_apex;
	default:
		return false;
	}
}

/*!< \brief Checks prereq for given packet RR. */
static int process_prereq(const knot_rrset_t *rrset, uint16_t qclass,
                          zone_update_t *update, uint16_t *rcode,
                          list_t *rrset_list)
{
	if (rrset->ttl != 0) {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	if (!knot_dname_in(update->zone->name, rrset->owner)) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	if (rrset->rclass == KNOT_CLASS_ANY) {
		if (!rrset_empty(rrset)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
		if (rrset->type == KNOT_RRTYPE_ANY) {
			return check_in_use(update, rrset->owner, rcode);
		} else {
			return check_type_exist(update, rrset, rcode);
		}
	} else if (rrset->rclass == KNOT_CLASS_NONE) {
		if (!rrset_empty(rrset)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
		if (rrset->type == KNOT_RRTYPE_ANY) {
			return check_not_in_use(update, rrset->owner, rcode);
		} else {
			return check_type_not_exist(update, rrset, rcode);
		}
	} else if (rrset->rclass == qclass) {
		// Store RRs for full check into list
		int ret = add_rr_to_list(rrset_list, rrset);
		if (ret != KNOT_EOK) {
			*rcode = KNOT_RCODE_SERVFAIL;
		}
		return ret;
	} else {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}
}

/* --------------------------- DDNS processing ------------------------------ */

/* --------------------- true/false helper functions ------------------------ */

static inline bool is_addition(const knot_rrset_t *rr)
{
	return rr->rclass == KNOT_CLASS_IN;
}

static inline bool is_removal(const knot_rrset_t *rr)
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

/*!< \brief Returns true if last addition of certain types is to be replaced. */
static bool should_replace(const knot_rrset_t *rrset)
{
	return rrset->type == KNOT_RRTYPE_CNAME ||
	       rrset->type == KNOT_RRTYPE_NSEC3PARAM;
}

/*!< \brief Returns true if node contains given RR in its RRSets. */
static bool node_contains_rr(const zone_node_t *node,
                             const knot_rrset_t *rr)
{
	const knot_rdataset_t *zone_rrs = node_rdataset(node, rr->type);
	if (zone_rrs) {
		assert(rr->rrs.rr_count == 1);
		return knot_rdataset_member(zone_rrs, knot_rdataset_at(&rr->rrs, 0));
	} else {
		return false;
	}
}

/*!< \brief Returns true if CNAME is in this node. */
static bool adding_to_cname(const knot_dname_t *owner,
                            const zone_node_t *node)
{
	if (node == NULL) {
		// Node did not exist before update.
		return false;
	}

	knot_rrset_t cname = node_rrset(node, KNOT_RRTYPE_CNAME);
	if (knot_rrset_empty(&cname)) {
		// Node did not contain CNAME before update.
		return false;
	}

	// CNAME present
	return true;
}

/*!< \brief Used to ignore SOA deletions and SOAs with lower serial than zone. */
static bool skip_soa(const knot_rrset_t *rr, int64_t sn)
{
	if (rr->type == KNOT_RRTYPE_SOA &&
	    (rr->rclass == KNOT_CLASS_NONE || rr->rclass == KNOT_CLASS_ANY ||
	     (serial_compare(knot_soa_serial(&rr->rrs), sn) != SERIAL_GREATER))) {
		return true;
	}

	return false;
}

/* ---------------------- changeset manipulation ---------------------------- */

/*!< \brief Replaces possible singleton RR type in changeset. */
static bool singleton_replaced(changeset_t *changeset,
                               const knot_rrset_t *rr)
{
	if (!should_replace(rr)) {
		return false;
	}

	zone_node_t *n = zone_contents_find_node_for_rr(changeset->add, rr);
	if (n == NULL) {
		return false;
	}

	knot_rdataset_t *rrs = node_rdataset(n, rr->type);
	if (rrs == NULL) {
		return false;
	}

	// Replace singleton RR.
	knot_rdataset_clear(rrs, NULL);
	node_remove_rdataset(n, rr->type);
	node_add_rrset(n, rr, NULL);

	return true;
}

/*!< \brief Adds RR into add section of changeset if it is deemed worthy. */
static int add_rr_to_chgset(const knot_rrset_t *rr,
                            zone_update_t *update)
{
	if (singleton_replaced(&update->change, rr)) {
		return KNOT_EOK;
	}

	return zone_update_add(update, rr);
}

/* ------------------------ RR processing logic ----------------------------- */

/* --------------------------- RR additions --------------------------------- */

/*!< \brief Processes CNAME addition (replace or ignore) */
static int process_add_cname(const zone_node_t *node,
                             const knot_rrset_t *rr,
                             zone_update_t *update)
{
	knot_rrset_t cname = node_rrset(node, KNOT_RRTYPE_CNAME);
	if (!knot_rrset_empty(&cname)) {
		// If they are identical, ignore.
		if (knot_rrset_equal(&cname, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		}

		int ret = zone_update_remove(update, &cname);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return add_rr_to_chgset(rr, update);
	} else if (!node_empty(node)) {
		// Other occupied node => ignore.
		return KNOT_EOK;
	} else {
		// Can add.
		return add_rr_to_chgset(rr, update);
	}
}

/*!< \brief Processes NSEC3PARAM addition (ignore when not removed, or non-apex) */
static int process_add_nsec3param(const zone_node_t *node,
                                  const knot_rrset_t *rr,
                                  zone_update_t *update)
{
	if (node == NULL || !node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Ignore non-apex additions
		char *owner = knot_dname_to_str_alloc(rr->owner);
		log_warning("DDNS, refusing to add NSEC3PARAM to non-apex "
		            "node '%s'", owner);
		free(owner);
		return KNOT_EDENIED;
	}
	knot_rrset_t param = node_rrset(node, KNOT_RRTYPE_NSEC3PARAM);
	if (knot_rrset_empty(&param)) {
		return add_rr_to_chgset(rr, update);
	}

	char *owner = knot_dname_to_str_alloc(rr->owner);
	log_warning("DDNS, refusing to add second NSEC3PARAM to node '%s'", owner);
	free(owner);

	return KNOT_EOK;
}

/*!
 * \brief Processes SOA addition (ignore when non-apex), lower serials
 *        dropped before.
 */
static int process_add_soa(const zone_node_t *node,
                           const knot_rrset_t *rr,
                           zone_update_t *update)
{
	if (node == NULL || !node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Adding SOA to non-apex node, ignore.
		return KNOT_EOK;
	}

	// Get current SOA RR.
	knot_rrset_t removed = node_rrset(node, KNOT_RRTYPE_SOA);
	if (knot_rrset_equal(&removed, rr, KNOT_RRSET_COMPARE_WHOLE)) {
		// If they are identical, ignore.
		return KNOT_EOK;
	}

	return add_rr_to_chgset(rr, update);
}

/*!< \brief Adds normal RR, ignores when CNAME exists in node. */
static int process_add_normal(const zone_node_t *node,
                              const knot_rrset_t *rr,
                              zone_update_t *update)
{
	if (adding_to_cname(rr->owner, node)) {
		// Adding RR to CNAME node, ignore.
		return KNOT_EOK;
	}

	if (node && node_contains_rr(node, rr)) {
		// Adding existing RR, ignore.
		return KNOT_EOK;
	}

	return add_rr_to_chgset(rr, update);
}

/*!< \brief Decides what to do with RR addition. */
static int process_add(const knot_rrset_t *rr,
                       const zone_node_t *node,
                       zone_update_t *update)
{
	switch(rr->type) {
	case KNOT_RRTYPE_CNAME:
		return process_add_cname(node, rr, update);
	case KNOT_RRTYPE_SOA:
		return process_add_soa(node, rr, update);
	case KNOT_RRTYPE_NSEC3PARAM:
		return process_add_nsec3param(node, rr, update);
	default:
		return process_add_normal(node, rr, update);
	}
}

/* --------------------------- RR deletions --------------------------------- */

/*!< \brief Removes single RR from zone. */
static int process_rem_rr(const knot_rrset_t *rr,
                          const zone_node_t *node,
                          zone_update_t *update)
{
	if (node == NULL) {
		// Removing from node that does not exist
		return KNOT_EOK;
	}

	const bool apex_ns = node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	                     rr->type == KNOT_RRTYPE_NS;
	if (apex_ns) {
		const knot_rdataset_t *ns_rrs =
			node_rdataset(node, KNOT_RRTYPE_NS);
		if (ns_rrs == NULL) {
			// Zone without apex NS.
			return KNOT_EOK;
		}
		if (ns_rrs->rr_count == 1) {
			// Cannot remove last apex NS RR.
			return KNOT_EOK;
		}
	}

	knot_rrset_t to_modify = node_rrset(node, rr->type);
	if (knot_rrset_empty(&to_modify)) {
		// No such RRSet
		return KNOT_EOK;
	}

	knot_rdataset_t *rrs = node_rdataset(node, rr->type);
	if (!knot_rdataset_member(rrs, rr->rrs.data)) {
		// Node does not contain this RR
		return KNOT_EOK;
	}

	return zone_update_remove(update, rr);
}

/*!< \brief Removes RRSet from zone. */
static int process_rem_rrset(const knot_rrset_t *rrset,
                             const zone_node_t *node,
                             zone_update_t *update)
{
	bool is_apex = node_rrtype_exists(node, KNOT_RRTYPE_SOA);

	if (rrset->type == KNOT_RRTYPE_SOA || is_dnssec_protected(rrset->type, is_apex)) {
		// Ignore SOA and DNSSEC removals.
		return KNOT_EOK;
	}

	if (is_apex && rrset->type == KNOT_RRTYPE_NS) {
		// Ignore NS apex RRSet removals.
		return KNOT_EOK;
	}

	if (node == NULL) {
		// no such node in zone, ignore
		return KNOT_EOK;
	}

	if (!node_rrtype_exists(node, rrset->type)) {
		// no such RR, ignore
		return KNOT_EOK;
	}

	knot_rrset_t to_remove = node_rrset(node, rrset->type);
	return zone_update_remove(update, &to_remove);
}

/*!< \brief Removes node from zone. */
static int process_rem_node(const knot_rrset_t *rr,
                            const zone_node_t *node, zone_update_t *update)
{
	if (node == NULL) {
		return KNOT_EOK;
	}

	zone_node_t *node_copy = node_shallow_copy(node, NULL);
	if (node_copy == NULL) {
		return KNOT_ENOMEM;
	}

	// Remove all RRSets from node
	size_t rrset_count = node_copy->rrset_count;
	for (int i = 0; i < rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node_copy, rrset_count - i - 1);
		int ret = process_rem_rrset(&rrset, node_copy, update);
		if (ret != KNOT_EOK) {
			node_free(&node_copy, NULL);
			return ret;
		}
	}

	node_free(&node_copy, NULL);

	return KNOT_EOK;
}

/*!< \brief Decides what to with removal. */
static int process_remove(const knot_rrset_t *rr,
                          const zone_node_t *node,
                          zone_update_t *update)
{
	if (is_rr_removal(rr)) {
		return process_rem_rr(rr, node, update);
	} else if (is_rrset_removal(rr)) {
		return process_rem_rrset(rr, node, update);
	} else if (is_node_removal(rr)) {
		return process_rem_node(rr, node, update);
	} else {
		return KNOT_EINVAL;
	}
}

/* --------------------------- validity checks ------------------------------ */

/*!< \brief Checks whether addition has not violated DNAME rules. */
static bool sem_check(const knot_rrset_t *rr, const zone_node_t *zone_node,
                      zone_update_t *update)
{
	// Check that we have not added DNAME child
	const knot_dname_t *parent_dname = knot_wire_next_label(rr->owner, NULL);
	const zone_node_t *parent = zone_update_get_node(update, parent_dname);
	if (parent == NULL) {
		return true;
	}

	if (node_rrtype_exists(parent, KNOT_RRTYPE_DNAME)) {
		// Parent has DNAME RRSet, refuse update
		return false;
	}

	if (rr->type != KNOT_RRTYPE_DNAME || zone_node == NULL) {
		return true;
	}

	// Check that we have not created node with DNAME children.
	if (zone_node->children > 0) {
		// Updated node has children and DNAME was added, refuse update
		return false;
	}

	return true;
}

/*!< \brief Checks whether we can accept this RR. */
static int check_update(const knot_rrset_t *rrset, const knot_pkt_t *query,
                        uint16_t *rcode)
{
	/* Accept both subdomain and dname match. */
	const knot_dname_t *owner = rrset->owner;
	const knot_dname_t *qname = knot_pkt_qname(query);
	const bool is_sub = knot_dname_is_sub(owner, qname);
	const bool is_apex = knot_dname_is_equal(owner, qname);
	if (!is_sub && !is_apex) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	if (is_dnssec_protected(rrset->type, is_apex)) {
		*rcode = KNOT_RCODE_REFUSED;
		log_warning("DDNS, refusing to update DNSSEC-related record");
		return KNOT_EDENIED;
	}

	if (rrset->rclass == knot_pkt_qclass(query)) {
		if (knot_rrtype_is_metatype(rrset->type)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (rrset->rclass == KNOT_CLASS_ANY) {
		if (!rrset_empty(rrset) ||
		    (knot_rrtype_is_metatype(rrset->type) &&
		     rrset->type != KNOT_RRTYPE_ANY)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else if (rrset->rclass == KNOT_CLASS_NONE) {
		if (rrset->ttl != 0 || knot_rrtype_is_metatype(rrset->type)) {
			*rcode = KNOT_RCODE_FORMERR;
			return KNOT_EMALF;
		}
	} else {
		*rcode = KNOT_RCODE_FORMERR;
		return KNOT_EMALF;
	}

	return KNOT_EOK;
}

/*!< \brief Checks RR and decides what to do with it. */
static int process_rr(const knot_rrset_t *rr, zone_update_t *update)
{
	const zone_node_t *node = zone_update_get_node(update, rr->owner);

	if (is_addition(rr)) {
		int ret = process_add(rr, node, update);
		if (ret == KNOT_EOK) {
			if (!sem_check(rr, node, update)) {
				return KNOT_EDENIED;
			}
		}
		return ret;
	} else if (is_removal(rr)) {
		return process_remove(rr, node, update);
	} else {
		return KNOT_EMALF;
	}
}

/*!< \brief Maps Knot return code to RCODE. */
static uint16_t ret_to_rcode(int ret)
{
	if (ret == KNOT_EMALF) {
		return KNOT_RCODE_FORMERR;
	} else if (ret == KNOT_EDENIED || ret == KNOT_ETTL) {
		return KNOT_RCODE_REFUSED;
	} else {
		return KNOT_RCODE_SERVFAIL;
	}
}

/* ---------------------------------- API ----------------------------------- */

int ddns_process_prereqs(const knot_pkt_t *query, zone_update_t *update,
                         uint16_t *rcode)
{
	if (query == NULL || rcode == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	list_t rrset_list; // List used to store merged RRSets
	init_list(&rrset_list);

	const knot_pktsection_t *answer = knot_pkt_section(query, KNOT_ANSWER);
	const knot_rrset_t *answer_rr = knot_pkt_rr(answer, 0);
	for (int i = 0; i < answer->count; ++i) {
		// Check what can be checked, store full RRs into list
		ret = process_prereq(&answer_rr[i], knot_pkt_qclass(query),
		                     update, rcode, &rrset_list);
		if (ret != KNOT_EOK) {
			rrset_list_clear(&rrset_list);
			return ret;
		}
	}

	// Check stored RRSets
	ret = check_stored_rrsets(&rrset_list, update, rcode);
	rrset_list_clear(&rrset_list);
	return ret;
}

int ddns_process_update(const zone_t *zone, const knot_pkt_t *query,
                        zone_update_t *update, uint16_t *rcode)
{
	if (zone == NULL || query == NULL || update == NULL || rcode == NULL) {
		if (rcode) {
			*rcode = ret_to_rcode(KNOT_EINVAL);
		}
		return KNOT_EINVAL;
	}

	uint32_t sn_old = knot_soa_serial(zone_update_from(update));

	// Process all RRs in the authority section.
	const knot_pktsection_t *authority = knot_pkt_section(query, KNOT_AUTHORITY);
	const knot_rrset_t *authority_rr = knot_pkt_rr(authority, 0);
	for (uint16_t i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = &authority_rr[i];
		// Check if RR is correct.
		int ret = check_update(rr, query, rcode);
		if (ret != KNOT_EOK) {
			assert(*rcode != KNOT_RCODE_NOERROR);
			return ret;
		}

		if (skip_soa(rr, sn_old)) {
			continue;
		}

		ret = process_rr(rr, update);
		if (ret != KNOT_EOK) {
			*rcode = ret_to_rcode(ret);
			return ret;
		}
	}

	*rcode = KNOT_RCODE_NOERROR;
	return KNOT_EOK;
}
