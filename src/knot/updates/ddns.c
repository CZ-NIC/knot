/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>

#include "knot/common/log.h"
#include "knot/updates/ddns.h"
#include "knot/updates/changesets.h"
#include "knot/zone/serial.h"
#include "libknot/libknot.h"
#include "contrib/ucw/lists.h"

/*!< \brief Clears prereq RRSet list. */
static void rrset_list_clear(list_t *l)
{
	node_t *n, *nxt;
	WALK_LIST_DELSAFE(n, nxt, *l) {
		ptrnode_t *ptr_n = (ptrnode_t *)n;
		knot_rrset_t *rrset = (knot_rrset_t *)ptr_n->d;
		knot_rrset_free(rrset, NULL);
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
		if (rrset->type == rr->type && knot_dname_is_equal(rrset->owner, rr->owner)) {
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
		if (knot_rrset_equal(&found, rrset, false)) {
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

/*!< \brief Returns true if rrset has 0 data or RDATA of size 0 (we need TTL). */
static bool rrset_empty(const knot_rrset_t *rrset)
{
	switch (rrset->rrs.count) {
	case 0:
		return true;
	case 1:
		return rrset->rrs.rdata->len == 0;
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

	if (knot_dname_in_bailiwick(rrset->owner, update->zone->name) < 0) {
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
	       rrset->type == KNOT_RRTYPE_DNAME ||
	       rrset->type == KNOT_RRTYPE_NSEC3PARAM;
}

/*!< \brief Returns true if node contains given RR in its RRSets. */
static bool node_contains_rr(const zone_node_t *node,
                             const knot_rrset_t *rrset)
{
	const knot_rdataset_t *zone_rrs = node_rdataset(node, rrset->type);
	if (zone_rrs != NULL) {
		assert(rrset->rrs.count == 1);
		return knot_rdataset_member(zone_rrs, rrset->rrs.rdata);
	} else {
		return false;
	}
}

/*!< \brief Returns true if CNAME is in this node. */
static bool adding_to_cname(const knot_dname_t *owner,
                            zone_update_t *update,
                            const zone_node_t *node)
{
	if (node == NULL) {
		// Node did not exist before update, juch check DNAMEs above.

		while (owner[0] != '\0' &&
		       (owner = knot_dname_next_label(owner)) != NULL &&
		       (node = zone_update_get_node(update, owner)) == NULL);

		for ( ; node != NULL; node = node->parent) {
			knot_rrset_t dname = node_rrset(node, KNOT_RRTYPE_DNAME);
			if (!knot_rrset_empty(&dname)) {
				// DNAME above
				return true;
			}
		}

		return false;
	}

	knot_rrset_t cname = node_rrset(node, KNOT_RRTYPE_CNAME);
	if (!knot_rrset_empty(&cname)) {
		// CNAME present
		return true;
	}

	while ((node = node->parent) != NULL) {
		knot_rrset_t dname = node_rrset(node, KNOT_RRTYPE_DNAME);
		if (!knot_rrset_empty(&dname)) {
			// DNAME above
			return true;
		}
	}

	return false;
}

/*!< \brief Used to ignore SOA deletions and SOAs with lower serial than zone. */
static bool skip_soa(const knot_rrset_t *rr, int64_t sn)
{
	if (rr->type == KNOT_RRTYPE_SOA &&
	    (rr->rclass == KNOT_CLASS_NONE || rr->rclass == KNOT_CLASS_ANY ||
	     (serial_compare(knot_soa_serial(rr->rrs.rdata), sn) != SERIAL_GREATER))) {
		return true;
	}

	return false;
}

/*!< \brief Replaces possible singleton RR type in changeset. */
static bool singleton_replaced(zone_update_t *update, const knot_rrset_t *rr)
{
	if (!should_replace(rr)) {
		return false;
	}

	return zone_update_remove_rrset(update, rr->owner, rr->type) == KNOT_EOK;
}

/*!< \brief Adds RR into add section of changeset if it is deemed worthy. */
static int add_rr_to_changeset(const knot_rrset_t *rr, zone_update_t *update)
{
	if (singleton_replaced(update, rr)) {
		return KNOT_EOK;
	}

	return zone_update_add(update, rr);
}

int node_empty_cb(zone_node_t *node, _unused_ void *ctx)
{
	return node_empty(node) ? KNOT_EOK : KNOT_ESEMCHECK;
}

bool subtree_empty(zone_contents_t *zone, const zone_node_t *node)
{
	if (node == NULL) {
		return true;
	}
	int ret = zone_tree_sub_apply(zone->nodes, node->owner, true, node_empty_cb, NULL);
	return (ret == KNOT_EOK);
}

/*!< \brief Processes CNAME/DNAME addition (replace or ignore) */
static int process_add_cname(const zone_node_t *node,
                             const knot_rrset_t *rr,
                             uint16_t type,
                             zone_update_t *update)
{
	assert(type == KNOT_RRTYPE_CNAME || type == KNOT_RRTYPE_DNAME);

	knot_rrset_t cname = node_rrset(node, type);
	if (!knot_rrset_empty(&cname)) {
		// If they are identical, ignore.
		if (knot_rrset_equal(&cname, rr, true)) {
			return KNOT_EOK;
		}

		int ret = zone_update_remove(update, &cname);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return add_rr_to_changeset(rr, update);
	} else if (type == KNOT_RRTYPE_CNAME && !node_empty(node)) {
		// Other occupied node => ignore.
		return KNOT_EOK;
	} else if (type == KNOT_RRTYPE_DNAME && !subtree_empty(update->new_cont, node)) {
		// Equivalent to above, ignore.
		return KNOT_EOK;
	} else if (type == KNOT_RRTYPE_DNAME && node_rrtype_exists(node, KNOT_RRTYPE_CNAME)) {
		// RFC 6672 §5.2.
		return KNOT_EOK;
	} else if (type == KNOT_RRTYPE_CNAME && adding_to_cname(rr->owner, update, node)) {
		// DNAME exists above CNAME, ignore.
		return KNOT_EOK;
	} else {
		// Can add.
		return add_rr_to_changeset(rr, update);
	}
}

/*!
 * \brief Processes SOA addition (ignore when non-apex), lower serials
 *        dropped before.
 */
static int process_add_soa(const zone_node_t *node,
                           const knot_rrset_t *rr,
                           zone_update_t *update)
{
	bool empty_zone = (update->flags & UPDATE_FULL);
	if (!empty_zone) {
		if (node == NULL || !node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
			// Adding SOA to non-apex node, ignore.
			return KNOT_EOK;
		}

		// Get current SOA RR.
		knot_rrset_t removed = node_rrset(node, KNOT_RRTYPE_SOA);
		if (knot_rrset_equal(&removed, rr, true)) {
			// If they are identical, ignore.
			return KNOT_EOK;
		}
	}

	return add_rr_to_changeset(rr, update);
}

/*!< \brief Adds normal RR, ignores when CNAME exists in node. */
static int process_add_normal(const zone_node_t *node,
                              const knot_rrset_t *rr,
                              zone_update_t *update)
{
	if (adding_to_cname(rr->owner, update, node)) {
		// Adding RR to CNAME node, ignore.
		return KNOT_EOK;
	}

	if (node && node_contains_rr(node, rr)) {
		// Adding existing RR, ignore.
		return KNOT_EOK;
	}

	return add_rr_to_changeset(rr, update);
}

/*!< \brief Decides what to do with RR addition. */
static int process_add(const knot_rrset_t *rr,
                       const zone_node_t *node,
                       zone_update_t *update)
{
	switch(rr->type) {
	case KNOT_RRTYPE_CNAME:
	case KNOT_RRTYPE_DNAME:
		return process_add_cname(node, rr, rr->type, update);
	case KNOT_RRTYPE_SOA:
		return process_add_soa(node, rr, update);
	default:
		return process_add_normal(node, rr, update);
	}
}

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
		if (ns_rrs->count == 1) {
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
	if (!knot_rdataset_member(rrs, rr->rrs.rdata)) {
		// Node does not contain this RR
		return KNOT_EOK;
	}

	knot_rrset_t rr_ttl = *rr;
	rr_ttl.ttl = to_modify.ttl;

	return zone_update_remove(update, &rr_ttl);
}

/*!< \brief Removes RRSet from zone. */
static int process_rem_rrset(const knot_rrset_t *rrset,
                             const zone_node_t *node,
                             zone_update_t *update)
{
	bool is_apex = node_rrtype_exists(node, KNOT_RRTYPE_SOA);

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

	// Remove all RRSets from node
	size_t rrset_count = node->rrset_count;
	for (int i = 0; i < rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(node, rrset_count - i - 1);
		int ret = process_rem_rrset(&rrset, node, update);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

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

/*!< \brief Checks whether we can accept this RR. */
static int check_update(const knot_rrset_t *rrset, const knot_pkt_t *query,
                        const zone_contents_t *zone, uint16_t *rcode)
{
	/* Accept both subdomain and dname match. */
	const knot_dname_t *owner = rrset->owner;
	const knot_dname_t *qname = knot_pkt_qname(query);
	assert(knot_dname_is_equal(qname, zone->apex->owner));
	const int in_bailiwick = knot_dname_in_bailiwick(owner, qname);
	if (in_bailiwick < 0) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	if (rrset->type == KNOT_RRTYPE_NSEC3PARAM) {
		if (!knot_dname_is_equal(rrset->owner, zone->apex->owner)) {
			log_warning("DDNS, refusing to add NSEC3PARAM to non-apex node");
			*rcode = KNOT_RCODE_REFUSED;
			return KNOT_EDENIED;
		} else if (node_rrtype_exists(zone->apex, rrset->type)) {
			log_warning("DDNS, refusing to add second NSEC3PARAM to zone apex");
			*rcode = KNOT_RCODE_REFUSED;
			return KNOT_EDENIED;
		}
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
		return process_add(rr, node, update);
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
	} else if (ret == KNOT_EDENIED) {
		return KNOT_RCODE_REFUSED;
	} else {
		return KNOT_RCODE_SERVFAIL;
	}
}

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
	const knot_rrset_t *answer_rr = (answer->count > 0) ? knot_pkt_rr(answer, 0) : NULL;
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

int ddns_precheck_update(const knot_pkt_t *query, zone_update_t *update,
                         uint16_t *rcode)
{
	if (query == NULL || rcode == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	// Check all RRs in the authority section.
	const knot_pktsection_t *authority = knot_pkt_section(query, KNOT_AUTHORITY);
	const knot_rrset_t *authority_rr = (authority->count > 0) ? knot_pkt_rr(authority, 0) : NULL;
	for (uint16_t i = 0; i < authority->count; ++i) {
		int ret = check_update(&authority_rr[i], query, update->new_cont, rcode);
		if (ret != KNOT_EOK) {
			assert(*rcode != KNOT_RCODE_NOERROR);
			return ret;
		}
	}

	return KNOT_EOK;
}

int ddns_process_update(const knot_pkt_t *query, zone_update_t *update,
                        uint16_t *rcode)
{
	if (query == NULL || update == NULL || rcode == NULL) {
		if (rcode) {
			*rcode = ret_to_rcode(KNOT_EINVAL);
		}
		return KNOT_EINVAL;
	}

	bool empty_zone = (update->flags & UPDATE_FULL);
	uint32_t sn_old = !empty_zone ? knot_soa_serial(zone_update_from(update)->rdata) : 0;

	// Process all RRs in the authority section.
	const knot_pktsection_t *authority = knot_pkt_section(query, KNOT_AUTHORITY);
	const knot_rrset_t *authority_rr = (authority->count > 0) ? knot_pkt_rr(authority, 0) : NULL;
	for (uint16_t i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = &authority_rr[i];
		if (!empty_zone && skip_soa(rr, sn_old)) {
			continue;
		}

		int ret = process_rr(rr, update);
		if (ret != KNOT_EOK) {
			*rcode = ret_to_rcode(ret);
			return ret;
		}
	}

	*rcode = KNOT_RCODE_NOERROR;
	return KNOT_EOK;
}
