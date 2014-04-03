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
			int ret = knot_rrset_merge(rrset, rr, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
			return KNOT_EOK;
		}
	};

	knot_rrset_t *rr_copy = knot_rrset_copy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}
	return ptrlist_add(l, rr_copy, NULL) != NULL ? KNOT_EOK : KNOT_ENOMEM;
}

/*!< \brief Checks whether RR type exists in the zone. */
static int knot_ddns_check_exist(const knot_zone_contents_t *zone,
                                 const knot_rrset_t *rrset, uint16_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(rrset->type != KNOT_RRTYPE_ANY);
	assert(rrset->rclass == KNOT_CLASS_ANY);

	if (!knot_dname_is_sub(rrset->owner,
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	const knot_node_t *node;
	node = knot_zone_contents_find_node(zone, rrset->owner);
	if (node == NULL) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_ENONODE;
	} else if (!knot_node_rrtype_exists(node, rrset->type)) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_ENORRSET;
	}

	return KNOT_EOK;
}

/*!< \brief Checks whether RRSet exists in the zone. */
static int knot_ddns_check_exist_full(const knot_zone_contents_t *zone,
                                      const knot_rrset_t *rrset,
                                      uint16_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(rrset->type != KNOT_RRTYPE_ANY);

	if (!knot_dname_is_sub(rrset->owner,
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	const knot_node_t *node;
	node = knot_zone_contents_find_node(zone, rrset->owner);
	if (node == NULL) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else if (!knot_node_rrtype_exists(node, rrset->type)) {
		*rcode = KNOT_RCODE_NXRRSET;
		return KNOT_EPREREQ;
	} else {
		knot_rrset_t found = knot_node_rrset(node, rrset->type);
		assert(!knot_rrset_empty(&found));
		if (!knot_rrset_equal(&found, rrset, KNOT_RRSET_COMPARE_WHOLE)) {
			*rcode = KNOT_RCODE_NXRRSET;
			return KNOT_EPREREQ;
		}
	}

	return KNOT_EOK;
}

/*!< \brief Checks whether RRSets in the list exist in the zone. */
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

/*!< \brief Checks whether RR type is not in the zone. */
static int knot_ddns_check_not_exist(const knot_zone_contents_t *zone,
                                     const knot_rrset_t *rrset,
                                     uint16_t *rcode)
{
	assert(zone != NULL);
	assert(rrset != NULL);
	assert(rcode != NULL);
	assert(rrset->type != KNOT_RRTYPE_ANY);
	assert(rrset->rclass == KNOT_CLASS_NONE);

	if (!knot_dname_is_sub(rrset->owner,
	    knot_node_owner(knot_zone_contents_apex(zone)))) {
		*rcode = KNOT_RCODE_NOTZONE;
		return KNOT_EOUTOFZONE;
	}

	const knot_node_t *node;

	node = knot_zone_contents_find_node(zone, rrset->owner);
	if (node == NULL) {
		return KNOT_EOK;
	} else if (!knot_node_rrtype_exists(node, rrset->type)) {
		return KNOT_EOK;
	}

	*rcode = KNOT_RCODE_YXRRSET;
	return KNOT_EPREREQ;
}

/*!< \brief Checks whether DNAME is in the zone. */
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

/*!< \brief Checks whether DNAME is not in the zone. */
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

/*!< \brief Returns true if rrset has 0 data or RDATA of size 0 (we need TTL). */
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

/*!< \brief Checks prereq for given packet RR. */
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
		// Store RRs for full check into list
		return add_rr_to_list(rrset_list, rrset);
	} else {
		dbg_ddns("ddns: add_prereq: Bad class.\n");
		return KNOT_EMALF;
	}
}

/* --------------------------- DDNS processing ------------------------------ */

/* ----------------------- changeset lists helpers -------------------------- */

/*!< \brief Checks whether RR was already removed. */
static bool removed_rr(const knot_changeset_t *changeset, const knot_rrset_t *rr)
{
	knot_rr_ln_t *n;
	WALK_LIST(n, changeset->remove) {
		const knot_rrset_t *list_rr = n->rr;
		if (knot_rrset_equal(rr, list_rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return true;
		}
	};

	return false;
}

/*!< \brief Removes RR from list, full equality check. */
static void remove_rr_from_list(list_t *l, const knot_rrset_t *rr)
{
	knot_rr_ln_t *rr_node = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(rr_node, nxt, *l) {
		knot_rrset_t *rrset = rr_node->rr;
		if (knot_rrset_equal(rrset, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			knot_rrset_free(&rrset, NULL);
			rem_node((node_t *)rr_node);
			return;
		}
	}
}

/*!< \brief Removes RR from list, owner and type check. */
static void remove_header_from_list(list_t *l, const knot_rrset_t *rr)
{
	knot_rr_ln_t *rr_node = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(rr_node, nxt, *l) {
		knot_rrset_t *rrset = rr_node->rr;
		if (knot_rrset_equal(rrset, rr, KNOT_RRSET_COMPARE_HEADER)) {
			knot_rrset_free(&rrset, NULL);
			rem_node((node_t *)rr_node);
		}
	}
}

/*!< \brief Removes RR from list, owner check. */
static void remove_owner_from_list(list_t *l, const knot_dname_t *owner)
{
	knot_rr_ln_t *rr_node = NULL;
	node_t *nxt = NULL;
	WALK_LIST_DELSAFE(rr_node, nxt, *l) {
		knot_rrset_t *rrset = rr_node->rr;
		if (knot_dname_is_equal(rrset->owner, owner)) {
			knot_rrset_free(&rrset, NULL);
			rem_node((node_t *)rr_node);
		}
	}
}

/* --------------------- true/false helper functions ------------------------ */

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

/*!< \brief Returns true if last addition of certain types is to be replaced. */
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

/*!< \brief Returns true if node will be empty after update application. */
static bool node_empty(const knot_node_t *node, const knot_changeset_t *changeset)
{
	if (node == NULL) {
		return true;
	}

	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t node_rrset = knot_node_rrset_n(node, i);
		knot_rrset_t node_rr;
		knot_rrset_init(&node_rr, node->owner, node_rrset.type, KNOT_CLASS_IN);
		for (uint16_t j = 0; j < node_rrset.rrs.rr_count; ++j) {
			knot_rrset_add_rr_from_rrset(&node_rr, &node_rrset, j, NULL);
			if (!removed_rr(changeset, &node_rr)) {
				knot_rrs_clear(&node_rr.rrs, NULL);
				return false;
			}
			knot_rrs_clear(&node_rr.rrs, NULL);
		}
	}

	return true;
}

/*!< \brief Returns true if node contains given RR in its RRSets. */
static bool node_contains_rr(const knot_node_t *node,
                             const knot_rrset_t *rr)
{
	knot_rrset_t zone_rrset = knot_node_rrset(node, rr->type);
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

/*!< \brief Returns true if CNAME is in this node. */
static bool adding_to_cname(const knot_node_t *node,
                            knot_changeset_t *changeset)
{
	if (node == NULL) {
		// Node did not exist before update.
		return false;
	}

	knot_rrset_t cname = knot_node_rrset(node, KNOT_RRTYPE_CNAME);
	if (knot_rrset_empty(&cname)) {
		// Node did not contain CNAME before update.
		return false;
	}

	// Return true if we have not removed CNAME in this update.
	return !removed_rr(changeset, &cname);
}

/*!< \brief Used to ignore SOA deletions and SOAs with lower serial than zone. */
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

/* ---------------------- changeset manipulation ---------------------------- */

/*!< \brief Checks whether record should be added or replaced. */
static bool skip_record_addition(knot_changeset_t *changeset,
                                 knot_rrset_t *rr)
{
	knot_rr_ln_t *rr_node = NULL;
	WALK_LIST(rr_node, changeset->add) {
		knot_rrset_t *rrset = rr_node->rr;
		if (should_replace(rr, rrset)) {
			// Replacing singleton RR.
			knot_rrset_free(&rrset, NULL);
			rrset = rr;
			return true;
		} else if (knot_rrset_equal(rr, rrset, KNOT_RRSET_COMPARE_WHOLE)) {
			// Freeing duplication.
			knot_rrset_free(&rr, NULL);
			return true;
		}
	}

	return false;
}

/*!< \brief Adds RR into add section of changeset if it is deemed worthy. */
static int add_rr_to_chgset(const knot_rrset_t *rr, knot_changeset_t *changeset,
                            int *apex_ns_rem)
{
	knot_rrset_t *rr_copy = knot_rrset_copy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}

	rr_copy->rclass = KNOT_CLASS_IN;

	if (skip_record_addition(changeset, rr_copy)) {
		return KNOT_EOK;
	}

	if (apex_ns_rem) {
		// Increase post update apex NS count.
		(*apex_ns_rem)--;
	}

	return knot_changeset_add_rrset(changeset, rr_copy, KNOT_CHANGESET_ADD);
}

/*!< \brief Checks whether record should be removed (duplicate check). */
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

	return false;
}

/*!< \brief Adds RR into remove section of changeset if it is deemed worthy. */
static int rem_rr_to_chgset(const knot_rrset_t *rr, knot_changeset_t *changeset,
                            int *apex_ns_rem)
{
	knot_rrset_t *rr_copy = knot_rrset_copy(rr, NULL);
	if (rr_copy == NULL) {
		return KNOT_ENOMEM;
	}

	rr_copy->rclass = KNOT_CLASS_IN;

	if (skip_record_removal(changeset, rr_copy)) {
		return KNOT_EOK;
	}

	if (apex_ns_rem) {
		// Decrease post update apex NS count.
		(*apex_ns_rem)++;
	}

	return knot_changeset_add_rrset(changeset, rr_copy, KNOT_CHANGESET_REMOVE);
}

/*!< \brief Adds all RRs from RRSet into remove section of changeset. */
static int rem_rrset_to_chgset(const knot_rrset_t *rrset,
                               knot_changeset_t *changeset,
                               int *apex_ns_rem)
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

/* ------------------------ RR processing logic ----------------------------- */

/* --------------------------- RR additions --------------------------------- */

/*!< \brief Processes CNAME addition (replace or ignore) */
static int process_add_cname(const knot_node_t *node,
                             const knot_rrset_t *rr,
                             knot_changeset_t *changeset)
{
	knot_rrset_t cname = knot_node_rrset(node, KNOT_RRTYPE_CNAME);
	if (!knot_rrset_empty(&cname)) {
		// If they are identical, ignore.
		if (knot_rrset_equal(&cname, rr, KNOT_RRSET_COMPARE_WHOLE)) {
			return KNOT_EOK;
		}

		int ret = rem_rr_to_chgset(&cname, changeset, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}

		return add_rr_to_chgset(rr, changeset, NULL);
	} else if (!node_empty(node, changeset)) {
		// Other occupied node => ignore.
		return KNOT_EOK;
	} else {
		// Can add.
		return add_rr_to_chgset(rr, changeset, NULL);
	}

	return KNOT_EOK;
}

/*!< \brief Processes CNAME addition (ignore when not removed, or non-apex) */
static int process_add_nsec3param(const knot_node_t *node,
                                  const knot_rrset_t *rr,
                                  knot_changeset_t *changeset)
{
	if (node == NULL || !knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Ignore non-apex additions
		char *owner = knot_dname_to_str(rr->owner);
		log_server_warning("Refusing to add NSEC3PARAM owned "
		                   "by %s to non-apex node.\n", owner);
		free(owner);
		return KNOT_EDENIED;
	}
	knot_rrset_t param = knot_node_rrset(node, KNOT_RRTYPE_NSEC3PARAM);
	if (knot_rrset_empty(&param) || removed_rr(changeset, &param)) {
		return add_rr_to_chgset(rr, changeset, NULL);
	}

	char *owner = knot_dname_to_str(rr->owner);
	log_server_warning("Refusing to add NSEC3PARAM owned "
	                   "by %s. NSEC3PARAM already present, remove it first.\n",
	                   owner);
	free(owner);

	return KNOT_EOK;
}

/*!
 * \brief Processes SOA addition (ignore when non-apex), lower serials
 *        dropped before.
 */
static int process_add_soa(const knot_node_t *node,
                           const knot_rrset_t *rr,
                           knot_changeset_t *changeset)
{
	if (node == NULL || !knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		// Adding SOA to non-apex node, ignore
		return KNOT_EOK;
	}

	/* Get the current SOA RR from the node. */
	knot_rrset_t removed = knot_node_rrset(node, KNOT_RRTYPE_SOA);
	/* If they are identical, ignore. */
	if (knot_rrset_equal(&removed, rr, KNOT_RRSET_COMPARE_WHOLE)) {
		return KNOT_EOK;
	}
	return add_rr_to_chgset(rr, changeset, NULL);
}

/*!< \brief Adds normal RR, ignores when CNAME exists in node. */
static int process_add_normal(const knot_node_t *node,
                              const knot_rrset_t *rr,
                              knot_changeset_t *changeset,
                              int *apex_ns_rem)
{
	if (adding_to_cname(node, changeset)) {
		// Adding RR to CNAME node, ignore.
		return KNOT_EOK;
	}

	if (node && node_contains_rr(node, rr)) {
		// Adding existing RR, remove removal from changeset if it's there.
		remove_rr_from_list(&changeset->remove, rr);
		// And ignore.
		return KNOT_EOK;
	}

	const bool apex_ns = knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	                     rr->type == KNOT_RRTYPE_NS;
	return add_rr_to_chgset(rr, changeset, apex_ns ? apex_ns_rem : NULL);
}

/*!< \brief Decides what to do with RR addition. */
static int process_add(const knot_rrset_t *rr,
                       const knot_node_t *node,
                       knot_changeset_t *changeset,
                       int *apex_ns_rem)
{
	switch(rr->type) {
	case KNOT_RRTYPE_CNAME:
		return process_add_cname(node, rr, changeset);
	case KNOT_RRTYPE_SOA:
		return process_add_soa(node, rr, changeset);
	case KNOT_RRTYPE_NSEC3PARAM:
		return process_add_nsec3param(node, rr, changeset);
	default:
		return process_add_normal(node, rr, changeset, apex_ns_rem);
	}
}

/* --------------------------- RR deletions --------------------------------- */

/*!< \brief Removes single RR from zone. */
static int process_rem_rr(const knot_rrset_t *rr,
                          const knot_node_t *node,
                          knot_changeset_t *changeset,
                          int *apex_ns_rem)
{
	// Remove possible previously added RR
	remove_rr_from_list(&changeset->add, rr);
	if (node == NULL) {
		// Removing from node that did not exists before update
		return KNOT_EOK;
	}

	uint16_t type = rr->type;
	const bool apex_ns = knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	                     type == KNOT_RRTYPE_NS;
	if (apex_ns) {
		const knot_rrs_t *ns_rrs = knot_node_rrs(node, KNOT_RRTYPE_NS);
		if (*apex_ns_rem == ns_rrs->rr_count - 1) {
			// Cannot remove last apex NS RR
			return KNOT_EOK;
		}
	}

	knot_rrset_t to_modify = knot_node_rrset(node, rr->type);
	if (knot_rrset_empty(&to_modify)) {
		// No such RRSet
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
	assert(intersection.rrs.rr_count == 1);
	ret = rem_rr_to_chgset(&intersection, changeset,
	                       apex_ns ? apex_ns_rem : NULL);
	knot_rrs_clear(&intersection.rrs, NULL);
	return ret;
}

/*!< \brief Removes RRSet from zone. */
static int process_rem_rrset(const knot_rrset_t *rrset,
                             const knot_node_t *node,
                             knot_changeset_t *changeset)
{
	// Removing all previously added RRs with this owner and type from changeset
	remove_header_from_list(&changeset->add, rrset);
	if (node == NULL) {
		return KNOT_EOK;
	}

	if (rrset->type == KNOT_RRTYPE_SOA ||
	    knot_rrtype_is_ddns_forbidden(rrset->type)) {
		// Ignore SOA and DNSSEC removals.
		return KNOT_EOK;
	}

	if (knot_node_rrtype_exists(node, KNOT_RRTYPE_SOA) &&
	    rrset->type == KNOT_RRTYPE_NS) {
		// Ignore NS apex RRSet removals.
		return KNOT_EOK;
	}

	if (!knot_node_rrtype_exists(node, rrset->type)) {
		// no such RR, ignore
		return KNOT_EOK;
	}

	knot_rrset_t to_remove = knot_node_rrset(node, rrset->type);
	return rem_rrset_to_chgset(&to_remove, changeset, NULL);
}

/*!< \brief Removes node from zone. */
static int process_rem_node(const knot_rrset_t *rr,
                            const knot_node_t *node, knot_changeset_t *changeset)
{
	// Remove all previously added records with given owner from changeset
	remove_owner_from_list(&changeset->add, rr->owner);

	if (node == NULL) {
		return KNOT_EOK;
	}

	// Remove all RRSets from node
	for (int i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rrset = knot_node_rrset_n(node, i);
		int ret = process_rem_rrset(&rrset, node, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

/*!< \brief Decides what to with removal. */
static int process_remove(const knot_rrset_t *rr,
                          const knot_node_t *node,
                          knot_changeset_t *changeset,
                          int *apex_ns_rem)
{
	if (is_rr_removal(rr)) {
		return process_rem_rr(rr, node, changeset, apex_ns_rem);
	} else if (is_rrset_removal(rr)) {
		return process_rem_rrset(rr, node, changeset);
	} else if (is_node_removal(rr)) {
		return process_rem_node(rr, node, changeset);
	} else {
		return KNOT_EINVAL;
	}
}

/* --------------------------- validity checks ------------------------------ */

/*!< \brief Checks whether addition has not violated DNAME rules. */
static bool sem_check(const knot_rrset_t *rr,
                      const knot_node_t *zone_node,
                      const knot_zone_contents_t *zone)
{
	// Check that we have not added DNAME child
	const knot_dname_t *parent_dname = knot_wire_next_label(rr->owner, NULL);
	const knot_node_t *parent =
		knot_zone_contents_find_node(zone, parent_dname);
	if (parent == NULL) {
		return true;
	}

	if (knot_node_rrtype_exists(parent, KNOT_RRTYPE_DNAME)) {
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
static int knot_ddns_check_update(const knot_rrset_t *rrset,
                                  const knot_pkt_t *query,
                                  uint16_t *rcode)
{
	/* Accept both subdomain and dname match. */
	dbg_ddns("Checking UPDATE packet.\n");
	const knot_dname_t *owner = rrset->owner;
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

/*!< \brief Checks RR and decides what to do with it. */
static int knot_ddns_process_rr(const knot_rrset_t *rr,
                                const knot_zone_contents_t *zone,
                                knot_changeset_t *changeset,
                                int *apex_ns_rem)
{
	const knot_node_t *node = knot_zone_contents_find_node(zone, rr->owner);
	if (is_addition(rr)) {
		int ret = process_add(rr, node, changeset, apex_ns_rem);
		if (ret == KNOT_EOK) {
			if (!sem_check(rr, node, zone)) {
				return KNOT_EDENIED;
			}
		}
		return ret;
	} else if (is_deletion(rr)) {
		return process_remove(rr, node, changeset, apex_ns_rem);
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

/* ---------------------------------- API ----------------------------------- */

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

int knot_ddns_process_update(const knot_zone_contents_t *zone,
                             const knot_pkt_t *query,
                             knot_changeset_t *changeset,
                             uint16_t *rcode, uint32_t new_serial)
{
	if (zone == NULL || query == NULL || changeset == NULL || rcode == NULL) {
		return KNOT_EINVAL;
	}

	/* Copy base SOA RR. */
	knot_rrset_t *soa_begin = knot_node_create_rrset(zone->apex,
	                                                 KNOT_RRTYPE_SOA);
	knot_changeset_add_soa(changeset, soa_begin, KNOT_CHANGESET_REMOVE);

	int64_t sn_old = knot_zone_serial(zone);

	/* Process all RRs the Authority (Update) section. */

	dbg_ddns("Processing UPDATE section.\n");
	knot_rrset_t *soa_end = NULL;
	int apex_ns_rem = 0;
	const knot_pktsection_t *authority = knot_pkt_section(query, KNOT_AUTHORITY);
	for (uint16_t i = 0; i < authority->count; ++i) {
		const knot_rrset_t *rr = &authority->rr[i];

		/* Check if the entry is correct. */
		int ret = knot_ddns_check_update(rr, query, rcode);
		if (ret != KNOT_EOK) {
			return ret;
		}

		if (skip_soa(rr, sn_old)) {
			continue;
		}

		ret = knot_ddns_process_rr(rr, zone, changeset, &apex_ns_rem);
		if (ret != KNOT_EOK) {
			*rcode = ret_to_rcode(ret);
			return ret;
		}

		if (rr->type == KNOT_RRTYPE_SOA) {
			// Using new SOA that came in the update
			if (soa_end == NULL) {
				knot_rrset_free(&soa_end, NULL);
			}
			int64_t sn_rr = knot_rrs_soa_serial(&rr->rrs);
			assert(knot_serial_compare(sn_rr, sn_old) > 0);
			soa_end = knot_rrset_copy(rr, NULL);
			if (soa_end == NULL) {
				return KNOT_ENOMEM;
			}
		}
	}

	if (soa_end == NULL) {
		// No SOA in the update, create according to current policy
		if (knot_changeset_is_empty(changeset)) {
			// No change, no new SOA
			return KNOT_EOK;
		}

		soa_end = knot_rrset_copy(soa_begin, NULL);
		if (soa_end == NULL) {
			*rcode = KNOT_RCODE_SERVFAIL;
			return KNOT_ENOMEM;
		}
		knot_rrs_soa_serial_set(&soa_end->rrs, new_serial);
	}

	knot_changeset_add_soa(changeset, soa_end, KNOT_CHANGESET_ADD);
	return KNOT_EOK;
}
