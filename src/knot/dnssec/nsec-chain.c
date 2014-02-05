/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>

#include "libknot/rdata.h"
#include "libknot/util/debug.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/dnssec/zone-nsec.h"

/* - Forward declarations --------------------------------------------------- */

static knot_rrset_t *create_nsec_rrset(const knot_node_t *,
                                       const knot_node_t *,
                                       uint32_t);

/* - Helper functions ------------------------------------------------------- */

/*!
 * \brief Returns true if NSEC is only RRSet in node.
 */
static bool only_nsec_in_node(const knot_node_t *n)
{
	assert(n);
	return n->rrset_count == 1 && knot_node_rrset(n, KNOT_RRTYPE_NSEC);
}

/*!
 * \brief Updates last used node and DNAME.
 *
 * \param data  Data to be updated.
 * \param d     DNAME to be set.
 * \param n     Node to be set.
 */
static void update_last_used(chain_fix_data_t *data, const knot_dname_t *d,
                             const knot_node_t *n)
{
	assert(data && d);
	data->last_used_dname = d;
	data->last_used_node = n;
}

/*!
 * \brief Checks whether NSEC in zone is valid and updates it if needed.
 *
 * \param from     Start node for NSEC link.
 * \param to       End node for NSEC link.
 * \param out_ch   Changes are stored here.
 * \param soa_min  TTL to use for NSEC RRs.
 *
 * \return KNOT_E*
 */
static int update_nsec(const knot_node_t *from, const knot_node_t *to,
                       knot_changeset_t *out_ch, uint32_t soa_min)
{
	assert(from && to && out_ch);
	const knot_rrset_t *nsec_rrset = knot_node_rrset(from,
	                                                 KNOT_RRTYPE_NSEC);
	// Create new NSEC
	knot_rrset_t *new_nsec;
	if (only_nsec_in_node(from)) {
		// Just NSEC present, it has to be dropped
		new_nsec = NULL;
	} else {
		new_nsec = create_nsec_rrset(from, to, soa_min);
		if (new_nsec == NULL) {
			return KNOT_ERROR;
		}
	}

	// If node in zone has NSEC record, drop it if needed
	if (nsec_rrset && new_nsec) {
		if (!knot_rrset_equal(new_nsec, nsec_rrset,
		                      KNOT_RRSET_COMPARE_WHOLE)) {
			dbg_dnssec_detail("Creating new NSEC for %s\n",
			                  knot_dname_to_str(new_nsec->owner));
			// Drop old
			int ret = knot_nsec_changeset_remove(nsec_rrset,
			                                out_ch);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&new_nsec, 1, NULL);
				return ret;
			}
			// Add new
			ret = knot_changeset_add_rrset(out_ch, new_nsec,
			                               KNOT_CHANGESET_ADD);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&new_nsec, 1, NULL);
				return ret;
			}
		} else {
			// All good, no need to update
			knot_rrset_deep_free(&new_nsec, 1, NULL);
			return KNOT_EOK;
		}
	} else if (new_nsec) {
		// Add new NSEC record
		int ret = knot_changeset_add_rrset(out_ch, new_nsec,
		                                   KNOT_CHANGESET_ADD);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&new_nsec, 1, NULL);
			return ret;
		}
	} else {
		// Drop old, no longer needed
		int ret = knot_nsec_changeset_remove(nsec_rrset,
		                                out_ch);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&new_nsec, 1, NULL);
			return ret;
		}
	}
	return KNOT_EOK;
}

/* - NSEC chain construction ------------------------------------------------ */

/*!
 * \brief Create NSEC RR set.
 *
 * \param from       Node that should contain the new RRSet
 * \param to         Node that should be pointed to from 'from'
 * \param ttl        Record TTL (SOA's minimum TTL).
 *
 * \return NSEC RR set, NULL on error.
 */
static knot_rrset_t *create_nsec_rrset(const knot_node_t *from,
                                       const knot_node_t *to,
                                       uint32_t ttl)
{
	assert(from);
	assert(to);

	// Create new RRSet
	knot_dname_t *owner_cpy = knot_dname_copy(from->owner);
	knot_rrset_t *rrset = knot_rrset_new(owner_cpy,
	                                     KNOT_RRTYPE_NSEC, KNOT_CLASS_IN,
	                                     ttl, NULL);
	if (!rrset) {
		return NULL;
	}

	// Create bitmap
	bitmap_t rr_types = { 0 };
	bitmap_add_node_rrsets(&rr_types, from);
	bitmap_add_type(&rr_types, KNOT_RRTYPE_NSEC);
	bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);
	if (knot_node_rrset(from, KNOT_RRTYPE_SOA)) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_DNSKEY);
	}

	// Create RDATA
	assert(to->owner);
	size_t next_owner_size = knot_dname_size(to->owner);
	size_t rdata_size = next_owner_size + bitmap_size(&rr_types);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size, NULL);
	if (!rdata) {
		knot_rrset_free(&rrset);
		return NULL;
	}

	// Fill RDATA
	memcpy(rdata, to->owner, next_owner_size);
	bitmap_write(&rr_types, rdata + next_owner_size);

	return rrset;
}

/*!
 * \brief Connect two nodes by adding a NSEC RR into the first node.
 *
 * Callback function, signature chain_iterate_cb.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Pointer to nsec_chain_iterate_data_t holding parameters
 *              including changeset.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec_nodes(knot_node_t *a, knot_node_t *b,
                              nsec_chain_iterate_data_t *data)
{
	assert(a);
	assert(b);
	assert(data);

	if (b->rrset_count == 0 || knot_node_is_non_auth(b)) {
		return NSEC_NODE_SKIP;
	}

	knot_rrset_t *old_next_nsec = knot_node_get_rrset(b, KNOT_RRTYPE_NSEC);
	int ret = 0;

	/*!
	 * If the node has no other RRSets than NSEC (and possibly RRSIG),
	 * just remove the NSEC and its RRSIG, they are redundant
	 */
	if (old_next_nsec != NULL
	    && knot_node_rrset_count(b) == KNOT_NODE_RRSET_COUNT_ONLY_NSEC) {
		ret = knot_nsec_changeset_remove(old_next_nsec,
		                                 data->changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
		// Skip the 'b' node
		return NSEC_NODE_SKIP;
	}

	// create new NSEC
	knot_rrset_t *new_nsec = create_nsec_rrset(a, b, data->ttl);
	if (!new_nsec) {
		dbg_dnssec_detail("Failed to create new NSEC.\n");
		return KNOT_ENOMEM;
	}

	knot_rrset_t *old_nsec = knot_node_get_rrset(a, KNOT_RRTYPE_NSEC);
	if (old_nsec != NULL) {
		if (knot_rrset_equal(new_nsec, old_nsec,
		                     KNOT_RRSET_COMPARE_WHOLE)) {
			// current NSEC is valid, do nothing
			dbg_dnssec_detail("NSECs equal.\n");
			knot_rrset_deep_free(&new_nsec, 1, NULL);
			return KNOT_EOK;
		}

		dbg_dnssec_detail("NSECs not equal, replacing.\n");
		// current NSEC is invalid, replace it and drop RRSIG
		// mark the node, so later we know this NSEC needs new RRSIGs
		knot_node_set_replaced_nsec(a);
		ret = knot_nsec_changeset_remove(old_nsec, data->changeset);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&new_nsec, 1, NULL);
			return ret;
		}
	}

	dbg_dnssec_detail("Adding new NSEC to changeset.\n");
	// Add new NSEC to the changeset (no matter if old was removed)
	return knot_changeset_add_rrset(data->changeset, new_nsec,
	                                KNOT_CHANGESET_ADD);
}

/* - NSEC chain fix --------------------------------------------------------- */

/*!
 * \brief Handles node that has been deleted by DDNS/reload.
 *
 * \param node      Deleted node
 * \param fix_data  Chain fix data.
 *
 * \return KNOT_E*, NSEC_NODE_SKIP
 */
static int handle_deleted_node(const knot_node_t *node,
                               chain_fix_data_t *fix_data)
{
	if (node == NULL) {
		// This node was deleted and used to be non-auth
		assert(knot_node_is_non_auth(node));
		return NSEC_NODE_SKIP;
	}
	const knot_rrset_t *old_nsec = knot_node_rrset(node, KNOT_RRTYPE_NSEC);
	assert(old_nsec);
	int ret = knot_nsec_changeset_remove(old_nsec, fix_data->out_ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*!
	 * This node should be ignored, but we might need the next dname from
	 * previous node.
	 */
	if (fix_data->next_dname == NULL) {
		fix_data->next_dname =
			(knot_dname_t *)knot_rdata_nsec_next(old_nsec);
		assert(fix_data->next_dname);
	}

	return NSEC_NODE_SKIP;
}

/*!
 * \brief Fixes 'gaps' between old and new NSEC chain.
 *
 * \param fix_data  Chain fix data.
 * \param a         Dname that should be connected to old chain.
 * \param a_node    Node that should be connected to old chain.
 *
 * \return KNOT_E*, or NSEC_NODE_RESET if needed.
 */
static int handle_nsec_next_dname(chain_fix_data_t *fix_data,
                                  const knot_dname_t *a,
                                  const knot_node_t *a_node)
{
	assert(fix_data && fix_data->next_dname && a && a_node);
	int ret = KNOT_EOK;
	if (knot_dname_is_equal(fix_data->next_dname, a)) {
		// We cannot point to the same record here, extract next->next
		const knot_rrset_t *nsec_rrset =
			knot_node_rrset(a_node, KNOT_RRTYPE_NSEC);
		assert(nsec_rrset);
		const knot_node_t *next_node =
			knot_zone_contents_find_node(fix_data->zone,
			                             knot_rdata_nsec_next(nsec_rrset));
		assert(next_node);
		update_last_used(fix_data, next_node->owner, next_node);
		ret = update_nsec(a_node, next_node, fix_data->out_ch,
		                  fix_data->ttl);
	} else {
		// We have no immediate previous node, connect broken chain
		const knot_node_t *next_node =
			knot_zone_contents_find_node(fix_data->zone,
			                             fix_data->next_dname);
		assert(next_node);
		update_last_used(fix_data, next_node->owner, next_node);
		ret = update_nsec(a_node, next_node, fix_data->out_ch,
		                  fix_data->ttl);
	}
	fix_data->next_dname = NULL;
	return ret == KNOT_EOK ? NSEC_NODE_RESET : ret;
}

/*!
 * \brief Finds previous usable NSEC node in zone.
 *
 * \param z  Zone to be searched.
 * \param d  DNAME to search for.
 *
 * \return Previous NSEC node for 'd'.
 */
static const knot_node_t *find_prev_nsec_node(const knot_zone_contents_t *z,
                                              const knot_dname_t *d)
{
	// Find previous node for the dname, return node that will be used later
	const knot_node_t *prev_zone_node = knot_zone_contents_find_previous(z,
	                                                                     d);
	bool nsec_node_found = !knot_node_is_non_auth(prev_zone_node) &&
	                       !only_nsec_in_node(prev_zone_node);
	while (!nsec_node_found) {
		// Get previous node from zone tree
		prev_zone_node =
			knot_zone_contents_find_previous(z,
		                                         prev_zone_node->owner);
		assert(prev_zone_node);
		// Infinite loop check
		if (knot_dname_is_equal(d, prev_zone_node->owner)) {
				return prev_zone_node;
		}
		nsec_node_found = !knot_node_is_non_auth(prev_zone_node) &&
		                  !only_nsec_in_node(prev_zone_node);
	}
	assert(nsec_node_found);
	return prev_zone_node;
}

/*!
 * \brief Fixes NSEC chain for 'a' and 'b'. 'a' is always < 'b'.
 *
 * \param a         First DNAME from changeset.
 * \param b         Second DNAME from changeset.
 * \param fix_data  Chain fix data.
 *
 * \return KNOT_E*, NSEC_NODE_SKIP, NSEC_NODE_RESET if needed.
 */
static int fix_nsec_chain(knot_dname_t *a, knot_dname_t *b,
                          chain_fix_data_t *fix_data)
{
	assert(b);
	assert(fix_data);
	// Get changed nodes from zone
	const knot_node_t *b_node = knot_zone_contents_find_node(fix_data->zone,
	                                                         b);
	assert(b_node);
	if (knot_node_is_non_auth(b_node)) {
		// Nothing to fix in this node
		return NSEC_NODE_SKIP;
	}
	const knot_node_t *a_node = knot_zone_contents_find_node(fix_data->zone,
	                                                         a);
	// Find previous node in zone
	const knot_node_t *prev_zone_node = find_prev_nsec_node(fix_data->zone,
	                                                        b);
	if (prev_zone_node == NULL) {
		return KNOT_ERROR;
	}

	// Handle removals
	bool node_deleted = only_nsec_in_node(b_node);
	if (node_deleted) {
		/*!
		 * If DDNS only contains removals, we need at least
		 * one 'last_used_dname'.
		 */
		if (fix_data->last_used_dname == NULL) {
			assert(fix_data->last_used_node == NULL);
			update_last_used(fix_data, prev_zone_node->owner,
			                 prev_zone_node);
		}
		return handle_deleted_node(b_node, fix_data);
	}

	// Find out whether the previous node is also part of the changeset.
	bool dname_equal =
		a && knot_dname_is_equal(prev_zone_node->owner, a);
	if (dname_equal) {
		// No valid data for the previous node, create the forward link
		update_last_used(fix_data, b_node->owner, b_node);
		return update_nsec(a_node, b_node, fix_data->out_ch,
		                   fix_data->ttl);
	} else {
		// Use data from zone or next_dname
		if (fix_data->next_dname) {
			return handle_nsec_next_dname(fix_data, a, a_node);
		}

		// Previous node was not changed in DDNS, it has to have NSEC
		const knot_rrset_t *nsec_rrset =
			knot_node_rrset(prev_zone_node, KNOT_RRTYPE_NSEC);
		assert(nsec_rrset);
		const knot_node_t *next_node = b_node;

		// Store next node for next iterations
		fix_data->next_dname =
			(knot_dname_t *)knot_rdata_nsec_next(nsec_rrset);
		update_last_used(fix_data, next_node->owner, next_node);
		// Fix NSEC
		return update_nsec(prev_zone_node, next_node, fix_data->out_ch,
		                   fix_data->ttl);
	}

	return KNOT_EOK;
}

/*!
 * \brief Wrapper for iteration function to be used with NSEC,
 *        shortens the code a bit.
 */
static int fix_nsec_chain_wrap(knot_dname_t *a, knot_dname_t *a_hash,
                               knot_dname_t *b, knot_dname_t *b_hash,
                               chain_fix_data_t *d)
{
	UNUSED(a_hash);
	UNUSED(b_hash);
	return fix_nsec_chain(a, b, d);
}

/*!
 * \brief Finalizes NSEC chain.
 *
 * \param d  Fix data.
 *
 * \return KNOT_E*
 */
static int chain_finalize_nsec(chain_fix_data_t *fix_data)
{
	assert(fix_data);
	assert(fix_data->last_used_dname && fix_data->next_dname);
	const knot_node_t *from = fix_data->last_used_node;
	assert(from);
	const knot_node_t *to = NULL;
	if (knot_dname_is_equal(fix_data->last_used_dname,
	                        fix_data->zone->apex->owner)) {
		// Everything but the apex deleted
		to = fix_data->zone->apex;
	} else if (knot_dname_is_equal(fix_data->last_used_dname,
	                               fix_data->next_dname)) {
		// NSEC cannot point to itself (except for the case above)
		const knot_rrset_t *nsec_rrset =
			knot_node_rrset(from, KNOT_RRTYPE_NSEC);
		to = knot_zone_contents_find_node(fix_data->zone,
		                                  knot_rdata_nsec_next(nsec_rrset));
	} else {
		// Normal case
		to = knot_zone_contents_find_node(fix_data->zone,
		                                  fix_data->next_dname);
	}
	assert(to);
	return update_nsec(from, to, fix_data->out_ch, fix_data->ttl);
}

/* - API - iterations ------------------------------------------------------- */

/*!
 * \brief Call a function for each piece of the chain formed by sorted nodes.
 */
int knot_nsec_chain_iterate_create(knot_zone_tree_t *nodes,
                                   chain_iterate_create_cb callback,
                                   nsec_chain_iterate_data_t *data)
{
	assert(nodes);
	assert(callback);

	bool sorted = true;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);

	if (!it) {
		return KNOT_ENOMEM;
	}

	if (hattrie_iter_finished(it)) {
		hattrie_iter_free(it);
		return KNOT_EINVAL;
	}

	knot_node_t *first = (knot_node_t *)*hattrie_iter_val(it);
	knot_node_t *previous = first;
	knot_node_t *current = first;

	hattrie_iter_next(it);

	int result = KNOT_EOK;
	while (!hattrie_iter_finished(it)) {
		current = (knot_node_t *)*hattrie_iter_val(it);

		result = callback(previous, current, data);
		if (result == NSEC_NODE_SKIP) {
			// No NSEC should be created for 'current' node, skip
			;
		} else if (result == KNOT_EOK) {
			previous = current;
		} else {
			hattrie_iter_free(it);
			return result;
		}
		hattrie_iter_next(it);
	}

	hattrie_iter_free(it);

	return result == NSEC_NODE_SKIP ? callback(previous, first, data) :
	                 callback(current, first, data);
}


/*!
 * \brief Iterates sorted changeset and calls callback function - works for
 *        NSEC and NSEC3 chain.
 */
int knot_nsec_chain_iterate_fix(hattrie_t *nodes, chain_iterate_fix_cb callback,
                                chain_finalize_cb finalize,
                                chain_fix_data_t *data)
{
	assert(nodes);
	assert(callback);

	bool sorted = true;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);

	if (!it) {
		return KNOT_ENOMEM;
	}

	if (hattrie_iter_finished(it)) {
		hattrie_iter_free(it);
		return KNOT_EINVAL;
	}

	knot_dname_t *previous_original = NULL;
	knot_dname_t *previous_hashed = NULL;
	knot_dname_t *current_original = NULL;
	knot_dname_t *current_hashed = NULL;

	int result = KNOT_EOK;
	while (!hattrie_iter_finished(it)) {
		signed_info_t *val = (signed_info_t *)(*hattrie_iter_val(it));
		current_original = val->dname;
		current_hashed = val->hashed_dname;

		result = callback(previous_original, previous_hashed,
		                  current_original, current_hashed, data);
		if (result == NSEC_NODE_SKIP) {
			// No NSEC should be created for 'current' node, skip
			hattrie_iter_next(it);
		} else if (result == NSEC_NODE_RESET) {
			/*!
			 * Used previous node, call once again so that
			 * we don't lose this current node.
			 */
			previous_original = NULL;
			previous_hashed = NULL;
		} else if (result == KNOT_EOK) {
			previous_original = current_original;
			previous_hashed = current_hashed;
			hattrie_iter_next(it);
		} else {
			hattrie_iter_free(it);
			return result;
		}
	}

	hattrie_iter_free(it);

	return finalize(data);
}

/* - API - utility functions ------------------------------------------------ */

/*!
 * \brief Add entry for removed NSEC to the changeset.
 */
int knot_nsec_changeset_remove(const knot_rrset_t *oldrr,
                               knot_changeset_t *changeset)
{
	if (oldrr == NULL) {
		return KNOT_EOK;
	}
	if (changeset == NULL) {
		return KNOT_EINVAL;
	}

	int result;

	// extract copy of NSEC and RRSIG

	knot_rrset_t *old_nsec = NULL;
	knot_rrset_t *old_rrsigs = NULL;

	result = knot_rrset_deep_copy(oldrr, &old_nsec, NULL);
	if (result != KNOT_EOK) {
		return result;
	}

	old_rrsigs = old_nsec->rrsigs;
	old_nsec->rrsigs = NULL;

	// update changeset

	result = knot_changeset_add_rrset(changeset, old_nsec,
	                                  KNOT_CHANGESET_REMOVE);
	if (result != KNOT_EOK) {
		knot_rrset_deep_free(&old_nsec, 1, NULL);
		knot_rrset_deep_free(&old_rrsigs, 1, NULL);
		return result;
	}

	if (old_rrsigs) {
		result = knot_changeset_add_rrset(changeset, old_rrsigs,
		                                  KNOT_CHANGESET_REMOVE);
		if (result != KNOT_EOK) {
			knot_rrset_deep_free(&old_rrsigs, 1, NULL);
			return result;
		}
	}

	return KNOT_EOK;
}

/* - API - Chain creation and fix ------------------------------------------- */

/*!
 * \brief Create new NSEC chain, add differences from current into a changeset.
 */
int knot_nsec_create_chain(const knot_zone_contents_t *zone, uint32_t ttl,
                           knot_changeset_t *changeset)
{
	assert(zone);
	assert(zone->nodes);
	assert(changeset);

	nsec_chain_iterate_data_t data = { ttl, changeset, zone };

	return knot_nsec_chain_iterate_create(zone->nodes,
	                                      connect_nsec_nodes, &data);
}

/*!
 * \brief Fixes NSEC chain after DDNS/reload
 */
int knot_nsec_fix_chain(hattrie_t *sorted_changes,
                        chain_fix_data_t *fix_data)
{
	if (sorted_changes == NULL || fix_data == NULL) {
		return KNOT_EINVAL;
	}

	hattrie_build_index(sorted_changes);
	return knot_nsec_chain_iterate_fix(sorted_changes, fix_nsec_chain_wrap,
	                                   chain_finalize_nsec, fix_data);
}
