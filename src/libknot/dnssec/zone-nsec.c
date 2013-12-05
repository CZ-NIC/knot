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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "common/base32hex.h"
#include "common/descriptor.h"
#include "common/hhash.h"
#include "libknot/dnssec/nsec-bitmap.h"
#include "libknot/dnssec/nsec3.h"
#include "libknot/dnssec/zone-nsec.h"
#include "libknot/dnssec/zone-sign.h"
#include "libknot/rdata.h"
#include "libknot/util/debug.h"
#include "libknot/util/utils.h"
#include "libknot/util/wire.h"
#include "libknot/zone/zone-contents.h"
#include "libknot/zone/zone-diff.h"

/*!
 * \brief Parameters to be used in connect_nsec_nodes callback.
 */
typedef struct {
	uint32_t ttl;
	knot_changeset_t *changeset;
	const knot_zone_contents_t *zone;
} nsec_chain_iterate_data_t;

#define NSEC_NODE_SKIP 1

/* - NSEC chain iteration -------------------------------------------------- */

typedef int (*chain_iterate_cb)(knot_node_t *, knot_node_t *, void *);
typedef int (*chain_iterate_nsec_cb)(knot_dname_t *, knot_dname_t *, void *);

/*!
 * \brief Call a function for each piece of the chain formed by sorted nodes.
 *
 * \note If the callback function returns anything other than KNOT_EOK, the
 *       iteration is terminated and the error code is propagated.
 *
 * \param nodes     Zone nodes.
 * \param callback  Callback function.
 * \param data      Custom data supplied to the callback function.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int chain_iterate(knot_zone_tree_t *nodes, chain_iterate_cb callback,
                         void *data)
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

	/*!< \todo Remove direct hattrie calls. */
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
 * \brief Call a function for each piece of the chain formed by sorted nodes.
 *
 * \note If the callback function returns anything other than KNOT_EOK, the
 *       iteration is terminated and the error code is propagated.
 *
 * \param nodes     Zone nodes.
 * \param callback  Callback function.
 * \param data      Custom data supplied to the callback function.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int chain_iterate_nsec(hattrie_t *nodes, chain_iterate_nsec_cb callback,
                              void *data)
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

	knot_dname_t *previous = NULL;
	knot_dname_t *current = NULL;

	int result = KNOT_EOK;
	while (!hattrie_iter_finished(it)) {
		current = ((signed_info_t *)(*hattrie_iter_val(it)))->dname;

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

	return result == NSEC_NODE_SKIP && previous ?
	                 callback(NULL, previous, data) :
	                 callback(NULL, current, data);
}

/*!
 * \brief Add entry for removed NSEC to the changeset.
 *
 * \param oldrr      Old NSEC RR set to be removed (including RRSIG).
 * \param changeset  Changeset to add the old RR into.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int changeset_remove_nsec(const knot_rrset_t *oldrr,
                                 knot_changeset_t *changeset)
{
	assert(oldrr);
	assert(changeset);

	int result;

	// extract copy of NSEC and RRSIG

	knot_rrset_t *old_nsec = NULL;
	knot_rrset_t *old_rrsigs = NULL;

	result = knot_rrset_deep_copy(oldrr, &old_nsec);
	if (result != KNOT_EOK) {
		return result;
	}

	old_rrsigs = old_nsec->rrsigs;
	old_nsec->rrsigs = NULL;

	// update changeset

	result = knot_changeset_add_rrset(changeset, old_nsec,
	                                  KNOT_CHANGESET_REMOVE);
	if (result != KNOT_EOK) {
		knot_rrset_deep_free(&old_nsec, 1);
		knot_rrset_deep_free(&old_rrsigs, 1);
		return result;
	}

	if (old_rrsigs) {
		result = knot_changeset_add_rrset(changeset, old_rrsigs,
		                                  KNOT_CHANGESET_REMOVE);
		if (result != KNOT_EOK) {
			knot_rrset_deep_free(&old_rrsigs, 1);
			return result;
		}
	}

	return KNOT_EOK;
}

/* - NSEC nodes construction ----------------------------------------------- */

/*!
 * \brief Create NSEC RR set.
 *
 * \param from       Node that should contain the new RRSet
 * \param to         Node that should be pointed to from 'from'
 * \param ttl        Record TTL (SOA's minimun TTL).
 * \param from_apex  Indicates that 'from' node is zone apex node.
 *
 * \return NSEC RR set, NULL on error.
 */
static knot_rrset_t *create_nsec_rrset(const knot_node_t *from,
                                       const knot_node_t *to,
                                       uint32_t ttl, bool from_apex)
{
	assert(from);
	assert(to);

	// Create new RRSet
	knot_dname_t *owner_cpy = knot_dname_copy(from->owner);
	knot_rrset_t *rrset = knot_rrset_new(owner_cpy,
	                                     KNOT_RRTYPE_NSEC, KNOT_CLASS_IN,
	                                     ttl);
	if (!rrset) {
		return NULL;
	}

	// Create bitmap
	bitmap_t rr_types = { 0 };
	bitmap_add_node_rrsets(&rr_types, from);
	bitmap_add_type(&rr_types, KNOT_RRTYPE_NSEC);
	bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);
	if (from_apex) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_DNSKEY);
	}

	// Create RDATA
	assert(to->owner);
	size_t next_owner_size = knot_dname_size(to->owner);
	size_t rdata_size = next_owner_size + bitmap_size(&rr_types);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
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
 * \param a  First node.
 * \param b  Second node (immediate follower of a).
 * \param d  Pointer to nsec_chain_iterate_data_t holding parameters
 *           including changeset.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec_nodes(knot_node_t *a, knot_node_t *b, void *d)
{
	assert(a);
	assert(b);
	assert(d);

	if (b->rrset_count == 0 || knot_node_is_non_auth(b)) {
		return NSEC_NODE_SKIP;
	}

	nsec_chain_iterate_data_t *data = (nsec_chain_iterate_data_t *)d;
	knot_rrset_t *old_next_nsec = knot_node_get_rrset(b, KNOT_RRTYPE_NSEC);
	int ret = 0;

	/*!
	 * If the node has no other RRSets than NSEC (and possibly RRSIG),
	 * just remove the NSEC and its RRSIG, they are redundant
	 */
	if (old_next_nsec != NULL
	    && knot_node_rrset_count(b) == KNOT_NODE_RRSET_COUNT_ONLY_NSEC) {
		ret = changeset_remove_nsec(old_next_nsec, data->changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
		// Skip the 'b' node
		return NSEC_NODE_SKIP;
	}

	// create new NSEC
	bool a_is_apex = a == data->zone->apex;
	knot_rrset_t *new_nsec = create_nsec_rrset(a, b, data->ttl, a_is_apex);
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
			knot_rrset_deep_free(&new_nsec, 1);
			return KNOT_EOK;
		}

		dbg_dnssec_detail("NSECs not equal, replacing.\n");
		// current NSEC is invalid, replace it and drop RRSIG
		// mark the node, so later we know this NSEC needs new RRSIGs
		knot_node_set_replaced_nsec(a);
		ret = changeset_remove_nsec(old_nsec, data->changeset);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&new_nsec, 1);
			return ret;
		}
	}

	dbg_dnssec_detail("Adding new NSEC to changeset.\n");
	// Add new NSEC to the changeset (no matter if old was removed)
	return knot_changeset_add_rrset(data->changeset, new_nsec,
	                                KNOT_CHANGESET_ADD);
}

/*!
 * \brief Create new NSEC chain, add differences from current into a changeset.
 *
 * \param zone       Zone.
 * \param ttl        TTL for created NSEC records.
 * \param changeset  Changeset the differences will be put into.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec_chain(const knot_zone_contents_t *zone, uint32_t ttl,
			     knot_changeset_t *changeset)
{
	assert(zone);
	assert(zone->nodes);
	assert(changeset);

	nsec_chain_iterate_data_t data = { ttl, changeset, zone };

	return chain_iterate(zone->nodes, connect_nsec_nodes, &data);
}

/* - NSEC3 nodes comparison ------------------------------------------------ */

/*!
 * \brief Perform some basic checks that the node is valid NSEC3 node.
 */
inline static bool valid_nsec3_node(const knot_node_t *node)
{
	assert(node);

	if (node->rrset_count != 1) {
		return false;
	}

	if (node->rrset_tree[0]->type != KNOT_RRTYPE_NSEC3) {
		return false;
	}

	if (node->rrset_tree[0]->rdata_count != 1) {
		return false;
	}

	return true;
}

/*!
 * \brief Check if two nodes are equal.
 */
static bool are_nsec3_nodes_equal(const knot_node_t *a, const knot_node_t *b)
{
	assert(valid_nsec3_node(a));
	assert(valid_nsec3_node(b));

	knot_rrset_t *a_rrset = a->rrset_tree[0];
	knot_rrset_t *b_rrset = b->rrset_tree[0];

	return knot_rrset_equal(a_rrset, b_rrset, KNOT_RRSET_COMPARE_WHOLE);
}

/* - RRSIGs handling for NSEC3 --------------------------------------------- */

/*!
 * \brief Shallow copy NSEC3 signatures from the one node to the second one.
 *
 * Just sets the pointer, needed only for comparison.
 */
static void shallow_copy_signature(const knot_node_t *from, knot_node_t *to)
{
	assert(valid_nsec3_node(from));
	assert(valid_nsec3_node(to));

	knot_rrset_t *from_rrset = from->rrset_tree[0];
	knot_rrset_t *to_rrset = to->rrset_tree[0];

	assert(to_rrset->rrsigs == NULL);

	to_rrset->rrsigs = from_rrset->rrsigs;
}

/*!
 * \brief Reuse signatatures by shallow copying them from one tree to another.
 */
static void copy_signatures(const knot_zone_tree_t *from, knot_zone_tree_t *to)
{
	assert(from);
	assert(to);

	bool sorted = false;
	/*! \todo Remove direct hattrie calls */
	hattrie_iter_t *it = hattrie_iter_begin(from, sorted);

	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		knot_node_t *node_from = (knot_node_t *)*hattrie_iter_val(it);
		knot_node_t *node_to = NULL;

		knot_zone_tree_get(to, node_from->owner, &node_to);
		if (node_to == NULL) {
			continue;
		}

		if (!are_nsec3_nodes_equal(node_from, node_to)) {
			continue;
		}

		shallow_copy_signature(node_from, node_to);
	}

	hattrie_iter_free(it);
}

/* - NSEC3 nodes construction ---------------------------------------------- */

/*!
 * \brief Get NSEC3 RDATA size.
 */
static size_t nsec3_rdata_size(const knot_nsec3_params_t *params,
                               const bitmap_t *rr_types)
{
	assert(params);
	assert(rr_types);

	return 6 + params->salt_length
	       + knot_nsec3_hash_length(params->algorithm)
	       + bitmap_size(rr_types);
}

/*!
 * \brief Fill NSEC3 RDATA.
 *
 * \note Content of next hash field is not changed.
 */
static void nsec3_fill_rdata(uint8_t *rdata, const knot_nsec3_params_t *params,
                             const bitmap_t *rr_types, uint32_t ttl)
{
	assert(rdata);
	assert(params);
	assert(rr_types);

	uint8_t hash_length = knot_nsec3_hash_length(params->algorithm);

	*rdata = params->algorithm;                       // hash algorithm
	rdata += 1;
	*rdata = 0;                                       // flags
	rdata += 1;
	knot_wire_write_u16(rdata, params->iterations);   // iterations
	rdata += 2;
	*rdata = params->salt_length;                     // salt length
	rdata += 1;
	memcpy(rdata, params->salt, params->salt_length); // salt
	rdata += params->salt_length;
	*rdata = hash_length;                             // hash length
	rdata += 1;
	/*memset(rdata, '\0', hash_len);*/                // hash (unknown)
	rdata += hash_length;
	bitmap_write(rr_types, rdata);                    // RR types bit map
}

/*!
 * \brief Create NSEC3 RR set.
 */
static knot_rrset_t *create_nsec3_rrset(knot_dname_t *owner,
                                        const knot_nsec3_params_t *params,
                                        const bitmap_t *rr_types,
                                        uint32_t ttl)
{
	assert(owner);
	assert(params);
	assert(rr_types);

	knot_rrset_t *rrset;
	rrset = knot_rrset_new(owner, KNOT_RRTYPE_NSEC3, KNOT_CLASS_IN, ttl);
	if (!rrset) {
		return NULL;
	}

	size_t rdata_size = nsec3_rdata_size(params, rr_types);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size);
	if (!rdata) {
		knot_rrset_free(&rrset);
		return NULL;
	}

	nsec3_fill_rdata(rdata, params, rr_types, ttl);

	return rrset;
}

/*!
 * \brief Create NSEC3 node.
 */
static knot_node_t *create_nsec3_node(knot_dname_t *owner,
                                      const knot_nsec3_params_t *nsec3_params,
                                      knot_node_t *apex_node,
                                      const bitmap_t *rr_types,
                                      uint32_t ttl)
{
	assert(owner);
	assert(nsec3_params);
	assert(apex_node);
	assert(rr_types);

	uint8_t flags = 0;
	knot_node_t *new_node = knot_node_new(owner, apex_node, flags);
	if (!new_node) {
		return NULL;
	}

	knot_rrset_t *nsec3_rrset;
	nsec3_rrset = create_nsec3_rrset(owner, nsec3_params, rr_types, ttl);
	if (!nsec3_rrset) {
		knot_node_free(&new_node);
		return NULL;
	}

	if (knot_node_add_rrset_no_merge(new_node, nsec3_rrset) != KNOT_EOK) {
		knot_rrset_free(&nsec3_rrset);
		knot_node_free(&new_node);
		return NULL;
	}

	return new_node;
}

/*!
 * \brief Connect two nodes by filling 'hash' field of NSEC3 RDATA of the node.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Unused parameter.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec3_nodes(knot_node_t *a, knot_node_t *b, void *data)
{
	assert(a);
	assert(b);
	UNUSED(data);

	assert(a->rrset_count == 1);

	uint8_t algorithm = knot_rdata_nsec3_algorithm(a->rrset_tree[0], 0);
	if (algorithm == 0) {
		return KNOT_EINVAL;
	}

	uint8_t *raw_hash = NULL;
	uint8_t raw_length = 0;
	knot_rdata_nsec3_next_hashed(a->rrset_tree[0], 0, &raw_hash, &raw_length);
	if (raw_hash == NULL) {
		return KNOT_EINVAL;
	}

	assert(raw_length == knot_nsec3_hash_length(algorithm));

	uint8_t *b32_hash = (uint8_t *)knot_dname_to_str(b->owner);
	size_t b32_length = knot_nsec3_hash_b32_length(algorithm);
	if (!b32_hash) {
		return KNOT_ENOMEM;
	}

	int32_t written = base32hex_decode(b32_hash, b32_length,
	                                   raw_hash, raw_length);

	free(b32_hash);

	if (written != raw_length) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

/*!
 * \brief Check whether at least one RR type in node should be signed
 *
 * \param node  Node for which the check is done.
 *
 * \return true/false.
 */
static bool node_should_be_signed(const knot_node_t *n)
{
	knot_rrset_t **node_rrsets = knot_node_get_rrsets_no_copy(n);
	for (int i = 0; i < n->rrset_count; i++) {
		if (knot_zone_sign_rr_should_be_signed(n, node_rrsets[i],
		                                       NULL)) {
			return true;
		}
	}

	return false;
}

/*!
 * \brief Create new NSEC3 node for given regular node.
 *
 * \param node       Node for which the NSEC3 node is created.
 * \param apex       Zone apex node.
 * \param params     NSEC3 hash function parameters.
 * \param ttl        TTL of the new NSEC3 node.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static knot_node_t *create_nsec3_node_for_node(knot_node_t *node,
                                               knot_node_t *apex,
                                               const knot_nsec3_params_t *params,
                                               uint32_t ttl)
{
	assert(node);
	assert(apex);
	assert(params);

	knot_dname_t *nsec3_owner;
	nsec3_owner = create_nsec3_owner(node->owner, apex->owner, params);
	if (!nsec3_owner) {
		return NULL;
	}

	bitmap_t rr_types = { 0 };
	bitmap_add_node_rrsets(&rr_types, node);
	if (node->rrset_count > 0 && node_should_be_signed(node)) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);
	}
	if (node == apex) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_DNSKEY);
	}

	knot_node_t *nsec3_node;
	nsec3_node = create_nsec3_node(nsec3_owner, params, apex, &rr_types, ttl);

	return nsec3_node;
}

/*!
 * \brief Create NSEC3 node for each regular node in the zone.
 *
 * \param zone         Zone.
 * \param ttl          TTL for the created NSEC records.
 * \param nsec3_nodes  Tree whereto new NSEC3 nodes will be added.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec3_nodes(const knot_zone_contents_t *zone, uint32_t ttl,
                              knot_zone_tree_t *nsec3_nodes)
{
	assert(zone);
	assert(nsec3_nodes);

	const knot_nsec3_params_t *params = &zone->nsec3_params;

	assert(params);

	int result = KNOT_EOK;

	int sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(zone->nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);

		if (knot_node_is_non_auth(node)) {
			hattrie_iter_next(it);
			continue;
		}

		knot_node_t *nsec3_node;
		nsec3_node = create_nsec3_node_for_node(node, zone->apex,
		                                        params, ttl);
		if (!nsec3_node) {
			result = KNOT_ENOMEM;
			break;
		}

		result = knot_zone_tree_insert(nsec3_nodes, nsec3_node);
		if (result != KNOT_EOK) {
			break;
		}

		hattrie_iter_next(it);
	}

	hattrie_iter_free(it);

	/* Rebuild index over nsec3 nodes. */
	hattrie_build_index(nsec3_nodes);

	return result;
}

/*!
 * \brief Custom NSEC3 tree free function.
 *
 * - Leaves RRSIGs, as these are only referenced (shallow copied).
 * - Deep frees NSEC3 RRs, as these nodes were created.
 *
 */
static void free_nsec3_tree(knot_zone_tree_t *nodes)
{
	assert(nodes);

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);
	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);

		for (int i = 0; i < node->rrset_count; i++) {
			// referenced RRSIGs from old NSEC3 tree
			node->rrset_tree[i]->rrsigs = NULL;
			// newly allocated NSEC3 nodes
			knot_rrset_deep_free(&node->rrset_tree[i], 1);
		}

		knot_node_free(&node);
	}

	hattrie_iter_free(it);
	knot_zone_tree_free(&nodes);
}

/*!
 * \brief Create new NSEC3 chain, add differences from current into a changeset.
 */
static int create_nsec3_chain(const knot_zone_contents_t *zone, uint32_t ttl,
			      knot_changeset_t *changeset)
{
	assert(zone);
	assert(changeset);

	int result;

	knot_zone_tree_t *nsec3_nodes = knot_zone_tree_create();
	if (!nsec3_nodes) {
		return KNOT_ENOMEM;
	}

	result = create_nsec3_nodes(zone, ttl, nsec3_nodes);
	if (result != KNOT_EOK) {
		free_nsec3_tree(nsec3_nodes);
		return result;
	}

	result = chain_iterate(nsec3_nodes, connect_nsec3_nodes, NULL);
	if (result != KNOT_EOK) {
		free_nsec3_tree(nsec3_nodes);
		return result;
	}

	copy_signatures(zone->nsec3_nodes, nsec3_nodes);

	result = knot_zone_tree_add_diff(zone->nsec3_nodes, nsec3_nodes,
	                                 changeset);

	free_nsec3_tree(nsec3_nodes);

	return result;
}

static int delete_nsec3_chain(const knot_zone_contents_t *zone,
                              knot_changeset_t *changeset)
{
	assert(zone);
	assert(zone->nsec3_nodes);
	assert(changeset);

	if (knot_zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	dbg_dnssec_detail("deleting NSEC3 chain\n");
	knot_zone_tree_t *empty_tree = knot_zone_tree_create();
	if (!empty_tree) {
		return KNOT_ENOMEM;
	}

	int result = knot_zone_tree_add_diff(zone->nsec3_nodes, empty_tree,
	                                     changeset);

	knot_zone_tree_free(&empty_tree);

	return result;
}

/* - helper functions ------------------------------------------------------ */

/*!
 * \brief Check if NSEC3 is enabled for given zone.
 */
bool is_nsec3_enabled(const knot_zone_contents_t *zone)
{
	if (!zone) {
		return false;
	}

	return zone->nsec3_params.algorithm != 0;
}

/*!
 * \brief Get minimum TTL from zone SOA.
 * \note Value should be used for NSEC records.
 */
static bool get_zone_soa_min_ttl(const knot_zone_contents_t *zone,
                                 uint32_t *ttl)
{
	assert(zone);
	assert(zone->apex);
	assert(ttl);

	knot_node_t *apex = zone->apex;
	knot_rrset_t *soa = knot_node_get_rrset(apex, KNOT_RRTYPE_SOA);
	if (!soa) {
		return false;
	}

	uint32_t result =  knot_rdata_soa_minimum(soa);
	if (result == 0) {
		return false;
	}

	*ttl = result;
	return true;
}

static int walk_dname_and_store_empty_nonterminals(knot_dname_t *dname,
	const knot_zone_contents_t *zone, hhash_t *t)
{
	assert(dname);
	assert(zone);
	assert(t);

	if (knot_dname_size(dname) == 1) {
		// Root dname
		assert(*dname == '\0');
		return KNOT_EOK;
	}

	// Start after the first cut
	const knot_dname_t *cut = knot_wire_next_label(dname, NULL);
	while (*cut != '\0') {
		// Search for name in the zone
		const knot_node_t *n = knot_zone_contents_find_node(zone, cut);
		if (n == NULL || n->rrset_count == 0) {
			/*!
			 * n == NULL:
			 * This means that RR *removal* caused non-terminal
			 * deletion - NSEC3 has to be dropped.
			 *
			 * n->rrset_count == 0:
			 * This means that RR *addition* created new empty
			 * non-terminal - NSEC3 has to be added.
			 */

			// Convert dname to sortable format
			uint8_t lf[KNOT_DNAME_MAXLEN];
			knot_dname_lf(lf, n->owner, NULL);
			// Store into trie (duplicates 'rewritten')
			hhash_insert(t, (char *)lf+1, *lf, n->owner);
		}
		cut = knot_wire_next_label(dname, NULL);
	}
	return KNOT_EOK;
}
/*!
 * \brief Cuts labels and looks for nodes in zone, if an empty node is found
 *        adds it into trie. There may be multiple nodes. Not all nodes
 *        have to be checked, but doing that would bloat the code.
 */
static int update_changes_with_non_terminals(const knot_zone_contents_t *zone,
                                             hattrie_t *sorted_changes)
{
	assert(zone);
	assert(is_nsec3_enabled(zone));
	assert(sorted_changes);

	/*!
	 * Create table with newly created nonterminals, as we cannot
	 * insert to the trie in the middle of iteration. Also useful
	 * because it will filter duplicated added nonterminals.
	 */
	hhash_t *nterminal_t = hhash_create(hattrie_size(sorted_changes));
	if (nterminal_t == NULL) {
		return KNOT_ENOMEM;
	}

	// Start trie iteration
	const bool sort = false;
	hattrie_iter_t *itt = hattrie_iter_begin(sorted_changes, sort);
	if (itt == NULL) {
		return KNOT_ERROR;
	}
	for (; !hattrie_iter_finished(itt); hattrie_iter_next(itt)) {
		signed_info_t *info = (signed_info_t *)*hattrie_iter_val(itt);
		knot_dname_t *node_dname = info->dname;
		assert(node_dname);
		int ret = walk_dname_and_store_empty_nonterminals(node_dname,
		                                                  zone,
		                                                  nterminal_t);
		if (ret != KNOT_EOK) {
			hhash_free(nterminal_t);
			return ret;
		}
	}
	hattrie_iter_free(itt);

	// Reinsert ahtable values into trie (dname already converted)
	hhash_iter_t ith = { '\0' };
	hhash_iter_begin(nterminal_t, &ith, sort);
	for (; !hhash_iter_finished(&ith); hhash_iter_next(&ith)) {
		// Store keys from table directly to trie
		uint16_t key_size = 0;
		const char *k = hhash_iter_key(&ith, &key_size);
		assert(k && key_size > 0);
		// Create dummy value
		signed_info_t *info = malloc(sizeof(signed_info_t));
		if (info == NULL) {
			ERR_ALLOC_FAILED;
			hhash_free(nterminal_t);
			return KNOT_ENOMEM;
		}
		memset(info, 0, sizeof(signed_info_t));
		info->dname =
			knot_dname_copy((knot_dname_t *)(*hhash_iter_val(&ith)));
		if (info->dname == NULL) {
			hhash_free(nterminal_t);
			return KNOT_ENOMEM;
		}
		*hattrie_get(sorted_changes, k, key_size) = info;
	}

	hhash_free(nterminal_t);

	return KNOT_EOK;
}

static int create_nsec3_hashes_from_trie(const hattrie_t *sorted_changes,
                                         const knot_zone_contents_t *zone,
                                         hattrie_t **out)
{
	assert(sorted_changes);
	assert(hattrie_size(sorted_changes) > 0);
	*out = hattrie_create();
	if (*out == NULL) {
		return KNOT_ENOMEM;
	}

	const bool sort = false;
	hattrie_iter_t *itt = hattrie_iter_begin(sorted_changes, sort);
	if (itt == NULL) {
		return KNOT_ERROR;
	}

	for (; !hattrie_iter_finished(itt); hattrie_iter_next(itt)) {
		knot_dname_t *nsec3_name =
			create_nsec3_owner((knot_dname_t *)*hattrie_iter_val(itt),
		                           zone->apex->owner,
		                           &zone->nsec3_params);
		if (nsec3_name == NULL) {
			return KNOT_ERROR;
		}
		hattrie_insert_dname(*out, nsec3_name);
	}
	hattrie_iter_free(itt);
	return KNOT_EOK;
}

static bool only_nsec_in_node(const knot_node_t *n)
{
	assert(n);
	return n->rrset_count == 1 && knot_node_rrset(n, KNOT_RRTYPE_NSEC);
}

static int update_nsec(const knot_node_t *from, const knot_node_t *to,
                       knot_changeset_t *out_ch, uint32_t soa_min,
                       bool is_apex)
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
		new_nsec = create_nsec_rrset(from, to, soa_min, is_apex);
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
			int ret = changeset_remove_nsec(nsec_rrset,
			                                out_ch);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&new_nsec, 1);
				return ret;
			}
			// Add new
			ret = knot_changeset_add_rrset(out_ch, new_nsec,
			                               KNOT_CHANGESET_ADD);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&new_nsec, 1);
				return ret;
			}
		} else {
			// All good, no need to update
			knot_rrset_deep_free(&new_nsec, 1);
			return KNOT_EOK;
		}
	} else if (new_nsec) {
		// Add new NSEC record
		int ret = knot_changeset_add_rrset(out_ch, new_nsec,
		                                   KNOT_CHANGESET_ADD);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&new_nsec, 1);
			return ret;
		}
	} else {
		// Drop old, no longer needed
		int ret = changeset_remove_nsec(nsec_rrset,
		                                out_ch);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&new_nsec, 1);
			return ret;
		}
	}
	return KNOT_EOK;
}

typedef struct chain_fix_data {
	const knot_zone_contents_t *zone;
	knot_changeset_t *out_ch;
	const knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	const knot_dname_t *next_dname;
} chain_fix_data_t;

static const knot_node_t *find_prev_nsec_node(const knot_zone_contents_t *z,
                                              const knot_node_t *n)
{
	// Find previous node for the node
	bool nsec_node_found = false;
	const knot_node_t *prev_zone_node = n;
	while (!nsec_node_found) {
		// Get previous node from zone tree
		prev_zone_node =
			knot_zone_contents_find_previous(z,
		                                         prev_zone_node->owner);
		assert(prev_zone_node);
		// Sanity check
		if (knot_dname_is_equal(n->owner, prev_zone_node->owner)) {
			if (z->apex == prev_zone_node) {
				// Only apex in zone and changed in DDNS
				assert(hattrie_size(z->nodes) == 1);
				return prev_zone_node;
			} else {
				/*!
				 * Something is really wrong here -
				 * maybe the zone is unsigned?
				 */
				return NULL;
			}
		}
		nsec_node_found = !knot_node_is_non_auth(prev_zone_node) &&
		                  !only_nsec_in_node(prev_zone_node);
	}
	assert(nsec_node_found);
	return prev_zone_node;
}

static int handle_removed_node(const knot_node_t *node,
                               const knot_node_t *prev_zone_node,
                               chain_fix_data_t *fix_data)
{
	const knot_rrset_t *old_nsec = knot_node_rrset(node, KNOT_RRTYPE_NSEC);
	assert(old_nsec);
	int ret = changeset_remove_nsec(old_nsec, fix_data->out_ch);
	if (ret != KNOT_EOK) {
		return ret;
	}
	// Fix if we have next dname, store it otherwise
	if (fix_data->next_dname) {
		const knot_node_t *next_node =
			knot_zone_contents_find_node(fix_data->zone,
			                             fix_data->next_dname);
		fix_data->next_dname = NULL;
		return update_nsec(prev_zone_node, next_node, fix_data->out_ch,
		                   3600,
		                   prev_zone_node == fix_data->zone->apex);
	} else {
		fix_data->next_dname = knot_rdata_nsec_next(old_nsec);
	}
	return NSEC_NODE_SKIP;
}

static int fix_nsec_chain(knot_dname_t *a, knot_dname_t *b, void *d)
{
	assert(b);
	chain_fix_data_t *fix_data = (chain_fix_data_t *)d;
	assert(fix_data);
	// Get changed nodes from zone
	const knot_node_t *a_node = knot_zone_contents_find_node(fix_data->zone,
	                                                         a);
	const knot_node_t *b_node = knot_zone_contents_find_node(fix_data->zone,
	                                                         b);
	if (b_node == NULL || knot_node_is_non_auth(b_node)) {
		// Nothing to fix in this node
		return NSEC_NODE_SKIP;
	}

	// Find previous node in zone
	const knot_node_t *prev_zone_node = find_prev_nsec_node(fix_data->zone,
	                                                        b_node);
	if (prev_zone_node == NULL) {
		return KNOT_ERROR;
	}

	// Handle removals
	bool node_deleted = only_nsec_in_node(b_node);
	if (node_deleted) {
		return handle_removed_node(b_node, prev_zone_node, fix_data);
	}

	// Find out whether the previous node is also part of the changeset.
	bool dname_equal =
		a ? knot_dname_is_equal(prev_zone_node->owner, a) : false;
	if (dname_equal) {
		// No valid data for the previous node, create the forward NSEC
		return update_nsec(a_node, b_node, fix_data->out_ch, 3600,
		                   prev_zone_node == fix_data->zone->apex);
	} else {
		bool next_dname_equal = fix_data->next_dname &&
		                        knot_dname_is_equal(fix_data->next_dname, b);
		bool use_next = fix_data->next_dname && !next_dname_equal;
		if (use_next) {
			const knot_node_t *next_node =
				knot_zone_contents_find_node(fix_data->zone,
				                             fix_data->next_dname);
			int ret = update_nsec(a ? a_node : b_node,
			                      next_node, fix_data->out_ch,
			                      3600, false);
			fix_data->next_dname = NULL;
			return ret;
		}

		const knot_rrset_t *nsec_rrset = NULL;
		const knot_node_t *next_node = NULL;
		if (next_dname_equal || node_deleted) {
			// Updating node, extract next
			nsec_rrset = knot_node_rrset(b_node, KNOT_RRTYPE_NSEC);
			prev_zone_node = b_node;
			next_node = knot_zone_contents_find_node(fix_data->zone,
			                                         knot_rdata_nsec_next(nsec_rrset));
			assert(nsec_rrset);
		} else {
			// Previous node was not changed in DDNS, it has to have NSEC
			nsec_rrset = knot_node_rrset(prev_zone_node,
			                             KNOT_RRTYPE_NSEC);
			next_node = b_node;
			assert(nsec_rrset);
		}

		// Store next node for next iterations
		fix_data->next_dname = knot_rdata_nsec_next(nsec_rrset);
		// Fix NSEC
		return update_nsec(prev_zone_node, next_node, fix_data->out_ch,
		                   3600, prev_zone_node == fix_data->zone->apex);
	}

	return KNOT_EOK;
}

/* - public API ------------------------------------------------------------ */

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 */
knot_dname_t *create_nsec3_owner(const knot_dname_t *owner,
                                 const knot_dname_t *zone_apex,
                                 const knot_nsec3_params_t *params)
{
	if (owner == NULL || zone_apex == NULL || params == NULL) {
		return NULL;
	}

	uint8_t *hash = NULL;
	size_t hash_size = 0;
	int owner_size = knot_dname_size(owner);

	if (owner_size < 0) {
		return NULL;
	}

	if (knot_nsec3_hash(params, owner, owner_size, &hash, &hash_size)
	    != KNOT_EOK) {
		return NULL;
	}

	knot_dname_t *result = knot_nsec3_hash_to_dname(hash, hash_size, zone_apex);
	free(hash);

	return result;
}

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 */
knot_dname_t *knot_nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
                                       const knot_dname_t *zone_apex)
{
	assert(zone_apex);

	// encode raw hash to first label

	uint8_t label[KNOT_DNAME_MAX_LENGTH];
	int32_t label_size;
	label_size = base32hex_encode(hash, hash_size, label, sizeof(label));
	if (label_size <= 0) {
		return NULL;
	}

	// allocate result

	size_t zone_apex_size = knot_dname_size(zone_apex);
	size_t result_size = 1 + label_size + zone_apex_size;
	knot_dname_t *result = malloc(result_size);
	if (!result) {
		return NULL;
	}

	// build the result

	uint8_t *write = result;

	*write = (uint8_t)label_size;
	write += 1;
	memcpy(write, label, label_size);
	write += label_size;
	memcpy(write, zone_apex, zone_apex_size);
	write += zone_apex_size;

	assert(write == result + result_size);
	knot_dname_to_lower(result);

	return result;
}

/*!
 * \brief Create NSEC or NSEC3 chain in the zone.
 */
int knot_zone_create_nsec_chain(const knot_zone_contents_t *zone,
                                knot_changeset_t *changeset,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy)
{
	if (!zone || !changeset) {
		return KNOT_EINVAL;
	}

	uint32_t nsec_ttl = 0;
	if (!get_zone_soa_min_ttl(zone, &nsec_ttl)) {
		return KNOT_EINVAL;
	}

	int result;
	bool nsec3_enabled = is_nsec3_enabled(zone);

	if (nsec3_enabled) {
		result = create_nsec3_chain(zone, nsec_ttl, changeset);
	} else {
		result = create_nsec_chain(zone, nsec_ttl, changeset);
	}

	if (result == KNOT_EOK && !nsec3_enabled) {
		result = delete_nsec3_chain(zone, changeset);
	}

	if (result != KNOT_EOK) {
		return result;
	}

	// Sign newly created records right away
	return knot_zone_sign_nsecs_in_changeset(zone_keys, policy, changeset);
}

int knot_zone_fix_chain(const knot_zone_contents_t *zone,
                        hattrie_t *sorted_changes,
                        knot_changeset_t *out_ch,
                        const knot_zone_keys_t *zone_keys,
                        const knot_dnssec_policy_t *policy)
{
	if (zone == NULL || sorted_changes == NULL || zone_keys == NULL ||
	    policy == NULL) {
		return KNOT_EINVAL;
	}

	if (hattrie_size(sorted_changes) == 0) {
		// no changes, no fixing
		return KNOT_EOK;
	}

	// Build hattrie index for sorted iterations
	hattrie_build_index(sorted_changes);

	// Prepare data for chain fixing functions
	chain_fix_data_t fix_data = { .zone = zone,
	                              .out_ch = out_ch,
	                              .zone_keys = zone_keys,
	                              .policy = policy,
	                              .next_dname = NULL };
	int ret = KNOT_EOK;
	if (is_nsec3_enabled(zone)) {
		ret = update_changes_with_non_terminals(zone, sorted_changes);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Create and sort NSEC3 hashes
		hattrie_t *nsec3_names = NULL;
		ret = create_nsec3_hashes_from_trie(sorted_changes,
		                                    zone,
		                                    &nsec3_names);
		assert(0);
//		ret = chain_iterate(nsec3_names, fix_nsec3_chain, &fix_data);
	} else {
		ret = chain_iterate_nsec(sorted_changes, fix_nsec_chain,
		                         &fix_data);
	}

	dbg_dnssec_verb("NSEC(3) chain fixed (%s)", knot_strerror(ret));

	return ret;
}

