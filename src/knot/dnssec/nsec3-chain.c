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

#include "common/base32hex.h"
#include "knot/dnssec/nsec3-chain.h"
#include "libknot/dname.h"
#include "libknot/rdata.h"
#include "libknot/packet/wire.h"
#include "knot/zone/zone-contents.h"
#include "knot/zone/zone-diff.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/dnssec/bitmap.h"

/* - Forward declarations --------------------------------------------------- */

static int create_nsec3_rrset(knot_rrset_t *rrset,
                              knot_dname_t *dname,
                              const knot_nsec3_params_t *,
                              const bitmap_t *,
                              const uint8_t *,
                              uint32_t);

/* - Helper functions ------------------------------------------------------- */

/* - NSEC3 node comparison -------------------------------------------------- */

/*!
 * \brief Perform some basic checks that the node is a valid NSEC3 node.
 */
inline static bool valid_nsec3_node(const knot_node_t *node)
{
	assert(node);

	if (node->rrset_count > 2) {
		return false;
	}

	const knot_rrs_t *nsec3 = knot_node_rrs(node, KNOT_RRTYPE_NSEC3);
	if (nsec3 == NULL) {
		return false;
	}

	if (nsec3->rr_count != 1) {
		return false;
	}

	return true;
}

/*!
 * \brief Check if two nodes are equal.
 */
static bool are_nsec3_nodes_equal(const knot_node_t *a, const knot_node_t *b)
{
	if (!(valid_nsec3_node(a) && valid_nsec3_node(b))) {
		return false;
	}

	knot_rrset_t a_rrset = knot_node_rrset(a, KNOT_RRTYPE_NSEC3);
	knot_rrset_t b_rrset = knot_node_rrset(b, KNOT_RRTYPE_NSEC3);
	return knot_rrset_equal(&a_rrset, &b_rrset, KNOT_RRSET_COMPARE_WHOLE);
}

/*!
 * \brief Check whether at least one RR type in node should be signed,
 *        used when signing with NSEC3.
 *
 * \param node  Node for which the check is done.
 *
 * \return true/false.
 */
static bool node_should_be_signed_nsec3(const knot_node_t *n)
{
	for (int i = 0; i < n->rrset_count; i++) {
		knot_rrset_t rrset = knot_node_rrset_at(n, i);
		if (rrset.type == KNOT_RRTYPE_NSEC ||
		    rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		bool should_sign = false;
		int ret = knot_zone_sign_rr_should_be_signed(n, &rrset,
		                                             &should_sign);
		assert(ret == KNOT_EOK); // No tree inside the function, no fail
		if (should_sign) {
			return true;
		}
	}

	return false;
}

/* - RRSIGs handling for NSEC3 ---------------------------------------------- */

/*!
 * \brief Shallow copy NSEC3 signatures from the one node to the second one.
 *        Just sets the pointer, needed only for comparison.
 */
static int shallow_copy_signature(const knot_node_t *from, knot_node_t *to)
{
	assert(valid_nsec3_node(from));
	assert(valid_nsec3_node(to));

	knot_rrset_t from_sig = knot_node_rrset(from, KNOT_RRTYPE_RRSIG);
	if (knot_rrset_empty(&from_sig)) {
		return KNOT_EOK;
	}
	return knot_node_add_rrset(to, &from_sig, NULL);
}

/*!
 * \brief Reuse signatatures by shallow copying them from one tree to another.
 */
static int copy_signatures(const knot_zone_tree_t *from, knot_zone_tree_t *to)
{
	if (knot_zone_tree_is_empty(from)) {
		return KNOT_EOK;
	}

	assert(to);

	bool sorted = false;
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

		int ret = shallow_copy_signature(node_from, node_to);
		if (ret != KNOT_EOK) {
			hattrie_iter_free(it);
			return ret;
		}
	}

	hattrie_iter_free(it);
	return KNOT_EOK;
}

/*!
 * \brief Custom NSEC3 tree free function.
 *
 */
static void free_nsec3_tree(knot_zone_tree_t *nodes)
{
	assert(nodes);

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);
	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);
		// newly allocated NSEC3 nodes
		knot_rrs_t *nsec3 = knot_node_get_rrs(node, KNOT_RRTYPE_NSEC3);
		knot_rrs_t *rrsig = knot_node_get_rrs(node, KNOT_RRTYPE_RRSIG);
		knot_rrs_clear(nsec3, NULL);
		knot_rrs_clear(rrsig, NULL);
		knot_node_free(&node);
	}

	hattrie_iter_free(it);
	knot_zone_tree_free(&nodes);
}

/* - NSEC3 nodes construction ----------------------------------------------- */

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
                             const bitmap_t *rr_types,
                             const uint8_t *next_hashed, uint32_t ttl)
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
	if (next_hashed) {
		memcpy(rdata, next_hashed, hash_length);
	}
	rdata += hash_length;
	bitmap_write(rr_types, rdata);                    // RR types bit map
}

/*!
 * \brief Creates NSEC3 RRSet.
 *
 * \param owner        Owner for the RRSet.
 * \param params       Parsed NSEC3PARAM.
 * \param rr_types     Bitmap.
 * \param next_hashed  Next hashed.
 * \param ttl          TTL for the RRSet.
 *
 * \return Pointer to created RRSet on success, NULL on errors.
 */
static int create_nsec3_rrset(knot_rrset_t *rrset,
                              knot_dname_t *owner,
                              const knot_nsec3_params_t *params,
                              const bitmap_t *rr_types,
                              const uint8_t *next_hashed,
                              uint32_t ttl)
{
	assert(rrset);
	assert(owner);
	assert(params);
	assert(rr_types);

	knot_rrset_init(rrset, owner, KNOT_RRTYPE_NSEC3, KNOT_CLASS_IN);

	size_t rdata_size = nsec3_rdata_size(params, rr_types);
	uint8_t rdata[rdata_size];
	nsec3_fill_rdata(rdata, params, rr_types, next_hashed, ttl);

	return knot_rrset_add_rr(rrset, rdata, rdata_size, ttl, NULL);
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

	knot_rrset_t nsec3_rrset;
	int ret = create_nsec3_rrset(&nsec3_rrset, owner, nsec3_params,
	                             rr_types, NULL, ttl);
	if (ret != KNOT_EOK) {
		knot_node_free(&new_node);
		return NULL;
	}

	ret = knot_node_add_rrset(new_node, &nsec3_rrset, NULL);
	knot_rrset_clear(&nsec3_rrset, NULL);
	if (ret != KNOT_EOK) {
		knot_node_free(&new_node);
		return NULL;
	}

	return new_node;
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
	nsec3_owner = knot_create_nsec3_owner(node->owner, apex->owner, params);
	if (!nsec3_owner) {
		return NULL;
	}

	bitmap_t rr_types = { 0 };
	bitmap_add_node_rrsets(&rr_types, node);
	if (node->rrset_count > 0 && node_should_be_signed_nsec3(node)) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);
	}
	if (node == apex) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_DNSKEY);
	}

	knot_node_t *nsec3_node;
	nsec3_node = create_nsec3_node(nsec3_owner, params, apex, &rr_types, ttl);

	return nsec3_node;
}

/* - NSEC3 chain creation --------------------------------------------------- */

/*!
 * \brief Connect two nodes by filling 'hash' field of NSEC3 RDATA of the node.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Unused parameter.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec3_nodes(knot_node_t *a, knot_node_t *b,
                               nsec_chain_iterate_data_t *data)
{
	assert(a);
	assert(b);
	UNUSED(data);

	assert(a->rrset_count == 1);

	knot_rrs_t *a_rrs = knot_node_get_rrs(a, KNOT_RRTYPE_NSEC3);
	assert(a_rrs);
	uint8_t algorithm = knot_rrs_nsec3_algorithm(a_rrs, 0);
	if (algorithm == 0) {
		return KNOT_EINVAL;
	}

	uint8_t *raw_hash = NULL;
	uint8_t raw_length = 0;
	knot_rrs_nsec3_next_hashed(a_rrs, 0, &raw_hash, &raw_length);
	if (raw_hash == NULL) {
		return KNOT_EINVAL;
	}

	assert(raw_length == knot_nsec3_hash_length(algorithm));

	knot_dname_to_lower(b->owner);
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
 * \brief Create NSEC3 node for each regular node in the zone.
 *
 * \param zone         Zone.
 * \param ttl          TTL for the created NSEC records.
 * \param nsec3_nodes  Tree whereto new NSEC3 nodes will be added.
 * \param chgset       Changeset used for possible NSEC removals
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec3_nodes(const knot_zone_contents_t *zone, uint32_t ttl,
                              knot_zone_tree_t *nsec3_nodes,
                              knot_changeset_t *chgset)
{
	assert(zone);
	assert(nsec3_nodes);
	assert(chgset);

	const knot_nsec3_params_t *params = &zone->nsec3_params;

	assert(params);

	int result = KNOT_EOK;

	int sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(zone->nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		knot_node_t *node = (knot_node_t *)*hattrie_iter_val(it);

		/*!
		 * Remove possible NSEC from the node. (Do not allow both NSEC
		 * and NSEC3 in the zone at once.)
		 */
		result = knot_nsec_changeset_remove(node, chgset);
		if (result != KNOT_EOK) {
			break;
		}
		if (knot_node_rrtype_exists(node, KNOT_RRTYPE_NSEC)) {
			knot_node_set_removed_nsec(node);
		}
		if (knot_node_is_non_auth(node) || knot_node_is_empty(node)) {
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
 * \brief Checks if NSEC3 should be generated for this node.
 *
 * \retval true if the node has no children and contains no RRSets or only
 *         RRSIGs and NSECs.
 * \retval false otherwise.
 */
static bool nsec3_is_empty(knot_node_t *node)
{
	if (knot_node_children(node) > 0) {
		return false;
	}

	return knot_nsec_empty_nsec_and_rrsigs_in_node(node);
}

/*!
 * \brief Marks node and its parents as empty if NSEC3 should not be generated
 *        for them.
 *
 * It also lowers the children count for the parent of marked node. This must be
 * fixed before further operations on the zone.
 */
static int nsec3_mark_empty(knot_node_t **node_p, void *data)
{
	UNUSED(data);
	knot_node_t *node = *node_p;

	if (!knot_node_is_empty(node) && nsec3_is_empty(node)) {
		/*!
		 * Mark this node and all parent nodes that meet the same
		 * criteria as empty.
		 */
		knot_node_set_empty(node);

		if (node->parent) {
			/* We must decrease the parent's children count,
			 * but only temporarily! It must be set back right after
			 * the operation
			 */
			node->parent->children--;
			/* Recurse using the parent node */
			return nsec3_mark_empty(&node->parent, data);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Function for temporary marking nodes as empty if NSEC3s should not be
 *        generated for them.
 *
 * This is only temporary for the time of NSEC3 generation. Afterwards it must
 * be reset (removed flag and fixed children counts).
 */
static void mark_empty_nodes_tmp(const knot_zone_contents_t *zone)
{
	assert(zone);

	int ret = knot_zone_tree_apply(zone->nodes, nsec3_mark_empty, NULL);

	assert(ret == KNOT_EOK);
}

/*!
 * \brief Resets the empty flag in the node and increases its parent's children
 *        count if the node was marked as empty.
 *
 * The children count of node's parent is increased if this node was marked as
 * empty, as it was previously decreased in the \a nsec3_mark_empty() function.
 */
static int nsec3_reset(knot_node_t **node_p, void *data)
{
	UNUSED(data);
	knot_node_t *node = *node_p;

	if (knot_node_is_empty(node)) {
		/* If node was marked as empty, increase its parent's children
		 * count.
		 */
		node->parent->children++;
		/* Clear the 'empty' flag. */
		knot_node_clear_empty(node);
	}

	return KNOT_EOK;
}

/*!
 * \brief Resets empty node flag and children count in nodes that were
 *        previously marked as empty by the \a mark_empty_nodes_tmp() function.
 *
 * This function must be called after NSEC3 generation, so that flags and
 * children count are back to normal before further processing.
 */
static void reset_nodes(const knot_zone_contents_t *zone)
{
	assert(zone);

	int ret = knot_zone_tree_apply(zone->nodes, nsec3_reset, NULL);

	assert(ret == KNOT_EOK);
}

/* - Public API ------------------------------------------------------------- */

/*!
 * \brief Create new NSEC3 chain, add differences from current into a changeset.
 */
int knot_nsec3_create_chain(const knot_zone_contents_t *zone, uint32_t ttl,
                            knot_changeset_t *changeset)
{
	assert(zone);
	assert(changeset);

	int result;

	knot_zone_tree_t *nsec3_nodes = knot_zone_tree_create();
	if (!nsec3_nodes) {
		return KNOT_ENOMEM;
	}

	/* Before creating NSEC3 nodes, we must temporarily mark those nodes
	 * that may still be in the zone, but for which the NSEC3s should not
	 * be created. I.e. nodes with only RRSIG (or NSEC+RRSIG) and their
	 * predecessors if they are empty.
	 *
	 * The flag will be removed when the node is encountered during NSEC3
	 * creation procedure.
	 */

	mark_empty_nodes_tmp(zone);

	result = create_nsec3_nodes(zone, ttl, nsec3_nodes, changeset);
	if (result != KNOT_EOK) {
		free_nsec3_tree(nsec3_nodes);
		return result;
	}

	reset_nodes(zone);

	result = knot_nsec_chain_iterate_create(nsec3_nodes,
	                                        connect_nsec3_nodes, NULL);
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
