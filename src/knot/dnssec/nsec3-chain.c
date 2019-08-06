/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "libknot/dname.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/zone/adjust.h"
#include "knot/zone/zone-diff.h"
#include "contrib/base32hex.h"
#include "contrib/macros.h"
#include "contrib/wire_ctx.h"

static bool nsec3_opt_out(const zone_node_t *node, bool opt_out_enabled)
{
	return (opt_out_enabled && (node->flags & NODE_FLAGS_DELEG) &&
	        !node_rrtype_exists(node, KNOT_RRTYPE_DS));
}

/*!
 * \brief Check whether at least one RR type in node should be signed,
 *        used when signing with NSEC3.
 *
 * \param node  Node for which the check is done.
 *
 * \return true/false.
 */
static bool node_should_be_signed_nsec3(const zone_node_t *n)
{
	for (int i = 0; i < n->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(n, i);
		if (rrset.type == KNOT_RRTYPE_NSEC ||
		    rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}

		if (knot_zone_sign_rr_should_be_signed(n, &rrset)) {
			return true;
		}
	}

	return false;
}

/*!
 * \brief Custom NSEC3 tree free function.
 *
 */
static void free_nsec3_tree(zone_tree_t *nodes)
{
	assert(nodes);

	zone_tree_it_t it = { 0 };
	for ((void)zone_tree_it_begin(nodes, &it); !zone_tree_it_finished(&it); zone_tree_it_next(&it)) {
		zone_node_t *node = zone_tree_it_val(&it);
		// newly allocated NSEC3 nodes
		knot_rdataset_t *nsec3 = node_rdataset(node, KNOT_RRTYPE_NSEC3);
		knot_rdataset_t *rrsig = node_rdataset(node, KNOT_RRTYPE_RRSIG);
		knot_rdataset_clear(nsec3, NULL);
		knot_rdataset_clear(rrsig, NULL);
		node_free(node, NULL);
	}

	zone_tree_it_free(&it);
	zone_tree_free(&nodes);
}

/* - NSEC3 nodes construction ----------------------------------------------- */

/*!
 * \brief Get NSEC3 RDATA size.
 */
static size_t nsec3_rdata_size(const dnssec_nsec3_params_t *params,
                               const dnssec_nsec_bitmap_t *rr_types)
{
	assert(params);
	assert(rr_types);

	return 6 + params->salt.size
	       + dnssec_nsec3_hash_length(params->algorithm)
	       + dnssec_nsec_bitmap_size(rr_types);
}

/*!
 * \brief Fill NSEC3 RDATA.
 *
 * \note Content of next hash field is not changed.
 */
static int nsec3_fill_rdata(uint8_t *rdata, size_t rdata_len,
                            const dnssec_nsec3_params_t *params,
                            const dnssec_nsec_bitmap_t *rr_types,
                            const uint8_t *next_hashed)
{
	assert(rdata);
	assert(params);
	assert(rr_types);

	uint8_t hash_length = dnssec_nsec3_hash_length(params->algorithm);

	wire_ctx_t wire = wire_ctx_init(rdata, rdata_len);

	wire_ctx_write_u8(&wire, params->algorithm);
	wire_ctx_write_u8(&wire, params->flags);
	wire_ctx_write_u16(&wire, params->iterations);
	wire_ctx_write_u8(&wire, params->salt.size);
	wire_ctx_write(&wire, params->salt.data, params->salt.size);
	wire_ctx_write_u8(&wire, hash_length);

	if (next_hashed != NULL) {
		wire_ctx_write(&wire, next_hashed, hash_length);
	} else {
		wire_ctx_skip(&wire, hash_length);
	}

	if (wire.error != KNOT_EOK) {
		return wire.error;
	}

	dnssec_nsec_bitmap_write(rr_types, wire.position);

	return KNOT_EOK;
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
                              const knot_dname_t *owner,
                              const dnssec_nsec3_params_t *params,
                              const dnssec_nsec_bitmap_t *rr_types,
                              const uint8_t *next_hashed,
                              uint32_t ttl)
{
	assert(rrset);
	assert(owner);
	assert(params);
	assert(rr_types);

	knot_dname_t *owner_copy = knot_dname_copy(owner, NULL);
	if (owner_copy == NULL) {
		return KNOT_ENOMEM;
	}
	knot_rrset_init(rrset, owner_copy, KNOT_RRTYPE_NSEC3, KNOT_CLASS_IN, ttl);

	size_t rdata_size = nsec3_rdata_size(params, rr_types);
	uint8_t rdata[rdata_size];
	memset(rdata, 0, rdata_size);
	int ret = nsec3_fill_rdata(rdata, rdata_size, params, rr_types,
	                           next_hashed);
	if (ret != KNOT_EOK) {
		knot_dname_free(owner_copy, NULL);
		return ret;
	}

	ret = knot_rrset_add_rdata(rrset, rdata, rdata_size, NULL);
	if (ret != KNOT_EOK) {
		knot_dname_free(owner_copy, NULL);
		return ret;
	}

	return KNOT_EOK;
}

/*!
 * \brief Create NSEC3 node.
 */
static zone_node_t *create_nsec3_node(const knot_dname_t *owner,
                                      const dnssec_nsec3_params_t *nsec3_params,
                                      zone_node_t *apex_node,
                                      const dnssec_nsec_bitmap_t *rr_types,
                                      uint32_t ttl)
{
	assert(owner);
	assert(nsec3_params);
	assert(apex_node);
	assert(rr_types);

	zone_node_t *new_node = node_new(owner, false, false, NULL);
	if (!new_node) {
		return NULL;
	}

	knot_rrset_t nsec3_rrset;
	int ret = create_nsec3_rrset(&nsec3_rrset, owner, nsec3_params,
	                             rr_types, NULL, ttl);
	if (ret != KNOT_EOK) {
		node_free(new_node, NULL);
		return NULL;
	}

	ret = node_add_rrset(new_node, &nsec3_rrset, NULL);
	knot_rrset_clear(&nsec3_rrset, NULL);
	if (ret != KNOT_EOK) {
		node_free(new_node, NULL);
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
 * \param apex_cds   Hint to guess apex node type bitmap: false=just DNSKEY, true=DNSKEY,CDS,CDNSKEY.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static zone_node_t *create_nsec3_node_for_node(const zone_node_t *node,
                                               zone_node_t *apex,
                                               const dnssec_nsec3_params_t *params,
                                               uint32_t ttl)
{
	assert(node);
	assert(apex);
	assert(params);

	uint8_t nsec3_owner[KNOT_DNAME_MAXLEN];
	int ret = knot_create_nsec3_owner(nsec3_owner, sizeof(nsec3_owner),
	                                  node->owner, apex->owner, params);
	if (ret != KNOT_EOK) {
		return NULL;
	}

	dnssec_nsec_bitmap_t *rr_types = dnssec_nsec_bitmap_new();
	if (!rr_types) {
		return NULL;
	}

	bitmap_add_node_rrsets(rr_types, KNOT_RRTYPE_NSEC3, node);
	if (node->rrset_count > 0 && node_should_be_signed_nsec3(node)) {
		dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_RRSIG);
	}
	if (node == apex) {
		dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_NSEC3PARAM);
	}

	zone_node_t *nsec3_node = create_nsec3_node(nsec3_owner, params, apex,
	                                            rr_types, ttl);
	dnssec_nsec_bitmap_free(rr_types);

	return nsec3_node;
}

/* - NSEC3 chain creation --------------------------------------------------- */

// see connect_nsec3_nodes() for what this function does
static int connect_nsec3_base(knot_rdataset_t *a_rrs, const knot_dname_t *b_name)
{
	assert(a_rrs);
	uint8_t algorithm = knot_nsec3_alg(a_rrs->rdata);
	if (algorithm == 0) {
		return KNOT_EINVAL;
	}

	uint8_t raw_length = knot_nsec3_next_len(a_rrs->rdata);
	uint8_t *raw_hash = (uint8_t *)knot_nsec3_next(a_rrs->rdata);
	if (raw_hash == NULL) {
		return KNOT_EINVAL;
	}

	assert(raw_length == dnssec_nsec3_hash_length(algorithm));

	char *b32_hash = knot_dname_to_str_alloc(b_name);
	if (!b32_hash) {
		return KNOT_ENOMEM;
	}

	char *b32_end = strchr(b32_hash, '.');
	if (!b32_end) {
		free(b32_hash);
		return KNOT_EINVAL;
	}

	size_t b32_length = b32_end - b32_hash;
	int32_t written = base32hex_decode((uint8_t *)b32_hash, b32_length,
					   raw_hash, raw_length);

	free(b32_hash);

	if (written != raw_length) {
		return KNOT_EINVAL;
	}

	return KNOT_EOK;
}

/*!
 * \brief Connect two nodes by filling 'hash' field of NSEC3 RDATA of the first node.
 *
 * \param a     First node. Gets modified in-place!
 * \param b     Second node (immediate follower of a).
 * \param data  Unused parameter.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec3_nodes(zone_node_t *a, zone_node_t *b,
                               nsec_chain_iterate_data_t *data)
{
	assert(a);
	assert(b);
	UNUSED(data);

	assert(a->rrset_count == 1);

	return connect_nsec3_base(node_rdataset(a, KNOT_RRTYPE_NSEC3), b->owner);
}

/*!
 * \brief Connect two nodes by updating the changeset.
 *
 * \param a     First node.
 * \param b     Second node.
 * \param data  Contains the changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec3_nodes2(zone_node_t *a, zone_node_t *b,
                                nsec_chain_iterate_data_t *data)
{
	assert(data);

	knot_rrset_t aorig = node_rrset(a, KNOT_RRTYPE_NSEC3);
	assert(!knot_rrset_empty(&aorig));

	// prepare a copy of NSEC3 rrsets in question
	knot_rrset_t *acopy = knot_rrset_copy(&aorig, NULL);
	if (acopy == NULL) {
		return KNOT_ENOMEM;
	}

	// connect the copied rrset
	int ret = connect_nsec3_base(&acopy->rrs, b->owner);
	if (ret != KNOT_EOK || knot_rrset_equal(&aorig, acopy, KNOT_RRSET_COMPARE_WHOLE)) {
		knot_rrset_free(acopy, NULL);
		return ret;
	}

	// add the removed original and the updated copy to changeset
	ret = zone_update_remove(data->update, &aorig);
	if (ret == KNOT_EOK) {
		ret = zone_update_add(data->update, acopy);
	}
	knot_rrset_free(acopy, NULL);
	return ret;
}

/*!
 * \brief Replace the "next hash" field in b's NSEC3 by that in a's NSEC3, by updating the changeset.
 *
 * \param a      A node to take the "next hash" from.
 * \param b      A node to put the "next hash" into.
 * \param data   Contains the changeset to be updated.
 *
 * \return KNOT_E*
 */
static int reconnect_nsec3_nodes2(zone_node_t *a, zone_node_t *b,
				  nsec_chain_iterate_data_t *data)
{
	assert(data);

	knot_rrset_t an = node_rrset(a, KNOT_RRTYPE_NSEC3);
	assert(!knot_rrset_empty(&an));

	knot_rrset_t bnorig = node_rrset(b, KNOT_RRTYPE_NSEC3);
	assert(!knot_rrset_empty(&bnorig));

	// prepare a copy of NSEC3 rrsets in question
	knot_rrset_t *bnnew = knot_rrset_copy(&bnorig, NULL);
	if (bnnew == NULL) {
		return KNOT_ENOMEM;
	}

	uint8_t raw_length = knot_nsec3_next_len(an.rrs.rdata);
	uint8_t *a_hash = (uint8_t *)knot_nsec3_next(an.rrs.rdata);
	uint8_t *bnew_hash = (uint8_t *)knot_nsec3_next(bnnew->rrs.rdata);
	if (a_hash == NULL || bnew_hash == NULL ||
	    raw_length != knot_nsec3_next_len(bnnew->rrs.rdata)) {
		knot_rrset_free(bnnew, NULL);
		return KNOT_ERROR;
	}
	memcpy(bnew_hash, a_hash, raw_length);

	int ret = zone_update_remove(data->update, &bnorig);
	if (ret == KNOT_EOK) {
		ret = zone_update_add(data->update, bnnew);
	}
	knot_rrset_free(bnnew, NULL);
	return ret;
}

/*!
 * \brief Create NSEC3 node for each regular node in the zone.
 *
 * \param zone         Zone.
 * \param params       NSEC3 params.
 * \param ttl          TTL for the created NSEC records.
 * \param cds_in_apex  Hint to guess apex node type bitmap: false=just DNSKEY, true=DNSKEY,CDS,CDNSKEY.
 * \param nsec3_nodes  Tree whereto new NSEC3 nodes will be added.
 * \param update       Zone update for possible NSEC removals
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec3_nodes(const zone_contents_t *zone,
                              const dnssec_nsec3_params_t *params,
                              uint32_t ttl,
                              zone_tree_t *nsec3_nodes,
                              zone_update_t *update)
{
	assert(zone);
	assert(nsec3_nodes);
	assert(update);

	zone_tree_it_t it = { 0 };
	int result = zone_tree_it_begin(zone->nodes, &it);

	while (!zone_tree_it_finished(&it)) {
		zone_node_t *node = zone_tree_it_val(&it);

		/*!
		 * Remove possible NSEC from the node. (Do not allow both NSEC
		 * and NSEC3 in the zone at once.)
		 */
		result = knot_nsec_changeset_remove(node, update);
		if (result != KNOT_EOK) {
			break;
		}
		if (node->flags & NODE_FLAGS_NONAUTH || node->flags & NODE_FLAGS_EMPTY || node->flags & NODE_FLAGS_DELETED) {
			zone_tree_it_next(&it);
			continue;
		}

		zone_node_t *nsec3_node;
		nsec3_node = create_nsec3_node_for_node(node, zone->apex,
							params, ttl);
		if (!nsec3_node) {
			result = KNOT_ENOMEM;
			break;
		}

		result = zone_tree_insert(nsec3_nodes, &nsec3_node);
		if (result != KNOT_EOK) {
			break;
		}

		zone_tree_it_next(&it);
	}

	zone_tree_it_free(&it);

	return result;
}

/*!
 * \brief For given dname, check if anything changed in zone_update, and recreate (possibly unconnected) NSEC3 nodes appropriately.
 *
 * \param update    Zone update structure holding zone contents changes.
 * \param params    NSEC3 params.
 * \param ttl       TTL for newly created NSEC3 records.
 * \param for_node  Domain name of the node in question.
 *
 * \retval KNOT_ENORECORD if the NSEC3 chain shall be rather recreated completely.
 * \return KNOT_EOK, KNOT_E* if any error.
 */
static int fix_nsec3_for_node(zone_update_t *update, const dnssec_nsec3_params_t *params,
                              uint32_t ttl, bool opt_out, const knot_dname_t *for_node)
{
	// check if we need to do something
	const zone_node_t *old_n = zone_contents_find_node(update->zone->contents, for_node);
	const zone_node_t *new_n = zone_contents_find_node(update->new_cont, for_node);
	if (node_bitmap_equal(old_n, new_n)) {
		return KNOT_EOK;
	}

	if ((new_n != NULL && knot_nsec_empty_nsec_and_rrsigs_in_node(new_n) && new_n->children > 0) ||
	    (old_n != NULL && knot_nsec_empty_nsec_and_rrsigs_in_node(old_n) && old_n->children > 0)) {
		// handling empty non-terminal creation and downfall is too difficult, recreate NSEC3 from scratch
		return KNOT_ENORECORD;
	}

	uint8_t for_node_hashed[KNOT_DNAME_MAXLEN];
	int ret = knot_create_nsec3_owner(for_node_hashed, sizeof(for_node_hashed),
	                                  for_node, update->new_cont->apex->owner, params);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// saved hash of next node
	uint8_t *next_hash = NULL;
	uint8_t next_length = 0;

	bool add_nsec3 = (new_n != NULL && !node_empty(new_n) && !(new_n->flags & NODE_FLAGS_NONAUTH) &&
			  !nsec3_opt_out(new_n, opt_out));

	// remove (all) existing NSEC3
	const zone_node_t *old_nsec3_n = zone_contents_find_nsec3_node(update->zone->contents, for_node_hashed);
	if (old_nsec3_n != NULL) {
		knot_rrset_t rem_nsec3 = node_rrset(old_nsec3_n, KNOT_RRTYPE_NSEC3);
		if (!knot_rrset_empty(&rem_nsec3)) {
			knot_rrset_t rem_rrsig = node_rrset(old_nsec3_n, KNOT_RRTYPE_RRSIG);
			if (1) {
				ret = zone_update_remove(update, &rem_nsec3);
				if (ret == KNOT_EOK && !knot_rrset_empty(&rem_rrsig)) {
					ret = zone_update_remove(update, &rem_rrsig);
				}
			}
			next_hash = (uint8_t *)knot_nsec3_next(rem_nsec3.rrs.rdata);
			next_length = knot_nsec3_next_len(rem_nsec3.rrs.rdata);
		}
	}

	// add NSEC3 with correct bitmap
	if (add_nsec3 && ret == KNOT_EOK) {
		zone_node_t *new_nsec3_n = create_nsec3_node_for_node(new_n, update->new_cont->apex, params, ttl);
		if (new_nsec3_n == NULL) {
			return KNOT_ENOMEM;
		}
		knot_rrset_t nsec3 = node_rrset(new_nsec3_n, KNOT_RRTYPE_NSEC3);
		assert(!knot_rrset_empty(&nsec3));

		// copy hash of next element from removed record
		if (next_hash != NULL) {
			uint8_t *raw_hash = (uint8_t *)knot_nsec3_next(nsec3.rrs.rdata);
			uint8_t raw_length = knot_nsec3_next_len(nsec3.rrs.rdata);
			assert(raw_hash != NULL);
			if (raw_length != next_length) {
				ret = KNOT_EMALF;
			} else {
				memcpy(raw_hash, next_hash, raw_length);
			}
		}
		if (ret == KNOT_EOK) {
			if (1) {
				ret = zone_update_add(update, &nsec3);
			}
		}
		binode_unify(new_nsec3_n, false, NULL);
		node_free_rrsets(new_nsec3_n, NULL);
		node_free(new_nsec3_n, NULL);
	}

	return ret;
}

static int fix_nsec3_nodes(zone_update_t *update, const dnssec_nsec3_params_t *params,
                           uint32_t ttl, bool opt_out)
{
	assert(update);

	zone_tree_it_t it = { 0 };
	int ret = zone_tree_it_begin(update->a_ctx->node_ptrs, &it);

	while (!zone_tree_it_finished(&it) && ret == KNOT_EOK) {
		zone_node_t *n = zone_tree_it_val(&it);
		ret = fix_nsec3_for_node(update, params, ttl, opt_out, n->owner);
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);

	return ret;
}

/*!
 * \brief Checks if NSEC3 should be generated for this node.
 *
 * \retval true if the node has no children and contains no RRSets or only
 *         RRSIGs and NSECs.
 * \retval false otherwise.
 */
static bool nsec3_is_empty(zone_node_t *node, bool opt_out)
{
	return ((node->children == 0 && knot_nsec_empty_nsec_and_rrsigs_in_node(node)) ||
		nsec3_opt_out(node, opt_out));
}

/*!
 * \brief Marks node and its parents as empty if NSEC3 should not be generated
 *        for them.
 *
 * It also lowers the children count for the parent of marked node. This must be
 * fixed before further operations on the zone.
 */
static int nsec3_mark_empty(zone_node_t *node, void *data)
{
	if (!(node->flags & NODE_FLAGS_EMPTY) && nsec3_is_empty(node, (data != NULL))) {
		/*!
		 * Mark this node and all parent nodes that meet the same
		 * criteria as empty.
		 */
		node->flags |= NODE_FLAGS_EMPTY;

		if (!(node->flags & NODE_FLAGS_APEX)) {
			/* We must decrease the parent's children count,
			 * but only temporarily! It must be set back right after
			 * the operation
			 */
			node_parent(node)->children--;
			/* Recurse using the parent node */
			return nsec3_mark_empty(node_parent(node), data);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Resets the empty flag in the node and increases its parent's children
 *        count if the node was marked as empty.
 *
 * The children count of node's parent is increased if this node was marked as
 * empty, as it was previously decreased in the \a nsec3_mark_empty() function.
 */
static int nsec3_reset(zone_node_t *node, void *data)
{
	UNUSED(data);
	if (node->flags & NODE_FLAGS_EMPTY) {
		/* If node was marked as empty, increase its parent's children
		 * count.
		 */
		node_parent(node)->children++;
		/* Clear the 'empty' flag. */
		node->flags &= ~NODE_FLAGS_EMPTY;
	}

	return KNOT_EOK;
}

static int zone_update_nsec3_nodes(zone_update_t *up, zone_tree_t *nsec3n)
{
	int ret = KNOT_EOK;
	zone_tree_delsafe_it_t dit = { 0 };
	zone_tree_it_t it = { 0 };
	if (up->new_cont->nsec3_nodes == NULL) {
		goto add_nsec3n;
	}
	ret = zone_tree_delsafe_it_begin(up->new_cont->nsec3_nodes, &dit, false);
	while (ret == KNOT_EOK && !zone_tree_delsafe_it_finished(&dit)) {
		zone_node_t *nold = zone_tree_delsafe_it_val(&dit);
		knot_rrset_t ns3old = node_rrset(nold, KNOT_RRTYPE_NSEC3);
		zone_node_t *nnew = zone_tree_get(nsec3n, nold->owner);
		if (!knot_rrset_empty(&ns3old)) {
			knot_rrset_t ns3new = node_rrset(nnew, KNOT_RRTYPE_NSEC3);
			if (knot_rrset_equal(&ns3old, &ns3new, KNOT_RRSET_COMPARE_WHOLE)) {
				node_remove_rdataset(nnew, KNOT_RRTYPE_NSEC3);
			} else {
				ret = knot_nsec_changeset_remove(nold, up);
			}
		} else if (node_rrtype_exists(nold, KNOT_RRTYPE_RRSIG)) {
			ret = knot_nsec_changeset_remove(nold, up);
		}
		zone_tree_delsafe_it_next(&dit);
	}
	zone_tree_delsafe_it_free(&dit);
	if (ret != KNOT_EOK) {
		return ret;
	}

add_nsec3n:
	ret = zone_tree_it_begin(nsec3n, &it);
	while (ret == KNOT_EOK && !zone_tree_it_finished(&it)) {
		zone_node_t *nnew = zone_tree_it_val(&it);
		knot_rrset_t ns3new = node_rrset(nnew, KNOT_RRTYPE_NSEC3);
		if (!knot_rrset_empty(&ns3new)) {
			ret = zone_update_add(up, &ns3new);
		}
		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);
	return ret;
}

/* - Public API ------------------------------------------------------------- */

int delete_nsec3_chain(zone_update_t *up)
{
	zone_tree_t *empty = zone_tree_create(false);
	if (empty == NULL) {
		return KNOT_ENOMEM;
	}
	int ret = zone_update_nsec3_nodes(up, empty);
	zone_tree_free(&empty);
	return ret;
}

/*!
 * \brief Create new NSEC3 chain, add differences from current into a changeset.
 */
int knot_nsec3_create_chain(const zone_contents_t *zone,
                            const dnssec_nsec3_params_t *params,
                            uint32_t ttl,
                            bool opt_out,
                            zone_update_t *update)
{
	assert(zone);
	assert(params);

	int result;

	zone_tree_t *nsec3_nodes = zone_tree_create(false);
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
	result = zone_tree_apply(zone->nodes, nsec3_mark_empty, (opt_out ? (void *)zone : NULL));
	if (result != KNOT_EOK) {
		free_nsec3_tree(nsec3_nodes);
		return result;
	}

	result = create_nsec3_nodes(zone, params, ttl, nsec3_nodes, update);
	if (result != KNOT_EOK) {
		free_nsec3_tree(nsec3_nodes);
		return result;
	}

	/* Resets empty node flag and children count in nodes that were
	 * previously marked as empty. Must be called after NSEC3 generation,
	 * so that flags and children count are back to normal before further
	 * processing.
	 */
	result = zone_tree_apply(zone->nodes, nsec3_reset, NULL);
	if (result != KNOT_EOK) {
		free_nsec3_tree(nsec3_nodes);
		return result;
	}

	result = knot_nsec_chain_iterate_create(nsec3_nodes,
	                                        connect_nsec3_nodes, NULL);
	if (result != KNOT_EOK) {
		free_nsec3_tree(nsec3_nodes);
		return result;
	}

	result = zone_update_nsec3_nodes(update, nsec3_nodes);

	free_nsec3_tree(nsec3_nodes);

	return result;
}

int knot_nsec3_fix_chain(zone_update_t *update,
                         const dnssec_nsec3_params_t *params,
                         uint32_t ttl,
                         bool opt_out)
{

	int ret = fix_nsec3_nodes(update, params, ttl, opt_out);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_adjust_contents(update->new_cont, NULL, adjust_cb_void, false, update->a_ctx->node_ptrs);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// ensure that nsec3 node for zone root is in list of changed nodes
	const zone_node_t *nsec3_for_root = NULL, *unused;
	ret = zone_contents_find_nsec3_for_name(update->new_cont, update->zone->name, &nsec3_for_root, &unused);
	if (ret >= 0) {
		assert(ret == ZONE_NAME_FOUND);
		assert(!(nsec3_for_root->flags & NODE_FLAGS_DELETED));
		assert(!(binode_counterpart((zone_node_t *)nsec3_for_root)->flags & NODE_FLAGS_DELETED));
		ret = zone_tree_insert(update->a_ctx->nsec3_ptrs, (zone_node_t **)&nsec3_for_root);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	nsec_chain_iterate_data_t data = { ttl, update };

	ret = knot_nsec_chain_iterate_fix(update->a_ctx->nsec3_ptrs,
	                                  connect_nsec3_nodes2, reconnect_nsec3_nodes2, &data);

	return ret;
}
