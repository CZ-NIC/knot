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

static knot_rrset_t *create_nsec3_rrset(knot_dname_t *,
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

	const knot_rrset_t *nsec3 = knot_node_rrset(node, KNOT_RRTYPE_NSEC3);
	if (nsec3 == NULL) {
		return false;
	}

	if (nsec3->rdata_count != 1) {
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

	const knot_rrset_t *a_rrset = knot_node_rrset(a, KNOT_RRTYPE_NSEC3);
	const knot_rrset_t *b_rrset = knot_node_rrset(b, KNOT_RRTYPE_NSEC3);

	return knot_rrset_equal(a_rrset, b_rrset, KNOT_RRSET_COMPARE_WHOLE);
}

/* - Chain fix data helpers ------------------------------------------------- */

/*!
 * \brief Creates knot_dname_t * from 'next hashed' NSEC3 RR field.
 *
 * \param rr         NSEC3 RRSet.
 * \param zone_apex  Zone apex dname.
 *
 * \return Created dname if successful, NULL otherwise.
 */
static knot_dname_t *next_dname_from_nsec3_rrset(const knot_rrset_t *rr,
                                                 const knot_dname_t *zone_apex)
{
	uint8_t *next_hashed = NULL;
	uint8_t hashed_size = 0;
	knot_rdata_nsec3_next_hashed(rr, 0, &next_hashed, &hashed_size);
	uint8_t *encoded = NULL;
	int32_t encoded_size = base32hex_encode_alloc(next_hashed, hashed_size,
	                                              &encoded);
	if (encoded_size < 0) {
		return NULL;
	}

	uint8_t catted_hash[encoded_size + knot_dname_size(zone_apex)];
	*catted_hash = encoded_size;
	memcpy(catted_hash + 1, encoded, encoded_size);
	free(encoded);
	memcpy(catted_hash + 1 + encoded_size,
	       zone_apex, knot_dname_size(zone_apex));
	knot_dname_t *next_dname = knot_dname_copy(catted_hash);
	if (next_dname == NULL) {
		return NULL;
	}
	knot_dname_to_lower(next_dname);
	return next_dname;
}

/*!
 * \brief Updates 'chain_start' field in 'chain_fix_data_t'.
 *
 * \param data  Data to be updated.
 * \param d     DNAME to be set.
 */
static void update_chain_start(chain_fix_data_t *data, const knot_dname_t *d)
{
	assert(data && d);
	data->chain_start = d;
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
 * \brief Updates next dname with 'next_hashed' from d's NSEC3 RR.
 *
 * \param fix_data  Data to be updated.
 * \param d         DNAME to search for.
 */
static void update_next_nsec3_dname(chain_fix_data_t *fix_data,
                                    const knot_dname_t *d)

{
	knot_dname_free(&fix_data->next_dname);
	if (d == NULL) {
		fix_data->next_dname = NULL;
	} else {
		const knot_node_t *nsec3_node =
			knot_zone_contents_find_nsec3_node(fix_data->zone, d);
		assert(nsec3_node);
		const knot_rrset_t *nsec3_rrset = knot_node_rrset(nsec3_node,
		                                                  KNOT_RRTYPE_NSEC3);
		assert(nsec3_rrset);
		fix_data->next_dname =
			next_dname_from_nsec3_rrset(nsec3_rrset,
		                                    fix_data->zone->apex->owner);
	}
}

/* - Misc. helpers ---------------------------------------------------------- */

/*!
 * \brief Helper function - sets variables by looking for data in the zone.
 */
static void fetch_nodes_from_zone(const knot_zone_contents_t *z,
                                  const knot_dname_t *a,
                                  const knot_dname_t *b,
                                  const knot_dname_t *a_hash,
                                  const knot_dname_t *b_hash,
                                  const knot_node_t **a_node,
                                  const knot_node_t **b_node,
                                  const knot_node_t **a_nsec3_node,
                                  const knot_node_t **b_nsec3_node)
{
	*a_node = knot_zone_contents_find_node(z, a);
	*b_node = knot_zone_contents_find_node(z, b);
	*a_nsec3_node = knot_zone_contents_find_nsec3_node(z, a_hash);
	*b_nsec3_node = knot_zone_contents_find_nsec3_node(z, b_hash);
}

/*!
 * \brief Checks whether NSEC3 covered was not changed and is now non-auth.
 *
 * \param z               Zone to be searched.
 * \param d_hashed        Hash to look for.
 * \param sorted_changes  DDNS/reload changes.
 *
 * \return True if this node can be used, false otherwise.
 */
static bool covered_node_usable(const knot_zone_contents_t *z,
                                const knot_dname_t *d_hashed,
                                const hattrie_t *sorted_changes)
{
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, d_hashed, NULL);
	value_t *val = hattrie_tryget((hattrie_t *)sorted_changes,
	                              (char *)lf+1, *lf);
	if (val == NULL) {
		return false;
	} else {
		signed_info_t *info = (signed_info_t *)(*val);
		assert(knot_dname_is_equal(info->hashed_dname, d_hashed));
		// Get normal node
		const knot_node_t *normal_node =
			knot_zone_contents_find_node(z, info->dname);
		// Usable if not deleted and not non-auth
		return normal_node != NULL &&
		       !knot_node_is_non_auth(normal_node);
	}
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
	knot_rrset_t **node_rrsets = knot_node_get_rrsets_no_copy(n);
	for (int i = 0; i < n->rrset_count; i++) {
		if (node_rrsets[i]->type == KNOT_RRTYPE_NSEC ||
		    node_rrsets[i]->type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		bool should_sign = false;
		int ret = knot_zone_sign_rr_should_be_signed(n,
		                                             node_rrsets[i],
		                                             NULL, &should_sign);
		assert(ret == KNOT_EOK); // No tree inside the function, no fail
		if (should_sign) {
			return true;
		}
	}

	return false;
}

/*!
 * \brief Checks whether NSEC3 RR in zone is valid and updates it if needed.
 *
 * \param from          Start hash in NSEC3 link.
 * \param to            Destination hash in NSEC3 link.
 * \param covered_node  Node covered by 'from' hash.
 * \param out_ch        Changes go here.
 * \param zone          Changed zone.
 * \param soa_min       TTL to use for new NSEC3 RRs.
 *
 * \return KNOT_E*
 */
static int update_nsec3(const knot_dname_t *from, const knot_dname_t *to,
                        const knot_node_t *covered_node,
                        knot_changeset_t *out_ch,
                        const knot_zone_contents_t *zone, uint32_t soa_min)
{
	assert(from && to && out_ch && zone);
	// Get old NSEC3 RR (there might not be any)
	const knot_node_t *from_node = knot_zone_contents_find_nsec3_node(zone,
	                                                                  from);
	const knot_rrset_t *old_nsec3 = from_node ?
	                                knot_node_rrset(from_node,
	                                                KNOT_RRTYPE_NSEC3) : NULL;

	// Create new NSEC3 - start with binary next hashed name
	uint8_t *b32_hash = (uint8_t *)knot_dname_to_str(to);
	assert(zone->nsec3_params.algorithm != 0);
	size_t b32_length =
		knot_nsec3_hash_b32_length(zone->nsec3_params.algorithm);
	if (b32_hash == NULL) {
		return KNOT_ENOMEM;
	}
	uint8_t *binary_next = NULL;
	int32_t written = base32hex_decode_alloc(b32_hash, b32_length,
	                                         &binary_next);
	free(b32_hash);
	if (written < 0) {
		return written;
	}

	knot_rrset_t *gen_nsec3 = NULL;
	// Create or reuse
	if (covered_node) {
		// Use bitmap from given node
		bitmap_t bm = { '\0' };
		bitmap_add_node_rrsets(&bm, covered_node);
		if (node_should_be_signed_nsec3(covered_node)) {
			bitmap_add_type(&bm, KNOT_RRTYPE_RRSIG);
		}
		// Create owner
		knot_dname_t *owner = knot_dname_copy(from);
		if (owner == NULL) {
			free(binary_next);
			return KNOT_ENOMEM;
		}
		// Create the RRSet
		gen_nsec3 = create_nsec3_rrset(owner,
		                                         &zone->nsec3_params,
		                                         &bm, binary_next,
		                                         soa_min);
		if (gen_nsec3 == NULL) {
			free(binary_next);
			knot_dname_free(&owner);
			return KNOT_ERROR;
		}
	} else {
		assert(old_nsec3);
		// Reuse bitmap and data from old NSEC3
		int ret = knot_rrset_deep_copy(old_nsec3, &gen_nsec3,
		                                      NULL);
		if (ret != KNOT_EOK) {
			free(binary_next);
			return ret;
		}
		uint8_t *next_hashed = NULL;
		uint8_t next_hashed_size;
		knot_rdata_nsec3_next_hashed(gen_nsec3, 0, &next_hashed,
		                             &next_hashed_size);
		assert(next_hashed);
		if (next_hashed_size != written) {
			// Possible algo mismatch
			free(binary_next);
			knot_rrset_deep_free(&gen_nsec3, 1, NULL);
			return KNOT_ERROR;
		}
		memcpy(next_hashed, binary_next, next_hashed_size);
	}
	free(binary_next);

	if (old_nsec3 && knot_rrset_equal(old_nsec3, gen_nsec3,
	                                  KNOT_RRSET_COMPARE_WHOLE)) {
		// Nothing to update
		knot_rrset_deep_free(&gen_nsec3, 1, NULL);
		return KNOT_EOK;
	} else {
		// Drop old
		int ret = KNOT_EOK;
		if (old_nsec3) {
			assert(0);
			ret = knot_nsec_changeset_remove(old_nsec3, NULL, out_ch);
			if (ret != KNOT_EOK) {
				knot_rrset_deep_free(&gen_nsec3, 1, NULL);
				return ret;
			}
		}

		// Add new
		ret = knot_changeset_add_rrset(out_ch, gen_nsec3,
		                               KNOT_CHANGESET_ADD);
		if (ret != KNOT_EOK) {
			knot_rrset_deep_free(&gen_nsec3, 1, NULL);
			return ret;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief  Gets first NSEC3 node from zone.
 *
 * \param  z Zone to be searched.
 *
 * \return first NSEC3 node on success, NULL otherwise.
 */
static const knot_node_t *zone_first_nsec3_node(const knot_zone_contents_t *z)
{
	assert(z && hattrie_weight(z->nsec3_nodes) > 0);
	hattrie_iter_t *i = hattrie_iter_begin(z->nsec3_nodes, true);
	if (i == NULL) {
		return NULL;
	}
	knot_node_t *first_node = (knot_node_t *)*hattrie_iter_val(i);
	assert(first_node);
	hattrie_iter_free(i);
	return first_node;
}

/*!
 * \brief  Gets last NSEC3 node from zone.
 *
 * \param  z Zone to be searched.
 *
 * \return last NSEC3 node on success, NULL otherwise.
 */
static const knot_node_t *zone_last_nsec3_node(const knot_zone_contents_t *z)
{
	// Get first node
	const knot_node_t *first_node = zone_first_nsec3_node(z);
	if (first_node == NULL) {
		return NULL;
	}
	// Get node previous to first = last node
	return knot_zone_contents_find_previous_nsec3(z, first_node->owner);
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

	knot_rrset_t *from_sig = knot_node_get_rrset(from, KNOT_RRTYPE_RRSIG);
	if (from_sig == NULL) {
		return KNOT_EOK;
	}
	return knot_node_add_rrset(to, from_sig);
}

/*!
 * \brief Reuse signatatures by shallow copying them from one tree to another.
 */
static int copy_signatures(const knot_zone_tree_t *from, knot_zone_tree_t *to)
{
	assert(from);
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
			return ret;
		}
	}

	hattrie_iter_free(it);
	return KNOT_EOK;
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
		// newly allocated NSEC3 nodes
		knot_rrset_t *nsec3 = knot_node_get_rrset(node,
		                                          KNOT_RRTYPE_NSEC3);
		knot_rrset_deep_free(&nsec3, 1, NULL);
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
static knot_rrset_t *create_nsec3_rrset(knot_dname_t *owner,
                                        const knot_nsec3_params_t *params,
                                        const bitmap_t *rr_types,
                                        const uint8_t *next_hashed,
                                        uint32_t ttl)
{
	assert(owner);
	assert(params);
	assert(rr_types);

	knot_rrset_t *rrset;
	rrset = knot_rrset_new(owner, KNOT_RRTYPE_NSEC3, KNOT_CLASS_IN, ttl, NULL);
	if (!rrset) {
		return NULL;
	}

	size_t rdata_size = nsec3_rdata_size(params, rr_types);
	uint8_t *rdata = knot_rrset_create_rdata(rrset, rdata_size, NULL);
	if (!rdata) {
		knot_rrset_free(&rrset);
		return NULL;
	}

	nsec3_fill_rdata(rdata, params, rr_types, next_hashed, ttl);

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
	nsec3_rrset = create_nsec3_rrset(owner, nsec3_params,
	                                           rr_types, NULL, ttl);
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

	knot_rrset_t *a_rrset = knot_node_get_rrset(a, KNOT_RRTYPE_NSEC3);
	assert(a_rrset);
	uint8_t algorithm = knot_rdata_nsec3_algorithm(a_rrset, 0);
	if (algorithm == 0) {
		return KNOT_EINVAL;
	}

	uint8_t *raw_hash = NULL;
	uint8_t raw_length = 0;
	knot_rdata_nsec3_next_hashed(a_rrset, 0, &raw_hash, &raw_length);
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
		result = knot_nsec_changeset_remove(knot_node_rrset(node,
		                                    KNOT_RRTYPE_NSEC),
		                                    knot_node_rrset(node,
		                                    KNOT_RRTYPE_RRSIG),
		                                    chgset);
		if (result != KNOT_EOK) {
			break;
		}
		if (knot_node_rrset(node, KNOT_RRTYPE_NSEC)) {
			knot_node_set_replaced_nsec(node);
		}

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

/* - NSEC3 chain fix -------------------------------------------------------- */

/* - Nonterminal handling --------------------------------------------------- */

/*!
 * \brief Cuts DNAME and looks for all the labels in the zone.
 *
 * \param dname  DNAME to be cut.
 * \param zone   Zone to be searched.
 * \param t      Trie that contains empty non-terminals.
 *
 * \return KNOT_E*
 */
static int walk_dname_and_store_empty_nonterminals(const knot_dname_t *dname,
                                                   const knot_zone_contents_t *zone,
                                                   hattrie_t *t)
{
	assert(dname);
	assert(zone);
	assert(t);

	if (knot_dname_size(dname) == 1) {
		// Root dname
		assert(*dname == '\0');
		return KNOT_EOK;
	}
	if (knot_dname_is_equal(dname, zone->apex->owner)) {
		// Apex
		return KNOT_EOK;
	}

	// Start after the first cut
	const knot_dname_t *cut = knot_wire_next_label(dname, NULL);
	while (*cut != '\0' && !knot_dname_is_equal(cut, zone->apex->owner)) {
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
			hattrie_insert_dname(t, (knot_dname_t *)cut);
		}
		cut = knot_wire_next_label(cut, NULL);
	}
	return KNOT_EOK;
}
/*!
 * \brief Cuts labels and looks for nodes in zone, if an empty node is found
 *        adds it into trie. There may be multiple nodes. Not all nodes
 *        have to be checked, but not doing that would bloat the code.
 *
 * \param zone
 * \param sorted_changes
 *
 * \return KNOT_E*
 */
static int update_changes_with_empty_non_terminals(const knot_zone_contents_t *zone,
                                                   hattrie_t *sorted_changes)
{
	assert(zone);
	assert(sorted_changes);

	/*!
	 * Create trie with newly created nonterminals, as we cannot (probably)
	 * insert to the trie in the middle of iteration.
	 */
	hattrie_t *nterminal_t = hattrie_create();
	if (nterminal_t == NULL) {
		return KNOT_ENOMEM;
	}

	// Start trie iteration
	const bool sorted = false;
	hattrie_iter_t *itt = hattrie_iter_begin(sorted_changes, sorted);
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
			hattrie_free(nterminal_t);
			return ret;
		}
	}
	hattrie_iter_free(itt);

	// Reinsert updated nonterminals into trie (dname already converted)
	itt = hattrie_iter_begin(nterminal_t, sorted);
	if (itt == NULL) {
		return KNOT_ERROR;
	}
	for (; !hattrie_iter_finished(itt); hattrie_iter_next(itt)) {
		// Store keys from table directly to trie
		size_t key_size = 0;
		const char *k = hattrie_iter_key(itt, &key_size);
		assert(k && key_size > 0);
		// Create dummy value
		signed_info_t *info = malloc(sizeof(signed_info_t));
		if (info == NULL) {
			ERR_ALLOC_FAILED;
			hattrie_iter_free(itt);
			hattrie_free(nterminal_t);
			return KNOT_ENOMEM;
		}
		memset(info, 0, sizeof(signed_info_t));
		info->dname =
			knot_dname_copy((knot_dname_t *)(*hattrie_iter_val(itt)));
		if (info->dname == NULL) {
			hattrie_iter_free(itt);
			hattrie_free(nterminal_t);
			return KNOT_ENOMEM;
		}
		*hattrie_get(sorted_changes, k, key_size) = info;
	}

	hattrie_iter_free(itt);
	hattrie_free(nterminal_t);

	return KNOT_EOK;
}

/* - Changeset hashing ------------------------------------------------------ */

/*!
 * \brief Iterates through changes made by DDNS/reload and NSEC3-hashes each name.
 *
 * \param sorted_changes  Changes to be iterated.
 * \param zone            Changed zone.
 * \param out             NSEC3 hashes are saved here with original DNAMEs.
 *
 * \return KNOT_E*
 */
static int create_nsec3_hashes_from_trie(const hattrie_t *sorted_changes,
                                         const knot_zone_contents_t *zone,
                                         hattrie_t **out)
{
	assert(sorted_changes);
	assert(hattrie_weight(sorted_changes) > 0);
	*out = hattrie_create();
	if (*out == NULL) {
		return KNOT_ENOMEM;
	}

	const bool sort = false;
	hattrie_iter_t *itt = hattrie_iter_begin(sorted_changes, sort);
	if (itt == NULL) {
		hattrie_free(*out);
		return KNOT_ERROR;
	}

	for (; !hattrie_iter_finished(itt); hattrie_iter_next(itt)) {
		signed_info_t *val = (signed_info_t *)(*hattrie_iter_val(itt));
		const knot_dname_t *original_dname = val->dname;
		knot_dname_t *nsec3_name =
			knot_create_nsec3_owner(original_dname,
		                                zone->apex->owner,
		                                &zone->nsec3_params);
		if (nsec3_name == NULL) {
			hattrie_free(*out);
			return KNOT_ERROR;
		}
		knot_dname_to_lower(nsec3_name);
		val->hashed_dname = nsec3_name;

		// Convert NSEC3 hash to sortable format
		uint8_t lf[KNOT_DNAME_MAXLEN];
		knot_dname_lf(lf, nsec3_name, NULL);
		// Store into new trie
		*hattrie_get(*out, (char *)lf+1, *lf) = val;
	}
	hattrie_iter_free(itt);
	return KNOT_EOK;
}

/* - Actual chain fix ------------------------------------------------------- */

/*!
 * \brief Fetches covered node for 'hash' from zone.
 *
 * \param fix_data  Chain fix data.
 * \param hash      Hash to search for.
 *
 * \return          Covered node if changed via DDNS/reload, NULL otherwise.
 */
static const knot_node_t *fetch_covered_node(chain_fix_data_t *fix_data,
                                             const knot_dname_t *hash)
{
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, hash, NULL);
	value_t *val = hattrie_tryget((hattrie_t *)fix_data->sorted_changes,
	                              (char *)lf+1, *lf);
	if (val == NULL) {
		// No change, old bitmap can be reused
		return NULL;
	} else {
		signed_info_t *info = (signed_info_t *)*val;
		return knot_zone_contents_find_node(fix_data->zone,
		                                    info->dname);
	}
}

/*!
 * \brief Handles fixing of 'gaps' in NSEC3 chain.
 *
 * \param fix_data      Chain fix data.
 * \param a_hash        Hash of DNAME we want to connect to.
 * \param a_node        Node covered by 'a_hash' (normal node).
 * \param a_nsec3_node  NSEC3 node for 'a_hash'.
 *
 * \return KNOT_E*
 */
static int handle_nsec3_next_dname(chain_fix_data_t *fix_data,
                                   const knot_dname_t *a_hash,
                                   const knot_node_t *a_node,
                                   const knot_node_t *a_nsec3_node)
{
	assert(fix_data && fix_data->next_dname && a_hash && a_node);
	int ret = KNOT_EOK;
	if (knot_dname_is_equal(fix_data->next_dname, a_hash)) {
		assert(a_nsec3_node);
		// We have to take one more step in the chain
		const knot_rrset_t *nsec3_rrset =
			knot_node_rrset(a_nsec3_node, KNOT_RRTYPE_NSEC3);
		assert(nsec3_rrset);
		knot_dname_t *rr_next_dname =
			next_dname_from_nsec3_rrset(nsec3_rrset,
		                                    fix_data->zone->apex->owner);
		if (rr_next_dname == NULL) {
			return KNOT_ENOMEM;
		}
		const knot_node_t *next_node =
			knot_zone_contents_find_nsec3_node(fix_data->zone,
			                                   rr_next_dname);
		assert(next_node);
		knot_dname_free(&rr_next_dname);
		update_last_used(fix_data, next_node->owner,
		                 fetch_covered_node(fix_data, next_node->owner));
		ret = update_nsec3(a_hash, rr_next_dname, a_node,
		                   fix_data->out_ch,
		                   fix_data->zone, fix_data->ttl);
	} else {
		// Next dname is usable
		update_last_used(fix_data, fix_data->next_dname,
		                 fetch_covered_node(fix_data, fix_data->next_dname));
		ret = update_nsec3(a_hash, fix_data->next_dname,
		                   a_node, fix_data->out_ch,
		                   fix_data->zone, fix_data->ttl);
		update_next_nsec3_dname(fix_data, NULL);
		return ret == KNOT_EOK ? NSEC_NODE_RESET : ret;
	}
	update_next_nsec3_dname(fix_data, NULL);
	return ret == KNOT_EOK ? NSEC_NODE_RESET : ret;
}

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
	const knot_rrset_t *old_nsec3 = knot_node_rrset(node, KNOT_RRTYPE_NSEC3);
	assert(old_nsec3);
	assert(0);
	int ret = knot_nsec_changeset_remove(old_nsec3, NULL, fix_data->out_ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/*!
	 * This node should be ignored, but we might need the next dname from
	 * previous node.
	 */
	if (fix_data->next_dname == NULL) {
		fix_data->next_dname =
			next_dname_from_nsec3_rrset(old_nsec3,
			                            fix_data->zone->apex->owner);
		if (fix_data->next_dname == NULL) {
			return KNOT_ENOMEM;
		}
	}

	return NSEC_NODE_SKIP;
}

/*!
 * \brief Checks if old and new NSEC3 chains should be connected.
 *
 * \param fix_data Chain fix data.
 * \param a          Old chain end.
 * \param b          New chain start.
 * \param zone_prev  Previous node from zone for 'b'.
 *
 * \return True if chains should be connected, false if no.
 */
static bool should_connect_to_old(chain_fix_data_t *fix_data,
                                  const knot_dname_t *a, const knot_dname_t *b,
                                  const knot_dname_t *zone_prev)
{
	return fix_data->chain_start && !fix_data->old_connected &&
	       a && knot_dname_cmp(a, zone_prev) < 0 &&
	       knot_dname_cmp(zone_prev, b) < 0;
}

/*!
 * \brief Connects old NSEC3 chain and new NSE3 chain.
 *
 * \param fix_data        Chain fix data.
 * \param a_hash          Old NSEC3 chain end.
 * \param b_hash          New NSEC3 chain beginning.
 * \param a_node          Node covered by 'a_hash', from changeset.
 * \param zone_prev_node  Nobe covered by 'a_hash', from zone.
 *
 * \return KNOT_E*
 */
static int connect_to_old_start(chain_fix_data_t *fix_data,
                                const knot_dname_t *a_hash,
                                const knot_dname_t *b_hash,
                                const knot_node_t *a_node,
                                const knot_node_t *zone_prev_node)
{
	fix_data->old_connected = true;
	assert(fix_data && a_hash && b_hash && a_node && zone_prev_node);
	int ret = update_nsec3(a_hash, zone_prev_node->owner,
	                       a_node, fix_data->out_ch, fix_data->zone,
	                       fix_data->ttl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	update_last_used(fix_data, b_hash,
	                 fetch_covered_node(fix_data, b_hash));
	return update_nsec3(zone_prev_node->owner, b_hash,
	                    fetch_covered_node(fix_data, zone_prev_node->owner),
	                    fix_data->out_ch, fix_data->zone, fix_data->ttl);
}

/*!
 * \brief Decides whether to use previous hash from zone or changeset.
 *
 * \param a_hash     Previous hash from changeset.
 * \param b_hash     Hash we want to connect to.
 * \param zone_prev  Previous hash from zone.
 *
 * \return True if previous dname from changeset should be used, false otherwise.
 */
static bool use_prev_from_changeset(const knot_dname_t *a_hash,
                                    const knot_dname_t *b_hash,
                                    const knot_dname_t *zone_prev)
{
	if (a_hash) {
		// Direct hit from changeset, or fits between zone and changeset gap
		bool name_eq_closer = knot_dname_cmp(a_hash,
		                                     zone_prev) >= 0;
		// Previous node is no longer valid - new chain start was set
		bool part_of_new_start = knot_dname_cmp(a_hash,
		                                        zone_prev) < 0 &&
		                         knot_dname_cmp(b_hash,
		                                        zone_prev) <= 0;
		return name_eq_closer || part_of_new_start;
	} else {
		return false;
	}
}

/*!
 * \brief Finds previous usable NSEC3 node in zone, checks if node node not
 *        deleted in changes.
 * \param z               Zone to be searched.
 * \param d_hashed        Hash to search for.
 * \param sorted_changes  DDNS/reload changes.
 *
 * \return Previous NSEC3 node for 'd_hashed'.
 */
static const knot_node_t *find_prev_nsec3_node(const knot_zone_contents_t *z,
                                               const knot_dname_t *d_hashed,
                                               const hattrie_t *sorted_changes)
{
	// Find previous node for the node
	const knot_node_t *prev_nsec3_node =
		knot_zone_contents_find_previous_nsec3(z, d_hashed);
	assert(prev_nsec3_node);
	bool prev_nsec3_found = !covered_node_usable(z, prev_nsec3_node->owner,
	                                             sorted_changes);
	while (!prev_nsec3_found) {
		prev_nsec3_node =
			knot_zone_contents_find_previous_nsec3(z,
			                                       prev_nsec3_node->owner);
		assert(prev_nsec3_node);
		// Either the node is usable, or there's nothing more to find
		prev_nsec3_found = covered_node_usable(z,
		                                       prev_nsec3_node->owner,
		                                       sorted_changes) ||
		                   knot_dname_is_equal(prev_nsec3_node->owner,
		                                       d_hashed);
	}
	return prev_nsec3_node;
}

/*!
 * \brief Fixes one link between 'a' and 'b', or rather between their hashes.
 *        'a_hash' is always < 'b_hash'. Called only via iteration function.
 *
 * \param a         Normal DNAME (changed in the update/reload)
 * \param a_hash    NSEC3 hash of 'a'.
 * \param b         Normal DNAME (changed in the update/reload)
 * \param b_hash    NSEC3 hash of 'b'.
 * \param fix_data  Fix data.
 *
 * \return KNOT_EOK if okay, KNOT_E* if something went wrong,
 *         NSEC_NODE_RESET, NSEC_NODE_SKIP if special handling is needed by the
 *         iteration funtion.
 */
static int fix_nsec3_chain(knot_dname_t *a, knot_dname_t *a_hash,
                           knot_dname_t *b, knot_dname_t *b_hash,
                           chain_fix_data_t *fix_data)
{
	assert(b && b_hash);
	assert((!a && !a_hash) || (a && a_hash));
	assert(fix_data);
	// Get nodes from zone
	const knot_node_t *a_node, *b_node, *a_nsec3_node, *b_nsec3_node;
	fetch_nodes_from_zone(fix_data->zone, a, b, a_hash, b_hash, &a_node,
	                      &b_node, &a_nsec3_node, &b_nsec3_node);
	// Find previous node in zone ('proper' node might not be in the zone yet)
	const knot_node_t *prev_nsec3_node =
		find_prev_nsec3_node(fix_data->zone, b_hash,
		                     fix_data->sorted_changes);
	if (prev_nsec3_node == NULL) {
		// Should not happen, zone would have to have no NSEC3 chain
		return KNOT_ERROR;
	}

	// Handle possible node removal
	bool node_deleted = b_node == NULL;
	if (node_deleted) {
		// The deleted node might have been authoritative, but not anymore
		if (fix_data->last_used_dname == NULL) {
			update_last_used(fix_data, prev_nsec3_node->owner,
			                 fetch_covered_node(fix_data,
			                                    prev_nsec3_node->owner));
		}
		return handle_deleted_node(b_nsec3_node, fix_data);
	}
	if (knot_node_is_non_auth(b_node)) {
		// Nothing to fix in this node
		return NSEC_NODE_SKIP;
	}

	// Find out whether to use a node from changeset or from zone
	bool use_prev_from_chgs = use_prev_from_changeset(a_hash, b_hash,
	                                                  prev_nsec3_node->owner);
	if (use_prev_from_chgs) {
		// No valid data for the previous node, create the forward NSEC3
		update_last_used(fix_data, b_hash, b_node);
		return update_nsec3(a_hash, b_hash, a_node, fix_data->out_ch,
		                    fix_data->zone, fix_data->ttl);
	}
	if (should_connect_to_old(fix_data,
	                          a_hash, b_hash, prev_nsec3_node->owner)) {
		// Connect old start with new start
		return connect_to_old_start(fix_data, a_hash, b_hash, a_node,
		                            prev_nsec3_node);
	}

	// Use either next_dname or data from zone
	bool new_chain_start =
		knot_dname_cmp(prev_nsec3_node->owner, b_hash) > 0 &&
		!(zone_first_nsec3_node(fix_data->zone) == b_nsec3_node);
	if (new_chain_start) {
		assert(a == NULL); // This has to be the first change
		// New chain started by this change
		update_last_used(fix_data, b_hash, b_node);
		update_chain_start(fix_data, b_hash);
		return KNOT_EOK;
	} else if (fix_data->next_dname) {
		return handle_nsec3_next_dname(fix_data, a_hash,
		                               a_node, a_nsec3_node);
	} else {
		// Previous node was not changed in DDNS, NSEC3 has to be present
		assert(knot_node_rrset(prev_nsec3_node, KNOT_RRTYPE_NSEC3));
		update_next_nsec3_dname(fix_data, prev_nsec3_node->owner);
		update_last_used(fix_data, b_hash, b_node);
		return update_nsec3(prev_nsec3_node->owner, b_hash,
		                    fetch_covered_node(fix_data, prev_nsec3_node->owner),
		                    fix_data->out_ch, fix_data->zone,
		                    fix_data->ttl);
	}

	return KNOT_EOK;
}

/*!
 * \brief Finalizes NSEC3 chain.
 *
 * \param fix_data Chain fix data.
 *
 * \return KNOT_E*
 */
static int chain_finalize_nsec3(chain_fix_data_t *fix_data)
{
	assert(fix_data);
	if (fix_data->next_dname == NULL && fix_data->chain_start == NULL) {
		// Nothing to fix
		return KNOT_EOK;
	}
	const knot_dname_t *from = fix_data->last_used_dname;
	assert(from);
	const knot_node_t *from_node = fix_data->last_used_node;
	const knot_dname_t *to = NULL;
	if (fix_data->chain_start) {
		/*!
		 * New chain start has to be closed - get last dname
		 * in the chain from zone or changeset.
		 */
		const knot_node_t *last_node =
			zone_last_nsec3_node(fix_data->zone);
		if (last_node == NULL) {
			return KNOT_ENOMEM;
		}
		if (!fix_data->old_connected) {
			/*!
			 * New chain was started, but not connected to
			 * the old one.
			 */
			const knot_node_t *first_nsec3 =
				zone_first_nsec3_node(fix_data->zone);
			if (first_nsec3 == NULL) {
				return KNOT_ENOMEM;
			}

			int ret = update_nsec3(fix_data->last_used_dname,
			                       first_nsec3->owner,
			                       fix_data->last_used_node,
			                       fix_data->out_ch,
			                       fix_data->zone, fix_data->ttl);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
		// Close the chain
		to = fix_data->chain_start;
		if (knot_dname_cmp(last_node->owner,
		                   fix_data->last_used_dname) > 0) {
			// Use last zone node to close the chain
			from = last_node->owner;
			from_node = NULL; // Was not changed
		}
	} else if (knot_dname_is_equal(from,
	                               fix_data->zone->apex->nsec3_node->owner)) {
		// Special case where all nodes but the apex are deleted
		to = fix_data->last_used_dname;
	} else if (knot_dname_is_equal(from, fix_data->next_dname)) {
		// We do not want to point it to itself, extract next
		const knot_node_t *nsec3_node =
			knot_zone_contents_find_nsec3_node(fix_data->zone,
			                                   from);
		assert(nsec3_node);
		const knot_rrset_t *nsec3_rrset =
			knot_node_rrset(nsec3_node, KNOT_RRTYPE_NSEC3);
		assert(nsec3_rrset);
		knot_dname_free(&fix_data->next_dname);
		knot_dname_t *next =
			next_dname_from_nsec3_rrset(nsec3_rrset,
			                            fix_data->zone->apex->owner);
		if (next == NULL) {
			return KNOT_ENOMEM;
		}
		// We have to call update here, since different name should be freed
		int ret = update_nsec3(from, next, fix_data->last_used_node,
		                       fix_data->out_ch, fix_data->zone,
		                       fix_data->ttl);
		knot_dname_free(&next);
		return ret;
	} else {
		// Normal case
		to = fix_data->next_dname;
	}
	assert(to);
	int ret = update_nsec3(from, to, from_node,
	                       fix_data->out_ch, fix_data->zone, fix_data->ttl);
	knot_dname_free(&fix_data->next_dname);
	return ret;
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

	return knot_nsec_only_nsec_and_rrsigs_in_node(node);
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
			 * but only temporarily! It must be set right after
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

/*!
 * \brief Fixes NSEC3 chain after DDNS/reload.
 */
int knot_nsec3_fix_chain(hattrie_t *sorted_changes, chain_fix_data_t *fix_data)
{
	// Empty non-terminals are not in the changes, update
	int ret = update_changes_with_empty_non_terminals(fix_data->zone,
	                                                  sorted_changes);
	if (ret != KNOT_EOK) {
		return ret;
	}
	// Create and sort NSEC3 hashes
	hattrie_t *nsec3_names = NULL;
	ret = create_nsec3_hashes_from_trie(sorted_changes,
	                                    fix_data->zone,
	                                    &nsec3_names);
	if (ret != KNOT_EOK) {
		return ret;
	}
	hattrie_build_index(nsec3_names);
	fix_data->sorted_changes = nsec3_names;

	// Fix NSEC3 chain
	ret = knot_nsec_chain_iterate_fix(nsec3_names, fix_nsec3_chain,
	                                  chain_finalize_nsec3, fix_data);
	hattrie_free(nsec3_names);
	return ret;
}
