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
#include "knot/dnssec/nsec5-chain.h"
#include "libknot/dname.h"
#include "libknot/packet/wire.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone-diff.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/zone-sign.h"
#include "libknot/rrset-dump.h"
#include "knot/dnssec/zone-nsec.h"
#include "libknot/dnssec/bitmap.h"
#include "libknot/rrtype/nsec5.h"

/* - Forward declarations --------------------------------------------------- */

static int create_nsec5_rrset(knot_rrset_t *rrset, //do I need keytag here?
                              knot_dname_t *dname,
                              const bitmap_t *,
                              const uint8_t *,
                              uint32_t,
                              const knot_zone_key_t *,
                              bool wildcard);

/* - Helper functions ------------------------------------------------------- */

/* - NSEC5 node comparison -------------------------------------------------- */

/*!
 * \brief Perform some basic checks that the node is a valid NSEC5 node.
 */
inline static bool valid_nsec5_node(const zone_node_t *node)
{
	assert(node);

	if (node->rrset_count > 2) {
		return false;
	}

	const knot_rdataset_t *nsec5 = node_rdataset(node, KNOT_RRTYPE_NSEC5);
	if (nsec5 == NULL) {
		return false;
	}

	if (nsec5->rr_count != 1) {
		return false;
	}
    //maybe additional checks here
	return true;
}

/*!
 * \brief Check if two nodes are equal.
 */
static bool are_nsec5_nodes_equal(const zone_node_t *a, const zone_node_t *b)
{
	if (!(valid_nsec5_node(a) && valid_nsec5_node(b))) {
		return false;
	}

	knot_rrset_t a_rrset = node_rrset(a, KNOT_RRTYPE_NSEC5);
	knot_rrset_t b_rrset = node_rrset(b, KNOT_RRTYPE_NSEC5);
	return knot_rrset_equal(&a_rrset, &b_rrset, KNOT_RRSET_COMPARE_WHOLE);
}

/*!
 * \brief Check whether at least one RR type in node should be signed,
 *        used when signing with NSEC5.
 *
 * \param node  Node for which the check is done.
 *
 * \return true/false.
 */
static bool node_should_be_signed_nsec5(const zone_node_t *n)
{
	for (int i = 0; i < n->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(n, i);
		if (rrset.type == KNOT_RRTYPE_NSEC ||
            rrset.type == KNOT_RRTYPE_NSEC3 ||
            rrset.type == KNOT_RRTYPE_NSEC5 ||
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

/* - RRSIGs handling for NSEC5 ---------------------------------------------- */

/*!
 * \brief Shallow copy NSEC5 signatures from the one node to the second one.
 *        Just sets the pointer, needed only for comparison.
 */
static int shallow_copy_signature(const zone_node_t *from, zone_node_t *to)
{
	assert(valid_nsec5_node(from));
	assert(valid_nsec5_node(to));

	knot_rrset_t from_sig = node_rrset(from, KNOT_RRTYPE_RRSIG);
	if (knot_rrset_empty(&from_sig)) {
		return KNOT_EOK;
	}
	return node_add_rrset(to, &from_sig, NULL);
}

/*!
 * \brief Reuse signatatures by shallow copying them from one tree to another.
 */
static int copy_signatures(const zone_tree_t *from, zone_tree_t *to)
{
	if (zone_tree_is_empty(from)) {
        printf("copy_signatures: zone->nsec3 nodes is empty\n");
		return KNOT_EOK;
	}

	assert(to);

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(from, sorted);

	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		zone_node_t *node_from = (zone_node_t *)*hattrie_iter_val(it);
		zone_node_t *node_to = NULL;

		zone_tree_get(to, node_from->owner, &node_to);
		if (node_to == NULL) {
			continue;
		}

		if (!are_nsec5_nodes_equal(node_from, node_to)) {
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
static void free_nsec5_tree(zone_tree_t *nodes)
{
	assert(nodes);

	bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);
	for (/* NOP */; !hattrie_iter_finished(it); hattrie_iter_next(it)) {
		zone_node_t *node = (zone_node_t *)*hattrie_iter_val(it);
		// newly allocated NSEC5 nodes
		knot_rdataset_t *nsec5 = node_rdataset(node, KNOT_RRTYPE_NSEC5);
		knot_rdataset_t *rrsig = node_rdataset(node, KNOT_RRTYPE_RRSIG);
		knot_rdataset_clear(nsec5, NULL);
		knot_rdataset_clear(rrsig, NULL);
		node_free(&node, NULL);
	}

	hattrie_iter_free(it);
	zone_tree_free(&nodes);
}

/* - NSEC5 nodes construction ----------------------------------------------- */

/*!
 * \brief Get NSEC5 RDATA size.
 */
static size_t nsec5_rdata_size(const bitmap_t *rr_types)
{
	assert(rr_types);

	return 4 + knot_nsec5_hash_length(1) //always FHDSHA256SHA256
	         + bitmap_size(rr_types);
}

/*!
 * \brief Fill NSEC5 RDATA.
 *
 * \note Content of next hash field is not changed.
 */
static void nsec5_fill_rdata(uint8_t *rdata,
                             const bitmap_t *rr_types,
                             const uint8_t *next_hashed, uint32_t ttl, const knot_zone_key_t *key, bool wildcard)
{
	assert(rdata);
	assert(rr_types);
    assert(key);

	uint8_t hash_length = knot_nsec5_hash_length(1); //always FHDSHA256SHA256
    
    knot_wire_write_u16(rdata, key->nsec5_key.keytag); ///HERE PUT KEYTAG!;
	rdata += 2;
    if (wildcard) {
        *rdata = 1 << 1;//todo: define as KNOT_NSEC5_WILDCARD_FLAG;
    }
    else {
        *rdata = 0;
    }
	rdata += 1;
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
 * \brief Creates NSEC5 RRSet.
 *
 * \param owner        Owner for the RRSet.
 * \param rr_types     Bitmap.
 * \param next_hashed  Next hashed.
 * \param ttl          TTL for the RRSet.
 *
 * \return Pointer to created RRSet on success, NULL on errors.
 */
static int create_nsec5_rrset(knot_rrset_t *rrset,
                              knot_dname_t *owner,
                              const bitmap_t *rr_types,
                              const uint8_t *next_hashed,
                              uint32_t ttl,
                              const knot_zone_key_t *key,
                              bool wildcard)
{
	assert(rrset);
	assert(owner);
	assert(rr_types);
    assert(key);

	knot_rrset_init(rrset, owner, KNOT_RRTYPE_NSEC5, KNOT_CLASS_IN);

	size_t rdata_size = nsec5_rdata_size(rr_types);
	uint8_t rdata[rdata_size];
	nsec5_fill_rdata(rdata, rr_types, next_hashed, ttl,key, wildcard);

	return knot_rrset_add_rdata(rrset, rdata, rdata_size, ttl, NULL);
}

/*!
 * \brief Create NSEC5 node.
 */
static zone_node_t *create_nsec5_node(knot_dname_t *owner,
                                      zone_node_t *apex_node,
                                      const bitmap_t *rr_types,
                                      uint32_t ttl, const knot_zone_key_t *key,
                                      bool wildcard_flag)
{
	assert(owner);
	assert(apex_node);
	assert(rr_types);
    assert(key);

	zone_node_t *new_node = node_new(owner, NULL);
	if (!new_node) {
		return NULL;
	}

	node_set_parent(new_node, apex_node);

	knot_rrset_t nsec5_rrset;
	int ret = create_nsec5_rrset(&nsec5_rrset, owner,
	                             rr_types, NULL, ttl,key, wildcard_flag);
	if (ret != KNOT_EOK) {
		node_free(&new_node, NULL);
		return NULL;
	}

	ret = node_add_rrset(new_node, &nsec5_rrset, NULL);
	knot_rrset_clear(&nsec5_rrset, NULL);
	if (ret != KNOT_EOK) {
		node_free(&new_node, NULL);
		return NULL;
	}

	return new_node;
}

/*!
 * \brief Create new NSEC5 node for given regular node.
 *
 * \param node       Node for which the NSEC3 node is created.
 * \param apex       Zone apex node.
 * \param params     NSEC3 hash function parameters.
 * \param ttl        TTL of the new NSEC3 node.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static zone_node_t *create_nsec5_node_for_node(zone_node_t *node,
                                               zone_node_t *apex,
                                               uint32_t ttl,
                                               const knot_zone_key_t *key)
{
	assert(node);
	assert(apex);
    assert(key);

	knot_dname_t *nsec5_owner;
    bool wildcard_flag = false;
	nsec5_owner = knot_create_nsec5_owner(node->owner, apex->owner, key);
	if (!nsec5_owner) {
		return NULL;
	}
//printf("nsec5_owner: %s\n", (knot_dname_to_str_alloc(nsec5_owner)));
    
	bitmap_t rr_types = { 0 };
	bitmap_add_node_rrsets(&rr_types, node);
	if (node->rrset_count > 0 && node_should_be_signed_nsec5(node)) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_RRSIG);
	}
	if (node == apex) {
		bitmap_add_type(&rr_types, KNOT_RRTYPE_DNSKEY);
        bitmap_add_type(&rr_types, KNOT_RRTYPE_NSEC5KEY); //not sure!
	}
    if (node->flags & NODE_FLAGS_WILDCARD_CHILD) {
        //printf("PREPEI NA SETARW TO NSEC5 WILDCARD FLAG TOU %s \n", knot_dname_to_str_alloc(node->owner));
        wildcard_flag = true;
    }
	zone_node_t *nsec5_node;
    nsec5_node = create_nsec5_node(nsec5_owner, apex, &rr_types, ttl,key, wildcard_flag);

	return nsec5_node;
}

/* - NSEC5 chain creation --------------------------------------------------- */

/*!
 * \brief Connect two nodes by filling 'hash' field of NSEC5 RDATA of the node.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Unused parameter.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec5_nodes(zone_node_t *a, zone_node_t *b,
                               nsec_chain_iterate_data_t *data)
{
	assert(a);
	assert(b);
	UNUSED(data);

	assert(a->rrset_count == 1);

	knot_rdataset_t *a_rrs = node_rdataset(a, KNOT_RRTYPE_NSEC5);
	assert(a_rrs);
	//uint8_t algorithm = knot_nsec3_algorithm(a_rrs, 0);
	//if (algorithm == 0) {
	//	return KNOT_EINVAL;
	//} NO ALGORITHM field at NSEC5 record

	uint8_t *raw_hash = NULL;
    uint8_t raw_length = knot_nsec5_hash_length(1);
	knot_nsec5_next_hashed(a_rrs, 0, &raw_hash);
	if (raw_hash == NULL) {
		return KNOT_EINVAL;
	}
    //printf( "raw_length: %u knot_nsec5_hash_length(1): %zu\n", raw_length, knot_nsec5_hash_length(1));
	//assert(raw_length == knot_nsec5_hash_length(1)); //no algorithm to compare unless I pass the key too

    //printf("b->owner: %s\n", (knot_dname_to_str_alloc(b->owner)));
	uint8_t *b32_hash = (uint8_t *)knot_dname_to_str_alloc(b->owner);
	size_t b32_length = knot_nsec5_hash_b32_length(1); ///
	if (!b32_hash) {
		return KNOT_ENOMEM;
	}

	int32_t written = base32hex_decode_no_padding(b32_hash, b32_length,
	                                   raw_hash, raw_length); //

    //printf("b32_length: %zu raw_length: %u written: %d\n", b32_length, raw_length , written);
   // printf("raw_hash= %s\n", raw_hash);

	free(b32_hash);

	if (written != raw_length) {
        printf("SIZE TROUBLE written and raw_length\n");
		return KNOT_EINVAL;
	}
/*
    for (uint16_t i = 0; i < a->rrset_count; i++) {
        knot_rrset_t rrset = node_rrset_at(a, i);
    char dst[1000];
    if (knot_rrset_txt_dump(&rrset, dst, 1000,
                        &KNOT_DUMP_STYLE_DEFAULT) < 0) {
            return KNOT_ENOMEM;
    }
    else printf("A RECORD = %s\n",dst);
    }
 */
    
	return KNOT_EOK;
}
/* DROPPED THIS. ONLY HERE FOR POSSIBLE FUTURE CHANGE
static int set_nsec5_wildcard_flags(zone_node_t *a, zone_node_t *b,
                               nsec_chain_iterate_data_t *data)
{
    assert(a);
    assert(b);
    UNUSED(b);
    UNUSED(data);
    
    assert(a->rrset_count == 1);
    
    knot_rdataset_t *a_rrs = node_rdataset(a, KNOT_RRTYPE_NSEC5);
    assert(a_rrs);
    
    if ((a->parent) && (a->parent->flags & NODE_FLAGS_WILDCARD_CHILD)) {
        //printf("PREPEI NA SETARW TO NSEC5 WILDCARD FLAG TOU %s gia to %s\n", knot_dname_to_str_alloc(a->parent->owner), knot_dname_to_str_alloc(a->owner));
        //node->parent->nsec3_node->flags
        assert(a->parent->nsec3_node);
    }
    return KNOT_EOK;
}
*/


/*!
 * \brief Create NSEC5 node for each regular node in the zone.
 *
 * \param zone         Zone.
 * \param ttl          TTL for the created NSEC records.
 * \param nsec3_nodes  Tree whereto new NSEC3 nodes will be added.
 * \param chgset       Changeset used for possible NSEC removals
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec5_nodes(const zone_contents_t *zone, uint32_t ttl,
                              zone_tree_t *nsec5_nodes,
                              changeset_t *chgset, const knot_zone_key_t *key)
{
	assert(zone);
	assert(nsec5_nodes);
	assert(chgset);
    assert(key);
    
    
	//const knot_nsec3_params_t *params = &zone->nsec3_params;

	//assert(params);

	int result = KNOT_EOK;

	const bool sorted = false;
	hattrie_iter_t *it = hattrie_iter_begin(zone->nodes, sorted);
	while (!hattrie_iter_finished(it)) {
		zone_node_t *node = (zone_node_t *)*hattrie_iter_val(it);

		/*!
		 * Remove possible NSEC from the node. (Do not allow both NSEC
		 * and NSEC3 in the zone at once.)
		 */
		result = knot_nsec_changeset_remove(node, chgset);
		if (result != KNOT_EOK) {
			break;
		}
		if (node_rrtype_exists(node, KNOT_RRTYPE_NSEC)
                            || node_rrtype_exists(node, KNOT_RRTYPE_NSEC3)) {
			node->flags |= NODE_FLAGS_REMOVED_NSEC;
		}
		if (node->flags & NODE_FLAGS_NONAUTH || node->flags & NODE_FLAGS_EMPTY) {
			hattrie_iter_next(it);
			continue;
		}

		zone_node_t *nsec5_node;
		nsec5_node = create_nsec5_node_for_node(node, zone->apex,
		                                         ttl, key);
		if (!nsec5_node) {
			result = KNOT_ENOMEM;
			break;
		}
        
        //printf("----------weight pro insertion: %zu------\n",hattrie_weight(nsec5_nodes));
		result = zone_tree_insert(nsec5_nodes, nsec5_node);
		if (result != KNOT_EOK) {
			break;
		}
        //printf("----------weight after insertion: %zu-------\n",hattrie_weight(nsec5_nodes));

		hattrie_iter_next(it);
	}

	hattrie_iter_free(it);

	/* Rebuild index over nsec5 nodes. */
	hattrie_build_index(nsec5_nodes);
    //printf("EKANA BUILD TO INDEX\n");
	return result;
}

/*!
 * \brief Checks if NSEC5 should be generated for this node.
 *
 * \retval true if the node has no children and contains no RRSets or only
 *         RRSIGs and NSECs.
 * \retval false otherwise.
 */
static bool nsec5_is_empty(zone_node_t *node)
{
	if (node->children > 0) {
		return false;
	}

	return knot_nsec_empty_nsec_and_rrsigs_in_node(node); //need to generalize check for nsec3 too?
}

/*!
 * \brief Marks node and its parents as empty if NSEC5 should not be generated
 *        for them.
 *
 * It also lowers the children count for the parent of marked node. This must be
 * fixed before further operations on the zone.
 */
static int nsec5_mark_empty(zone_node_t **node_p, void *data)
{
	UNUSED(data);
	zone_node_t *node = *node_p;

	if (!(node->flags & NODE_FLAGS_EMPTY) && nsec5_is_empty(node)) {
		/*!
		 * Mark this node and all parent nodes that meet the same
		 * criteria as empty.
		 */
		node->flags |= NODE_FLAGS_EMPTY;

		if (node->parent) {
			/* We must decrease the parent's children count,
			 * but only temporarily! It must be set back right after
			 * the operation
			 */
			node->parent->children--;
			/* Recurse using the parent node */
			return nsec5_mark_empty(&node->parent, data);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Function for temporary marking nodes as empty if NSEC5s should not be
 *        generated for them.
 *
 * This is only temporary for the time of NSEC5 generation. Afterwards it must
 * be reset (removed flag and fixed children counts).
 */
static void mark_empty_nodes_tmp(const zone_contents_t *zone)
{
	assert(zone);

	int ret = zone_tree_apply(zone->nodes, nsec5_mark_empty, NULL);

	assert(ret == KNOT_EOK);
}

/*!
 * \brief Resets the empty flag in the node and increases its parent's children
 *        count if the node was marked as empty.
 *
 * The children count of node's parent is increased if this node was marked as
 * empty, as it was previously decreased in the \a nsec3_mark_empty() function.
 */
static int nsec5_reset(zone_node_t **node_p, void *data)
{
	UNUSED(data);
	zone_node_t *node = *node_p;

	if (node->flags & NODE_FLAGS_EMPTY) {
		/* If node was marked as empty, increase its parent's children
		 * count.
		 */
		node->parent->children++;
		/* Clear the 'empty' flag. */
		node->flags &= ~NODE_FLAGS_EMPTY;
	}

	return KNOT_EOK;
}

/*!
 * \brief Resets empty node flag and children count in nodes that were
 *        previously marked as empty by the \a mark_empty_nodes_tmp() function.
 *
 * This function must be called after NSEC5 generation, so that flags and
 * children count are back to normal before further processing.
 */
static void reset_nodes(const zone_contents_t *zone)
{
	assert(zone);

	int ret = zone_tree_apply(zone->nodes, nsec5_reset, NULL);

	assert(ret == KNOT_EOK);
}

/* - Public API ------------------------------------------------------------- */

/*!
 * \brief Create new NSEC5 chain, add differences from current into a changeset.
 */
int knot_nsec5_create_chain(const zone_contents_t *zone, uint32_t ttl,
                            changeset_t *changeset, const knot_zone_key_t *key)
{
	assert(zone);
	assert(changeset);
    assert(key);

	int result;

	zone_tree_t *nsec5_nodes = zone_tree_create();
	if (!nsec5_nodes) {
		return KNOT_ENOMEM;
	}

	/* Before creating NSEC5 nodes, we must temporarily mark those nodes
	 * that may still be in the zone, but for which the NSEC5s should not
	 * be created. I.e. nodes with only RRSIG (or NSEC+RRSIG) and their
	 * predecessors if they are empty.
	 *
	 * The flag will be removed when the node is encountered during NSEC3
	 * creation procedure.
	 */

	mark_empty_nodes_tmp(zone);

	result = create_nsec5_nodes(zone, ttl, nsec5_nodes, changeset,key);
	if (result != KNOT_EOK) {
		free_nsec5_tree(nsec5_nodes);
		return result;
	}

	reset_nodes(zone);

	result = knot_nsec_chain_iterate_create(nsec5_nodes,
	                                        connect_nsec5_nodes, NULL);
	if (result != KNOT_EOK) {
        printf("anagkastika na kanw free???\n");
		free_nsec5_tree(nsec5_nodes);
		return result;
	}
    
    /*result = knot_nsec_chain_iterate_create(nsec5_nodes,
                                            set_nsec5_wildcard_flags, NULL);
    if (result != KNOT_EOK) {
        printf("error setting the flags!!!!!\n");
        free_nsec5_tree(nsec5_nodes);
        return result;
    }
    */
	copy_signatures(zone->nsec3_nodes, nsec5_nodes); //use nsec3_tree to store nsec5nodes. If error change this
    //printf("ekana copy signatures\n");
    
    //printf("PRIN TO TREE ADD DIFF, TO WEIGHT TOU NSEC5 NODES: %d\n", zone_tree_weight(nsec5_nodes));
    //printf("PRIN TO TREE ADD DIFF, TO WEIGHT TOU zone->nsec3_nodes NODES: %d\n", zone_tree_weight(zone->nsec3_nodes));

	result = zone_tree_add_diff(zone->nsec3_nodes, nsec5_nodes,
	                                 changeset);
    //printf("ekana tree add diff \n");

	free_nsec5_tree(nsec5_nodes);
    //printf("ekana free normal sto telos\n");
	return result;
}
