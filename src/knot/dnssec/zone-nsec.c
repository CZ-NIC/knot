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
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "common/base32hex.h"
#include "common/base64.h"
#include "common/debug.h"
#include "libknot/descriptor.h"
#include "common-knot/hhash.h"
#include "libknot/dnssec/bitmap.h"
#include "libknot/dnssec/nsec5hash.h"
#include "libknot/util/utils.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/soa.h"
#include "libknot/rrtype/nsec3.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
#include "knot/dnssec/nsec5-chain.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone-diff.h"

/*!
 * \brief Deletes NSEC3 chain if NSEC should be used. (used for NSEC5 too)
 *
 * \param zone       Zone to fix.
 * \param changeset  Changeset to be used.
 * \return KNOT_E*
 */
static int delete_nsec3_chain(const zone_contents_t *zone,
                              changeset_t *changeset)
{
	assert(zone);
	assert(changeset);

	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	dbg_dnssec_detail("deleting NSEC3 chain\n");
	zone_tree_t *empty_tree = zone_tree_create();
	if (!empty_tree) {
		return KNOT_ENOMEM;
	}

	int result = zone_tree_add_diff(zone->nsec3_nodes, empty_tree,
	                                     changeset);

	zone_tree_free(&empty_tree);

	return result;
}

/* - helper functions ------------------------------------------------------ */

/*!
 * \brief Check if NSEC3 is enabled for given zone.
 */
bool knot_is_nsec3_enabled(const zone_contents_t *zone)
{
	if (!zone) {
		return false;
	}
    //printf("============================EDW TESTARW GIA NSEC3=======================\n");
    bool is = zone->nsec3_params.algorithm != 0;
    //if (is) printf("============KAI EINAI NSEC3\n");
    //else printf("============KAI DEN EINAI NSEC3\n");

    return is;
}

/*!
 * \brief Check if NSEC5 is enabled for given zone.
 */
bool knot_is_nsec5_enabled(const zone_contents_t *zone)
{
    if (!zone) {
        return false;
    }
    //printf("============================EDW TESTARW GIA NSEC5=======================\n");
    bool is = zone->nsec5_key.nsec5_key.algorithm != 0;
    //if (is) printf("============KAI EINAI NSEC5\n");
    //else printf("============KAI DEN EINAI NSEC5\n");
    return is;
}

/*!
 * \brief Get minimum TTL from zone SOA.
 * \note Value should be used for NSEC records.
 */
static bool get_zone_soa_min_ttl(const zone_contents_t *zone,
                                 uint32_t *ttl)
{
	assert(zone);
	assert(zone->apex);
	assert(ttl);

	zone_node_t *apex = zone->apex;
	const knot_rdataset_t *soa = node_rdataset(apex, KNOT_RRTYPE_SOA);
	if (!soa) {
		return false;
	}

	uint32_t result =  knot_soa_minimum(soa);
	if (result == 0) {
		return false;
	}

	*ttl = result;
	return true;
}

/*!
 * \brief Finds a node with the same owner as the given NSEC3 RRSet and marks it
 *        as 'removed'. (for NSEC5 too)
 *
 * \param data NSEC3 tree to search for the node in. (type zone_tree_t *).
 * \param rrset RRSet whose owner will be sought in the zone tree. non-NSEC3
 *              RRSets are ignored.
 *
 * This function is constructed as a callback for the knot_changeset_apply() f
 * function.
 */
static int mark_nsec3(knot_rrset_t *rrset, zone_tree_t *nsec3s)
{
	assert(rrset != NULL);
	assert(nsec3s != NULL);

	zone_node_t *node = NULL;
	int ret;

	if (rrset->type == KNOT_RRTYPE_NSEC3) {
		// Find the name in the NSEC3 tree and mark the node
		ret = zone_tree_get(nsec3s, rrset->owner,
		                         &node);
		if (ret != KNOT_EOK) {
			return ret;
		}

		if (node != NULL) {
			node->flags |= NODE_FLAGS_REMOVED_NSEC;
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Marks all NSEC3 nodes in zone from which RRSets are to be removed.
 *
 * For each NSEC3 RRSet in the changeset finds its node and marks it with the
 * 'removed' flag. (for NSEC5 too)
 */
static int mark_removed_nsec3(changeset_t *out_ch,
                              const zone_contents_t *zone)
{
	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	changeset_iter_t itt;
	changeset_iter_rem(&itt, out_ch, false);
	
	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr)) {
		int ret = mark_nsec3(&rr, zone->nsec3_nodes);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);
	
	return KNOT_EOK;
}

/* - public API ------------------------------------------------------------ */

/*!
 * \brief Create NSEC3 owner name from regular owner name.
 *
 * \param owner      Node owner name.
 * \param zone_apex  Zone apex name.
 * \param params     Params for NSEC3 hashing function.
 *
 * \return NSEC3 owner name, NULL in case of error.
 */
knot_dname_t *knot_create_nsec3_owner(const knot_dname_t *owner,
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

	knot_dname_t *result = knot_nsec3_hash_to_dname(hash, hash_size, zone_apex,false);
	free(hash);

	return result;
}

/*!
 * \brief Create NSEC5 owner name from regular owner name.
 *
 * \param owner      Node owner name.
 * \param zone_apex  Zone apex name.
 * \param key        Zone key containing NSEC5 key and context.
 *
 * \return NSEC5 owner name, NULL in case of error.
 */
knot_dname_t *knot_create_nsec5_owner(const knot_dname_t *owner,
                                      const knot_dname_t *zone_apex,
                                      const knot_zone_key_t *key)
{
    if (owner == NULL || zone_apex == NULL || key == NULL) {
        printf("FAIL STO PRWTO CHECK\n");
        return NULL;
    }
    //printf("vgika apo to prwto check\n");
    uint8_t *hash = NULL;
    size_t hash_size = 0;
    //printf("metraw size\n");
    int owner_size = knot_dname_size(owner);
    //printf("metrisa size\n");

    if (owner_size < 0) {
        //printf("GYRNAW NULL!\n");
        return NULL;
    }
    //knot_nsec5_hash_new(key->nsec5_ctx);
    //printf("paw na kanw add\n");
    knot_nsec5_hash_add(key->nsec5_ctx, owner);
    //printf("ekana add\n");

    if (knot_nsec5_hash(key->nsec5_ctx, &hash, &hash_size)
       != KNOT_EOK) {
        printf("kati pige strava sto hash computation\n");
       return NULL;
    }
    
    knot_dname_t *result = knot_nsec3_hash_to_dname(hash, hash_size, zone_apex,true); //using same function as nsec3
    free(hash);
    
    return result;
}

knot_dname_t *knot_create_nsec5_owner_full(const knot_dname_t *owner,
                                      const knot_dname_t *zone_apex,
                                      const knot_zone_key_t *key,
                                           uint8_t ** nsec5proof,
                                           size_t *nsec5proof_size)
{
    if (owner == NULL || zone_apex == NULL || key == NULL) {
        printf("FAIL STO PRWTO CHECK\n");
        return NULL;
    }
    //printf("vgika apo to prwto check\n");
    uint8_t *hash = NULL;
    size_t hash_size = 0;
    //printf("metraw size\n");
    int owner_size = knot_dname_size(owner);
    //printf("metrisa size\n");
    
    if (owner_size < 0) {
        //printf("GYRNAW NULL!\n");
        return NULL;
    }
    //knot_nsec5_hash_new(key->nsec5_ctx);
    //printf("paw na kanw add\n");
    knot_nsec5_hash_add(key->nsec5_ctx, owner);
    //printf("ekana add\n");
    
    if (knot_nsec5_hash_full(key->nsec5_ctx, &hash, &hash_size, nsec5proof,nsec5proof_size)
        != KNOT_EOK) {
        printf("kati pige strava sto hash computation\n");
        return NULL;
    }
    
    /*
    uint8_t *b32_digest = NULL;
    printf("************zone_nsec.c*************\n");
    int32_t b32_length = base64_encode_alloc(*nsec5proof, *nsec5proof_size, &b32_digest);
    printf("NSEC5PROOF:\n%.*s \n", b32_length,
           b32_digest);
    printf("*********************************\n");
    */
    knot_dname_t *result = knot_nsec3_hash_to_dname(hash, hash_size, zone_apex,true); //using same function as nsec3
    free(hash);
    
    return result;
}

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 */
knot_dname_t *knot_nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
                                       const knot_dname_t *zone_apex, bool no_padding)
{
	assert(zone_apex);

	// encode raw hash to first label

    
	uint8_t label[KNOT_DNAME_MAXLEN];
	int32_t label_size;
    if (no_padding) {
        label_size = base32hex_encode_no_padding(hash, hash_size, label, sizeof(label)); //_no_padding
    }
    else {
        label_size = base32hex_encode(hash, hash_size, label, sizeof(label));
    }
    //uint8_t *mylabel;
    //int32_t mylabel_size;
    //mylabel_size = base32hex_encode_alloc(hash, hash_size, &mylabel);

    //printf("TO KNOT_DNAME_MAX_LENGTH: %d\n", KNOT_DNAME_MAXLEN);
    //printf("TO LABEL SIZE: %d\n", label_size);
    //printf("TO MYLABEL SIZE: %d\n", label_size);
    //printf("TO HASH SIZE: %zu\n", hash_size);
    
    //free(mylabel);
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
 * \brief Create NSEC or NSEC3 or NSEC5 chain in the zone.
 */
int knot_zone_create_nsec_chain(const zone_contents_t *zone,
                                changeset_t *changeset,
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
	bool nsec3_enabled = knot_is_nsec3_enabled(zone);
    bool nsec5_enabled = knot_is_nsec5_enabled(zone); //false FOR NOW
    
	if (nsec3_enabled) {
		result = knot_nsec3_create_chain(zone, nsec_ttl, changeset);
    }
    else if (nsec5_enabled) {
        //knot_zone_key_t *nsec5_zone_key = knot_get_nsec5_key(zone_keys);
        //printf("TO KLEIDI POU DIAVASA APO TA KEYS (KAI OXI APO ZONE) einai: %d\n", nsec5_zone_key->nsec5_key.keytag);
        //printf("TO KLEIDI POU DIAVASA APO ZONE einai: %d\n", zone->nsec5_key.nsec5_key.keytag);
        //result = knot_nsec3_create_chain(zone, nsec_ttl, changeset);
        //result = knot_nsec_create_chain(zone, nsec_ttl, changeset);

        result = knot_nsec5_create_chain(zone, nsec_ttl, changeset, &zone->nsec5_key);//nsec5_zone_key);
    }
    else {
		result = knot_nsec_create_chain(zone, nsec_ttl, changeset);
	}

	if (result == KNOT_EOK && !nsec3_enabled && !nsec5_enabled) {
		result = delete_nsec3_chain(zone, changeset); //keep in mind, nsec3chain is used both for nsec3 and nsec5....
	}
    
    //printf("================== MARKING REMOVED NSEC3 ===============\n");
    
	if (result == KNOT_EOK) {
		// Mark removed NSEC3 nodes, so that they are not signed later
		result = mark_removed_nsec3(changeset, zone); //same as above; nsec5 too
	}

	if (result != KNOT_EOK) {
		return result;
	}
    //printf("================== SIGNING NSEC CHANGESET ===============\n");

	// Sign newly created records right away
	return knot_zone_sign_nsecs_in_changeset(zone_keys, policy, changeset);
    //printf("================== OUT OF ZONE NSEC -> create_nsec_chain ===============\n");

}
