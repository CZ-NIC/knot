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
#include <sys/types.h>
#include <time.h>
#include "common/descriptor.h"
#include "common/errcode.h"
#include "common/hattrie/hat-trie.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/rrset-sign.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/dnssec/zone-sign.h"
#include "libknot/rdata.h"
#include "libknot/rrset.h"
#include "libknot/updates/changesets.h"
#include "libknot/util/debug.h"
#include "libknot/zone/node.h"
#include "libknot/zone/zone-contents.h"

/*- private API - common functions -------------------------------------------*/

/*!
 * \brief Create empty RRSIG RR set for a given RR set to be covered.
 */
static knot_rrset_t *create_empty_rrsigs_for(const knot_rrset_t *covered)
{
	assert(covered);

	knot_dname_t *owner_copy = knot_dname_copy(covered->owner);

	return knot_rrset_new(owner_copy, KNOT_RRTYPE_RRSIG, covered->rclass,
	                      covered->ttl);
}

/*- private API - signing of in-zone nodes -----------------------------------*/

/*!
 * \brief Check if there is a valid signature for a given RR set and key.
 *
 * \param covered  RR set with covered records.
 * \param rrsigs   RR set with RRSIGs.
 * \param key      Signing key.
 * \param ctx      Signing context.
 * \param policy   DNSSEC policy.
 *
 * \return The signature exists and is valid.
 */
static bool valid_signature_exists(const knot_rrset_t *covered,
				   const knot_rrset_t *rrsigs,
				   const knot_dnssec_key_t *key,
				   knot_dnssec_sign_context_t *ctx,
				   const knot_dnssec_policy_t *policy)
{
	assert(key);

	if (!rrsigs) {
		return false;
	}

	for (int i = 0; i < rrsigs->rdata_count; i++) {
		uint16_t keytag = knot_rdata_rrsig_key_tag(rrsigs, i);
		if (keytag != key->keytag) {
			continue;
		}

		return knot_is_valid_signature(covered, rrsigs, i, key, ctx,
		                               policy) == KNOT_EOK;
	}

	return false;
}

/*!
 * \brief Check if key can be used to sign given RR.
 *
 * \param key      Zone key.
 * \param covered  RR to be checked.
 *
 * \return The RR should be signed.
 */
static bool use_key(const knot_zone_key_t *key, const knot_rrset_t *covered)
{
	assert(key);
	assert(covered);

	if (!key->is_active) {
		return false;
	}

	if (key->is_ksk) {
		if (covered->type != KNOT_RRTYPE_DNSKEY) {
			return false;
		}

		// use KSK only in the zone apex
		if (!knot_dname_is_equal(key->dnssec_key.name, covered->owner)) {
			return false;
		}
	}

	return true;
}

/*!
 * \brief Check if valid signature exist for all keys for a given RR set.
 *
 * \param covered    RR set with covered records.
 * \param rrsigs     RR set with RRSIGs.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 *
 * \return Valid signature exists for every key.
 */
static bool all_signatures_exist(const knot_rrset_t *covered,
                                 const knot_rrset_t *rrsigs,
                                 const knot_zone_keys_t *zone_keys,
                                 const knot_dnssec_policy_t *policy)
{
	assert(covered);
	assert(zone_keys);

	node_t *node = NULL;
	WALK_LIST(node, zone_keys->list) {
		const knot_zone_key_t *key = (knot_zone_key_t *)node;
		if (!use_key(key, covered)) {
			continue;
		}

		if (!valid_signature_exists(covered, rrsigs, &key->dnssec_key,
		                            key->context, policy)) {
			return false;
		}
	}

	return true;
}

/*!
 * \brief Get zone key for given RRSIG (checks key tag only).
 *
 * \param rrsigs  RR set with RRSIGs.
 * \param pos     Number of RR in RR set.
 * \param keys    Zone keys.
 *
 * \return Zone key or NULL if a that key does not exist.
 */
static const knot_zone_key_t *get_matching_zone_key(const knot_rrset_t *rrsigs,
                                      size_t pos, const knot_zone_keys_t *keys)
{
	assert(rrsigs && rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(keys);

	uint16_t keytag = knot_rdata_rrsig_key_tag(rrsigs, pos);

	return knot_get_zone_key(keys, keytag);
}

/*!
 * \brief Note earliest expiration of a signature.
 *
 * \param rrsigs      RR set with RRSIGs.
 * \param pos         Position of RR in rrsigs.
 * \param expires_at  Current earliest expiration, will be updated.
 */
static void note_earliest_expiration(const knot_rrset_t *rrsigs, size_t pos,
                                     uint32_t *expires_at)
{
	assert(rrsigs);
	assert(expires_at);

	const uint32_t current = knot_rdata_rrsig_sig_expiration(rrsigs, pos);
	if (current < *expires_at) {
		*expires_at = current;
	}
}

/*!
 * \brief Add expired or invalid RRSIGs into the changeset for removal.
 *
 * \param covered     RR set with covered records.
 * \param rrsigs      RR set with RRSIGs.
 * \param zone_keys   Zone keys.
 * \param policy      DNSSEC policy.
 * \param changeset   Changeset to be updated.
 * \param expires_at  Earliest RRSIG expiration.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int remove_expired_rrsigs(const knot_rrset_t *covered,
                                 const knot_rrset_t *rrsigs,
                                 const knot_zone_keys_t *zone_keys,
                                 const knot_dnssec_policy_t *policy,
                                 knot_changeset_t *changeset,
                                 uint32_t *expires_at)
{
	assert(changeset);

	if (!rrsigs) {
		return KNOT_EOK;
	}

	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);

	knot_rrset_t *to_remove = NULL;
	int result = KNOT_EOK;

	for (int i = 0; i < rrsigs->rdata_count; i++) {
		const knot_zone_key_t *key;
		key = get_matching_zone_key(rrsigs, i, zone_keys);

		if (key && key->is_active && key->context) {
			result = knot_is_valid_signature(covered, rrsigs, i,
			                                 &key->dnssec_key,
			                                 key->context, policy);
			if (result == KNOT_EOK) {
				// valid signature
				note_earliest_expiration(rrsigs, i, expires_at);
				continue;
			}

			if (result != KNOT_DNSSEC_EINVALID_SIGNATURE) {
				break;
			}
		}

		if (to_remove == NULL) {
			to_remove = create_empty_rrsigs_for(rrsigs);
			if (to_remove == NULL) {
				result = KNOT_ENOMEM;
				break;
			}
		}

		result = knot_rrset_add_rr_from_rrset(to_remove, rrsigs, i);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (to_remove != NULL && result == KNOT_EOK) {
		result = knot_changeset_add_rrset(changeset, to_remove,
		                                  KNOT_CHANGESET_REMOVE);
	}

	if (to_remove != NULL && result != KNOT_EOK) {
		int free_owners = true;
		knot_rrset_deep_free(&to_remove, free_owners);
	}

	return result;
}

/*!
 * \brief Add missing RRSIGs into the changeset for adding.
 *
 * \param covered    RR set with covered records.
 * \param rrsigs     RR set with RRSIGs.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int add_missing_rrsigs(const knot_rrset_t *covered,
                              const knot_rrset_t *rrsigs,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              knot_changeset_t *changeset)
{
	assert(covered);
	assert(zone_keys);
	assert(changeset);
	if (covered->rdata_count == 0) {
		return KNOT_EOK;
	}

	int result = KNOT_EOK;
	knot_rrset_t *to_add = NULL;

	node_t *node = NULL;
	WALK_LIST(node, zone_keys->list) {
		const knot_zone_key_t *key = (knot_zone_key_t *)node;
		if (!use_key(key, covered)) {
			continue;
		}

		if (valid_signature_exists(covered, rrsigs, &key->dnssec_key,
		                           key->context, policy)) {
			continue;
		}

		if (to_add == NULL) {
			to_add = create_empty_rrsigs_for(covered);
			if (to_add == NULL) {
				return KNOT_ENOMEM;
			}
		}

		result = knot_sign_rrset(to_add, covered, &key->dnssec_key,
		                         key->context, policy);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (to_add != NULL && result == KNOT_EOK) {
		result = knot_changeset_add_rrset(changeset, to_add,
		                                  KNOT_CHANGESET_ADD);
	}

	if (to_add != NULL && result != KNOT_EOK) {
		int free_owners = true;
		knot_rrset_deep_free(&to_add, free_owners);
	}

	return result;
}

/*!
 * \brief Add all RRSIGs into the changeset for removal.
 *
 * \param covered    RR set with covered records.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int remove_rrset_rrsigs(const knot_rrset_t *rrset,
                               knot_changeset_t *changeset)
{
	assert(rrset);
	assert(changeset);

	if (!rrset->rrsigs) {
		return KNOT_EOK;
	}

	knot_rrset_t *to_remove = NULL;
	int result = knot_rrset_deep_copy(rrset->rrsigs, &to_remove);
	if (result != KNOT_EOK) {
		return result;
	}

	return knot_changeset_add_rrset(changeset, to_remove,
	                                KNOT_CHANGESET_REMOVE);
}

/*!
 * \brief Drop all existing and create new RRSIGs for covered records.
 *
 * \param covered    RR set with covered records.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int force_resign_rrset(const knot_rrset_t *covered,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              knot_changeset_t *changeset)
{
	assert(covered);

	if (covered->rrsigs) {
		int result = remove_rrset_rrsigs(covered, changeset);
		if (result != KNOT_EOK) {
			return result;
		}
	}

	return add_missing_rrsigs(covered, NULL, zone_keys, policy, changeset);
}

/*!
 * \brief Drop all expired and create new RRSIGs for covered records.
 *
 * \param covered     RR set with covered records.
 * \param zone_keys   Zone keys.
 * \param policy      DNSSEC policy.
 * \param changeset   Changeset to be updated.
 * \param expires_at  Current earliest expiration, will be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int resign_rrset(const knot_rrset_t *covered,
                        const knot_zone_keys_t *zone_keys,
                        const knot_dnssec_policy_t *policy,
                        knot_changeset_t *changeset,
                        uint32_t *expires_at)
{
	assert(covered);

	// TODO this function creates some signatures twice (for checking)
	// maybe merge the two functions into one
	// jvcelak: Not really, maybe for RSA. The digest is computed twice,
	// but the verification process can differ from signature computation.
	// TODO reuse digest for RSA then, RSA is the most used algo family,
	// and we create all the signatures twice, that is not cool I think.
	int result = remove_expired_rrsigs(covered, covered->rrsigs, zone_keys,
	                                   policy, changeset, expires_at);
	if (result != KNOT_EOK) {
		return result;
	}

	return add_missing_rrsigs(covered, covered->rrsigs, zone_keys, policy,
	                          changeset);
}

/*!
 * \brief Update RRSIGs in a given node by updating changeset.
 *
 * \param node        Node to be signed.
 * \param zone_keys   Zone keys.
 * \param policy      DNSSEC policy.
 * \param changeset   Changeset to be updated.
 * \param expires_at  Current earliest expiration, will be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_node_rrsets(const knot_node_t *node,
                            const knot_zone_keys_t *zone_keys,
                            const knot_dnssec_policy_t *policy,
                            knot_changeset_t *changeset,
                            uint32_t *expires_at)
{
	assert(node);
	assert(policy);

	int result = KNOT_EOK;

	for (int i = 0; i < node->rrset_count; i++) {
		const knot_rrset_t *rrset = node->rrset_tree[i];
		if (!knot_zone_sign_rr_should_be_signed(node, rrset, NULL)) {
			continue;
		}

		// Remove standalone RRSIGs (without the RRSet they sign)
		if (rrset->rdata_count == 0 && rrset->rrsigs) {
			assert(rrset->rrsigs->rdata_count > 0);
			result = remove_rrset_rrsigs(rrset, changeset);
			if (result != KNOT_EOK) {
				break;
			}
		}

		if (policy->forced_sign) {
			result = force_resign_rrset(rrset, zone_keys, policy,
			         changeset);
		} else {
			result = resign_rrset(rrset, zone_keys, policy,
			                      changeset, expires_at);
		}

		if (result != KNOT_EOK) {
			break;
		}
	}

	return result;
}

/*!
 * \brief Struct to carry data for 'sign_data' callback function.
 */
typedef struct node_sign_args {
	const knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	knot_changeset_t *changeset;
	uint32_t expires_at;
} node_sign_args_t;

/*!
 * \brief Sign node (callback function).
 *
 * \param node  Node to be signed.
 * \param data  Callback data, node_sign_args_t.
 */
static int sign_node(knot_node_t **node, void *data)
{
	assert(node && *node);
	assert(data);

	node_sign_args_t *args = (node_sign_args_t *)data;

	if ((*node)->rrset_count == 0) {
		return KNOT_EOK;
	}

	if (knot_node_is_non_auth(*node)) {
		return KNOT_EOK;
	}

	int result = sign_node_rrsets(*node, args->zone_keys, args->policy,
	                              args->changeset, &args->expires_at);
	knot_node_clear_replaced_nsec(*node);

	return result;
}

/*!
 * \brief Update RRSIGs in a given zone tree by updating changeset.
 *
 * \param tree        Zone tree to be signed.
 * \param zone_keys   Zone keys.
 * \param policy      DNSSEC policy.
 * \param changeset   Changeset to be updated.
 * \param expires_at  Expiration time of the oldest signature in zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int zone_tree_sign(knot_zone_tree_t *tree,
                          const knot_zone_keys_t *zone_keys,
                          const knot_dnssec_policy_t *policy,
                          knot_changeset_t *changeset,
                          uint32_t *expires_at)
{
	assert(tree);
	assert(zone_keys);
	assert(policy);
	assert(changeset);

	node_sign_args_t args = {
		.zone_keys = zone_keys,
		.policy = policy,
		.changeset = changeset,
		.expires_at = time(NULL) + policy->sign_lifetime
	};

	int result = knot_zone_tree_apply(tree, sign_node, &args);
	*expires_at = args.expires_at;

	return result;
}

/*- private API - signing of NSEC(3) in changeset ----------------------------*/

/*!
 * \brief Struct to carry data for 'add_rrsigs_for_nsec' callback function.
 */
typedef struct {
	const knot_zone_contents_t *zone;
	const knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	knot_changeset_t *changeset;
	hattrie_t *signed_table;
} changeset_signing_data_t;

/*!
 * \brief Sign NSEC nodes in changeset (callback function).
 *
 * \param node  Node to be signed, silently skipped if not NSEC/NSEC3.
 * \param data  Callback data, changeset_signing_data_t.
 */
static int add_rrsigs_for_nsec(knot_rrset_t *rrset, void *data)
{
	if (rrset == NULL) {
		return KNOT_EINVAL;
	}

	assert(data);

	int result = KNOT_EOK;
	changeset_signing_data_t *nsec_data = (changeset_signing_data_t *)data;

	if (rrset->type == KNOT_RRTYPE_NSEC ||
	    rrset->type == KNOT_RRTYPE_NSEC3
	) {
		result = add_missing_rrsigs(rrset, NULL, nsec_data->zone_keys,
		                            nsec_data->policy,
		                            nsec_data->changeset);
	}

	if (result != KNOT_EOK) {
		dbg_dnssec_detail("add_rrsigs_for_nsec() for NSEC failed\n");
	}

	return result;
}

/*- private API - DNSKEY handling --------------------------------------------*/

/*!
 * \brief Check if DNSKEY RDATA match with DNSSEC key.
 *
 * \param zone_key    Zone key.
 * \param rdata       DNSKEY RDATA.
 * \param rdata_size  DNSKEY RDATA size.
 *
 * \return DNSKEY RDATA match with DNSSEC key.
 */
static bool dnskey_rdata_match(const knot_zone_key_t *key,
                               const uint8_t *rdata, size_t rdata_size)
{
	assert(key);
	assert(rdata);

	const knot_dnssec_key_t *dnssec_key = &key->dnssec_key;

	return dnssec_key->dnskey_rdata.size == rdata_size &&
	       memcmp(dnssec_key->dnskey_rdata.data, rdata, rdata_size) == 0;
}

/*!
 * \brief Check if DNSKEY (key struct given) exists in zone.
 *
 * \param dnskeys  DNSKEYS RR set in zone apex.
 * \param key      Key to be searched for.
 *
 * \return DNSKEY exists in the zone.
 */
static bool dnskey_exists_in_zone(const knot_rrset_t *dnskeys,
                                  const knot_zone_key_t *key)
{
	assert(dnskeys);
	assert(key);

	for (int i = 0; i < dnskeys->rdata_count; i++) {
		uint8_t *rdata = knot_rrset_get_rdata(dnskeys, i);
		size_t rdata_size = rrset_rdata_item_size(dnskeys, i);

		if (dnskey_rdata_match(key, rdata, rdata_size)) {
			return true;
		}
	}

	return false;
}

static int rrset_add_zone_key(knot_rrset_t *rrset,
                                   const knot_zone_key_t *zone_key)
{
	assert(rrset);
	assert(zone_key);

	const knot_binary_t *key_rdata = &zone_key->dnssec_key.dnskey_rdata;

	return knot_rrset_add_rdata(rrset, key_rdata->data, key_rdata->size);
}

/*!
 * \brief Remove invalid DNSKEYs from the zone by updating the changeset.
 *
 * Invalid DNSKEY has wrong TTL, or the same keytag as some zone key
 * but different RDATA.
 *
 * \param soa        RR set with SOA (to get TTL value from).
 * \param dnskeys    RR set with DNSKEYs.
 * \param zone_keys  Zone keys.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int remove_invalid_dnskeys(const knot_rrset_t *soa,
                                  const knot_rrset_t *dnskeys,
                                  const knot_zone_keys_t *zone_keys,
                                  knot_changeset_t *changeset)
{
	assert(soa);
	assert(soa->type == KNOT_RRTYPE_SOA);
	assert(changeset);

	if (!dnskeys) {
		return KNOT_EOK;
	}
	assert(dnskeys->type == KNOT_RRTYPE_DNSKEY);

	knot_rrset_t *to_remove = NULL;
	int result = KNOT_EOK;

	if (dnskeys->ttl != soa->ttl) {
		dbg_dnssec_detail("removing DNSKEYs (SOA TTL differs)\n");
		result = knot_rrset_deep_copy_no_sig(dnskeys, &to_remove);
		goto done;
	}

	for (int i = 0; i < dnskeys->rdata_count; i++) {
		uint8_t *rdata = knot_rrset_get_rdata(dnskeys, i);
		size_t rdata_size = rrset_rdata_item_size(dnskeys, i);
		uint16_t keytag = knot_keytag(rdata, rdata_size);
		const knot_zone_key_t *key = knot_get_zone_key(zone_keys, keytag);
		if (key == NULL) {
			dbg_dnssec_detail("keeping unknown DNSKEY with tag "
			                  "%d\n", keytag);
			continue;
		}

		if (dnskey_rdata_match(key, rdata, rdata_size) && key->is_public) {
			dbg_dnssec_detail("keeping known DNSKEY with tag "
			                  "%d\n", keytag);
			continue;
		}

		dbg_dnssec_detail("removing DNSKEY with tag %d\n", keytag);

		if (to_remove == NULL) {
			to_remove = knot_rrset_new_from(dnskeys);
			if (to_remove == NULL) {
				result = KNOT_ENOMEM;
				break;
			}
		}

		result = knot_rrset_add_rr_from_rrset(to_remove, dnskeys, i);
		if (result != KNOT_EOK) {
			break;
		}
	}

done:

	if (to_remove != NULL && result == KNOT_EOK) {
		result = knot_changeset_add_rrset(changeset, to_remove,
		                                  KNOT_CHANGESET_REMOVE);
	}

	if (to_remove != NULL && result != KNOT_EOK) {
		knot_rrset_deep_free(&to_remove, 1);
	}

	return result;
}

/*!
 * \brief Create DNSKEY RR set from SOA RR set.
 *
 * \param soa  RR set with zone SOA.
 *
 * \return Empty DNSKEY RR set.
 */
static knot_rrset_t *create_dnskey_rrset_from_soa(const knot_rrset_t *soa)
{
	assert(soa);

	knot_dname_t *owner = knot_dname_copy(soa->owner);
	if (!owner) {
		return NULL;
	}

	return knot_rrset_new(owner, KNOT_RRTYPE_DNSKEY, soa->rclass, soa->ttl);
}

/*!
 * \brief Add missing DNSKEYs into the zone by updating the changeset.
 *
 * \param soa        RR set with SOA (to get TTL value from).
 * \param dnskeys    RR set with DNSKEYs.
 * \param zone_keys  Zone keys.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int add_missing_dnskeys(const knot_rrset_t *soa,
                               const knot_rrset_t *dnskeys,
                               const knot_zone_keys_t *zone_keys,
                               knot_changeset_t *changeset)
{
	assert(soa);
	assert(soa->type == KNOT_RRTYPE_SOA);
	assert(!dnskeys || dnskeys->type == KNOT_RRTYPE_DNSKEY);
	assert(zone_keys);
	assert(changeset);

	knot_rrset_t *to_add = NULL;
	int result = KNOT_EOK;
	bool add_all = dnskeys == NULL || dnskeys->ttl != soa->ttl;

	node_t *node = NULL;
	WALK_LIST(node, zone_keys->list) {
		const knot_zone_key_t *key = (knot_zone_key_t *)node;
		if (!add_all && dnskey_exists_in_zone(dnskeys, key)) {
			continue;
		}

		if (!key->is_public) {
			continue;
		}

		dbg_dnssec_detail("adding DNSKEY with tag %d\n",
		                  key->dnssec_key.keytag);

		if (to_add == NULL) {
			to_add = create_dnskey_rrset_from_soa(soa);
			if (to_add == NULL) {
				return KNOT_ENOMEM;
			}
		}

		result = rrset_add_zone_key(to_add, key);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (to_add != NULL && result == KNOT_EOK) {
		//! \todo Sorting should be handled by changesets application.
		result = knot_rrset_sort_rdata(to_add);
		if (result != KNOT_EOK) {
			knot_rrset_deep_free(&to_add, 1);
			return result;
		}
		result = knot_changeset_add_rrset(changeset, to_add,
		                                  KNOT_CHANGESET_ADD);
	}

	if (to_add != NULL && result != KNOT_EOK) {
		knot_rrset_deep_free(&to_add, 1);
	}

	return result;
}

/*!
 * \brief Refresh DNSKEY RRSIGs in the zone by updating the changeset.
 *
 * \param dnskeys    RR set with DNSKEYs.
 * \param soa        RR set with SOA.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int update_dnskeys_rrsigs(const knot_rrset_t *dnskeys,
                                 const knot_rrset_t *soa,
                                 const knot_zone_keys_t *zone_keys,
                                 const knot_dnssec_policy_t *policy,
                                 knot_changeset_t *changeset)
{
	assert(zone_keys);
	assert(changeset);

	int result;

	// We know how the DNSKEYs in zone should look like after applying
	// the changeset. RRSIGs can be then built easily.

	knot_rrset_t *new_dnskeys = create_dnskey_rrset_from_soa(soa);
	if (!new_dnskeys) {
		return KNOT_ENOMEM;
	}

	// add unknown keys from zone
	for (int i = 0; dnskeys && i < dnskeys->rdata_count; i++) {
		uint8_t *rdata = knot_rrset_get_rdata(dnskeys, i);
		size_t rdata_size = rrset_rdata_item_size(dnskeys, i);
		uint16_t keytag = knot_keytag(rdata, rdata_size);
		if (knot_get_zone_key(zone_keys, keytag) != NULL) {
			continue;
		}

		result = knot_rrset_add_rr_from_rrset(new_dnskeys, dnskeys, i);
		if (result != KNOT_EOK) {
			goto fail;
		}
	}

	// add known keys from key database
	node_t *node = NULL;
	WALK_LIST(node, zone_keys->list) {
		const knot_zone_key_t *key = (knot_zone_key_t *)node;
		if (!key->is_public) {
			continue;
		}

		result = rrset_add_zone_key(new_dnskeys, key);
		if (result != KNOT_EOK) {
			goto fail;
		}
	}

	result = knot_rrset_sort_rdata(new_dnskeys);
	if (result != KNOT_EOK) {
		goto fail;
	}

	result = add_missing_rrsigs(new_dnskeys, NULL, zone_keys, policy,
	                            changeset);
	if (result != KNOT_EOK) {
		goto fail;
	}

	if (dnskeys) {
		result = remove_rrset_rrsigs(dnskeys, changeset);
	}

fail:

	knot_rrset_deep_free(&new_dnskeys, 1);

	return result;
}

/*!
 * \brief Update DNSKEY records in the zone by updating the changeset.
 *
 * \param zone       Zone to be updated.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int update_dnskeys(const knot_zone_contents_t *zone,
                          const knot_zone_keys_t *zone_keys,
                          const knot_dnssec_policy_t *policy,
                          knot_changeset_t *changeset)
{
	assert(zone);
	assert(zone->apex);
	assert(changeset);

	const knot_node_t *apex = zone->apex;
	const knot_rrset_t *dnskeys = knot_node_rrset(apex, KNOT_RRTYPE_DNSKEY);
	const knot_rrset_t *soa = knot_node_rrset(apex, KNOT_RRTYPE_SOA);

	if (!soa) {
		return KNOT_EINVAL;
	}

	int result;
	size_t changes_before = knot_changeset_size(changeset);

	result = remove_invalid_dnskeys(soa, dnskeys, zone_keys, changeset);
	if (result != KNOT_EOK) {
		return result;
	}

	result = add_missing_dnskeys(soa, dnskeys, zone_keys, changeset);
	if (result != KNOT_EOK) {
		return result;
	}

	bool modified = knot_changeset_size(changeset) != changes_before;

	if (!modified && dnskeys &&
	    all_signatures_exist(dnskeys, dnskeys->rrsigs, zone_keys, policy)
	) {
		return KNOT_EOK;
	}

	dbg_dnssec_detail("Creating new signatures for DNSKEYs\n");
	return update_dnskeys_rrsigs(dnskeys, soa, zone_keys, policy, changeset);
}

/*!
 * \brief Wrapper function for changeset signing - to be used with changeset
 *        apply functions.
 *
 * \param chg_rrset  RRSet to be signed (potentially)
 * \param data       Signing data
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_changeset_wrap(knot_rrset_t *chg_rrset, void *data)
{
	changeset_signing_data_t *args = (changeset_signing_data_t *)data;
	// Find RR's node in zone, find out if we need to sign this RR
	const knot_node_t *node =
		knot_zone_contents_find_node(args->zone, chg_rrset->owner);
	// If node is not in zone, all its RRSIGs were dropped - no-op
	if (node) {
		const knot_rrset_t *zone_rrset =
			knot_node_rrset(node, chg_rrset->type);
		if (knot_zone_sign_rr_should_be_signed(node, zone_rrset,
		                                       args->signed_table)) {
			return force_resign_rrset(zone_rrset, args->zone_keys,
			                          args->policy, args->changeset);
		} else if (zone_rrset && zone_rrset->rrsigs != NULL) {
			/*!
			 * If RRSet in zone DOES have RRSIGs although we
			 * should not sign it, DDNS-caused change to node/rr
			 * occured and we have to drop all RRSIGs.
			 */
			return remove_rrset_rrsigs(zone_rrset, args->changeset);
		}
	}
	return KNOT_EOK;
}

/*!
 * \brief Checks whether RRSet is not already in the hash table, automatically
 *        stores its pointer to the table if not found, but returns false in
 *        that case.
 *
 * \param rrset  RRSet to be checked for.
 * \param table  Hash table with already signed RRs.
 *
 * \return True if RR should is signed already, false otherwise.
 */
static bool rr_already_signed(const knot_rrset_t *rrset, hattrie_t *t)
{
	assert(rrset);
	assert(t);

	// Create a key = combination of owner and type mnemonic
	int dname_size = knot_dname_size(rrset->owner);
	assert(dname_size > 0);
	char key[dname_size + 16];
	memset(key, 0, sizeof(key));
	memcpy(key, rrset->owner, dname_size);
	int ret = knot_rrtype_to_string(rrset->type, key + dname_size, 16);
	if (ret != KNOT_EOK) {
		return false;
	}
	if (hattrie_tryget(t, key, sizeof(key))) {
		return true;
	}

	// If not in the table, insert
	*hattrie_get(t, (char *)key, sizeof(key)) = (value_t *)rrset;
	return false;
}

/*- public API ---------------------------------------------------------------*/

/*!
 * \brief Update zone signatures and store performed changes in changeset.
 */
int knot_zone_sign(const knot_zone_contents_t *zone,
                   const knot_zone_keys_t *zone_keys,
                   const knot_dnssec_policy_t *policy,
                   knot_changeset_t *changeset,
                   uint32_t *refresh_at)
{
	if (!zone || !zone_keys || !policy || !changeset || !refresh_at) {
		return KNOT_EINVAL;
	}

	int result;

	result = update_dnskeys(zone, zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("update_dnskeys() failed\n");
		return result;
	}

	uint32_t normal_tree_expiration = UINT32_MAX;
	result = zone_tree_sign(zone->nodes, zone_keys, policy, changeset,
	                        &normal_tree_expiration);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("zone_tree_sign() on normal nodes failed\n");
		return result;
	}

	uint32_t nsec3_tree_expiration = UINT32_MAX;
	result = zone_tree_sign(zone->nsec3_nodes, zone_keys, policy,
	                        changeset, &nsec3_tree_expiration);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("zone_tree_sign() on nsec3 nodes failed\n");
		return result;
	}

	// renew the signatures a little earlier
	uint32_t expiration = MIN(normal_tree_expiration, nsec3_tree_expiration);

	// DNSKEY updates
	uint32_t dnskey_update = knot_get_next_zone_key_event(zone_keys);
	if (expiration < dnskey_update) {
		// Signatures expire before keys do
		*refresh_at = knot_dnssec_policy_refresh_time(policy, expiration);
	} else {
		// Keys expire before signatures
		*refresh_at = dnskey_update;
	}

	return KNOT_EOK;
}

/*!
 * \brief Check if zone SOA signatures are expired.
 */
bool knot_zone_sign_soa_expired(const knot_zone_contents_t *zone,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy)
{
	if (!zone || !zone_keys || !policy) {
		return KNOT_EINVAL;
	}

	const knot_rrset_t *soa = knot_node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	assert(soa);

	return !all_signatures_exist(soa, soa->rrsigs, zone_keys, policy);
}

/*!
 * \brief Update and sign SOA and store performed changes in changeset.
 */
int knot_zone_sign_update_soa(const knot_rrset_t *soa,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              uint32_t new_serial,
                              knot_changeset_t *changeset)
{
	if (!soa || !zone_keys || !policy || !changeset) {
		return KNOT_EINVAL;
	}

	dbg_dnssec_verb("Updating SOA...\n");

	uint32_t serial = knot_rdata_soa_serial(soa);
	if (serial == UINT32_MAX && policy->soa_up == KNOT_SOA_SERIAL_UPDATE) {
		// TODO: this is wrong, the value should be 'rewound' to 0 in this case
		return KNOT_EINVAL;
	}

	if (policy->soa_up == KNOT_SOA_SERIAL_UPDATE) {
		;
	} else {
		assert(policy->soa_up == KNOT_SOA_SERIAL_KEEP);
		new_serial = serial;
	}

	int result;

	// remove signatures for old SOA (if there are any)

	if (soa->rrsigs) {
		knot_rrset_t *soa_copy = NULL;
		result = knot_rrset_deep_copy_no_sig(soa->rrsigs, &soa_copy);
		if (result != KNOT_EOK) {
			return result;
		}
		result = knot_changeset_add_rrset(changeset, soa_copy,
		                                  KNOT_CHANGESET_REMOVE);
		if (result != KNOT_EOK) {
			knot_rrset_deep_free(&soa_copy, 1);
			return result;
		}
	}

	// copy old SOA and create new SOA with updated serial

	knot_rrset_t *soa_from = NULL;
	knot_rrset_t *soa_to = NULL;

	result = knot_rrset_deep_copy_no_sig(soa, &soa_from);
	if (result != KNOT_EOK) {
		return result;
	}

	result = knot_rrset_deep_copy_no_sig(soa, &soa_to);
	if (result != KNOT_EOK) {
		knot_rrset_deep_free(&soa_from, 1);
		return result;
	}

	knot_rdata_soa_serial_set(soa_to, new_serial);

	// add signatures for new SOA

	result = add_missing_rrsigs(soa_to, NULL, zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		knot_rrset_deep_free(&soa_from, 1);
		knot_rrset_deep_free(&soa_to, 1);
		return result;
	}

	// save the result

	changeset->soa_from = soa_from;
	changeset->soa_to = soa_to;
	changeset->serial_from = serial;
	changeset->serial_to = new_serial;

	return KNOT_EOK;
}

/*!
 * \brief Sign changeset created by DDNS or zone-diff.
 */
int knot_zone_sign_changeset(const knot_zone_contents_t *zone,
                             const knot_changeset_t *in_ch,
                             knot_changeset_t *out_ch,
                             const knot_zone_keys_t *zone_keys,
                             const knot_dnssec_policy_t *policy)
{
	if (zone == NULL || in_ch == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	// Create args for wrapper function - hattrie for duplicate sigs
	changeset_signing_data_t args = { .zone = zone, .zone_keys = zone_keys,
	                                  .policy = policy,
	                                  .changeset = out_ch,
	                                  .signed_table = hattrie_create()};

	// Sign all RRs that are new in changeset
	int ret = knot_changeset_apply((knot_changeset_t *)in_ch,
	                               KNOT_CHANGESET_ADD,
	                               sign_changeset_wrap, &args);

	// Sign all RRs that are removed in changeset
	if (ret == KNOT_EOK) {
		ret = knot_changeset_apply((knot_changeset_t *)in_ch,
		                           KNOT_CHANGESET_REMOVE,
		                           sign_changeset_wrap, &args);
	}

	hattrie_free(args.signed_table);

	return ret;
}

/*!
 * \brief Sign NSEC/NSEC3 nodes in changeset and update the changeset.
 */
int knot_zone_sign_nsecs_in_changeset(const knot_zone_keys_t *zone_keys,
                                      const knot_dnssec_policy_t *policy,
                                      knot_changeset_t *changeset)
{
	assert(zone_keys);
	assert(policy);
	assert(changeset);

	changeset_signing_data_t data = {.zone = NULL,
	                                 .zone_keys = zone_keys,
	                                 .policy = policy,
	                                 .changeset = changeset };

	return knot_changeset_apply(changeset, KNOT_CHANGESET_ADD,
	                            add_rrsigs_for_nsec, &data);
}

/*!
 * \brief Checks whether RRSet in a node has to be signed. Will not return
 *        true for all types that should be signed, do not use this as an
 *        universal function, it is implementation specific.
 */
bool knot_zone_sign_rr_should_be_signed(const knot_node_t *node,
                                        const knot_rrset_t *rrset,
                                        hattrie_t *table)
{
	if (node == NULL || rrset == NULL) {
		return false;
	}

	// We do not want to sign RRSIGs
	if (rrset->type == KNOT_RRTYPE_RRSIG) {
		return false;
	}

	// SOA and DNSKEYs are handled separately in the zone apex
	if (knot_node_is_apex(node)) {
		if (rrset->type == KNOT_RRTYPE_SOA) {
			return false;
		}

		if (rrset->type == KNOT_RRTYPE_DNSKEY) {
			return false;
		}
	}

	// At delegation points we only want to sign NSECs and DSs
	if (knot_node_is_deleg_point(node)) {
		if (!(rrset->type == KNOT_RRTYPE_NSEC ||
		    rrset->type == KNOT_RRTYPE_DS)) {
			return false;
		}
	}

	// These RRs have their signatures stored in changeset already
	if (knot_node_is_replaced_nsec(node)
	    && ((knot_rrset_type(rrset) == KNOT_RRTYPE_NSEC)
	         || (knot_rrset_type(rrset) == KNOT_RRTYPE_NSEC3))) {
		return false;
	}

	// Check for RRSet in the 'already_signed' table
	if (table) {
		if (rr_already_signed(rrset, table)) {
			return false;
		}
	}

	return true;
}
