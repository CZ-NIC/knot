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
#include "libknot/dname.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/rrset-sign.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/rdata.h"
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

	bool use_ksk = covered->type == KNOT_RRTYPE_DNSKEY;
	for (int i = 0; i < zone_keys->count; i++) {
		if (zone_keys->is_ksk[i] && !use_ksk) {
			continue;
		}

		const knot_dnssec_key_t *key = &zone_keys->keys[i];
		knot_dnssec_sign_context_t *ctx = zone_keys->contexts[i];

		if (!valid_signature_exists(covered, rrsigs, key, ctx, policy)) {
			return false;
		}
	}

	return true;
}

/*!
 * \brief Get key and signing context for given RRSIG.
 *
 * \param[in]  rrsigs  RR set with RRSIGs.
 * \param[in]  keys    Zone keys.
 * \param[out] key     Signing key, set to NULL if no matching key found.
 * \param[out] ctx     Signing context, set to NULL if no matching key found.
 */
static void get_matching_key_and_ctx(const knot_rrset_t *rrsigs, size_t pos,
				     const knot_zone_keys_t *keys,
				     const knot_dnssec_key_t **key,
				     knot_dnssec_sign_context_t **ctx)
{
	assert(rrsigs && rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(keys);
	assert(key);
	assert(ctx);

	uint16_t keytag = knot_rdata_rrsig_key_tag(rrsigs, pos);

	for (int i = 0; i < keys->count; i++) {
		const knot_dnssec_key_t *found_key = &keys->keys[i];
		if (keytag != found_key->keytag) {
			continue;
		}

		*ctx = keys->contexts[i];
		*key = &keys->keys[i];
		return;
	}

	*ctx = NULL;
	*key = NULL;
}

/*!
 * \brief Add expired or invalid RRSIGs into the changeset for removal.
 *
 * \param covered    RR set with covered records.
 * \param rrsigs     RR set with RRSIGs.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int remove_expired_rrsigs(const knot_rrset_t *covered,
				 const knot_rrset_t *rrsigs,
				 const knot_zone_keys_t *zone_keys,
				 const knot_dnssec_policy_t *policy,
				 knot_changeset_t *changeset)
{
	assert(changeset);

	if (!rrsigs) {
		return KNOT_EOK;
	}

	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);

	knot_rrset_t *to_remove = NULL;
	int result = KNOT_EOK;

	for (int i = 0; i < rrsigs->rdata_count; i++) {
		const knot_dnssec_key_t *key = NULL;
		knot_dnssec_sign_context_t *ctx = NULL;
		get_matching_key_and_ctx(rrsigs, i, zone_keys, &key, &ctx);

		if (key && ctx) {
			result = knot_is_valid_signature(covered, rrsigs, i,
			                                 key, ctx, policy);
			if (result == KNOT_EOK) {
				continue; // valid signature
			}

			if (result != KNOT_DNSSEC_EINVALID_SIGNATURE) {
				return result;
			}
		}

		if (to_remove == NULL) {
			to_remove = create_empty_rrsigs_for(rrsigs);
			if (to_remove == NULL) {
				return KNOT_ENOMEM;
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
		int free_rdata_dnames = true;
		knot_rrset_deep_free(&to_remove, free_owners, free_rdata_dnames);
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

	int result = KNOT_EOK;
	knot_rrset_t *to_add = NULL;
	bool use_ksk = covered->type == KNOT_RRTYPE_DNSKEY;

	for (int i = 0; i < zone_keys->count; i++) {
		if (zone_keys->is_ksk[i] && !use_ksk) {
			continue;
		}

		const knot_dnssec_key_t *key = &zone_keys->keys[i];
		knot_dnssec_sign_context_t *ctx = zone_keys->contexts[i];
		if (valid_signature_exists(covered, rrsigs, key, ctx, policy)) {
			continue;
		}

		if (to_add == NULL) {
			to_add = create_empty_rrsigs_for(covered);
			if (to_add == NULL) {
				return KNOT_ENOMEM;
			}
		}

		result = knot_sign_rrset(to_add, covered, key, ctx, policy);
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
		int free_rdata_dnames = true;
		knot_rrset_deep_free(&to_add, free_owners, free_rdata_dnames);
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
 * \param covered    RR set with covered records.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int resign_rrset(const knot_rrset_t *covered,
                        const knot_zone_keys_t *zone_keys,
                        const knot_dnssec_policy_t *policy,
                        knot_changeset_t *changeset)
{
	assert(covered);

	int result = remove_expired_rrsigs(covered, covered->rrsigs, zone_keys,
	                                   policy, changeset);
	if (result != KNOT_EOK) {
		return result;
	}

	return add_missing_rrsigs(covered, covered->rrsigs, zone_keys, policy,
				  changeset);
}

/*!
 * \brief Update RRSIGs in a given node by updating changeset.
 *
 * \param node       Node to be signed.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_node_rrsets(const knot_node_t *node,
                            const knot_zone_keys_t *zone_keys,
                            const knot_dnssec_policy_t *policy,
                            knot_changeset_t *changeset)
{
	assert(node);
	assert(policy);

	int result = KNOT_EOK;

	for (int i = 0; i < node->rrset_count; i++) {
		const knot_rrset_t *rrset = node->rrset_tree[i];
		// SOA entry is maintained separately
		if (rrset->type == KNOT_RRTYPE_SOA) {
			continue;
		}

		// DNSKEYs are maintained separately
		if (rrset->type == KNOT_RRTYPE_DNSKEY) {
			continue;
		}

		// We only want to sign NSEC and DS at delegation points
		if (knot_node_is_deleg_point(node) &&
		    (rrset->type != KNOT_RRTYPE_NSEC ||
		     rrset->type != KNOT_RRTYPE_DS)) {
			continue;
		}

		// These RRs have their signatures stored in changeset already
		if (knot_node_is_replaced_nsec(node) &&
		    (rrset->type == KNOT_RRTYPE_NSEC ||
		     rrset->type == KNOT_RRTYPE_NSEC3)) {
			continue;
		}

		// Remove standalone RRSIGs (without the RRSet they sign)
		if (rrset->rdata_count == 0 && rrset->rrsigs->rdata_count != 0) {
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
			                      changeset);
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
	int result;
} node_sign_args_t;

/*!
 * \brief Sign node (callback function).
 *
 * \param node  Node to be signed.
 * \param data  Callback data, node_sign_args_t.
 */
static void sign_node(knot_node_t **node, void *data)
{
	assert(node && *node);
	node_sign_args_t *args = (node_sign_args_t *)data;
	assert(data);

	if (args->result != KNOT_EOK) {
		return;
	}

	if ((*node)->rrset_count == 0) {
		return;
	}

	if (knot_node_is_non_auth(*node)) {
		return;
	}

	args->result = sign_node_rrsets(*node, args->zone_keys, args->policy,
	                                args->changeset);
	knot_node_clear_replaced_nsec(*node);
}

/*!
 * \brief Update RRSIGs in a given zone tree by updating changeset.
 *
 * \param tree       Zone tree to be signed.
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int zone_tree_sign(knot_zone_tree_t *tree,
                          const knot_zone_keys_t *zone_keys,
                          const knot_dnssec_policy_t *policy,
                          knot_changeset_t *changeset)
{
	assert(tree);
	assert(zone_keys);
	assert(policy);
	assert(changeset);

	node_sign_args_t args = {.zone_keys = zone_keys, .policy = policy,
	                         .changeset = changeset, .result = KNOT_EOK};
	knot_zone_tree_apply(tree, sign_node, &args);
	return args.result;
}

/*- private API - signing of NSEC(3) in changeset ----------------------------*/

/*!
 * \brief Struct to carry data for 'add_rrsigs_for_nsec' callback function.
 */
typedef struct {
	const knot_zone_contents_t *zone;
	knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	knot_changeset_t *changeset;
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

/*!
 * \brief Sign NSEC/NSEC3 nodes in changeset and update the changeset.
 *
 * \param zone_keys  Zone keys.
 * \param policy     DNSSEC policy.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_nsecs_in_changeset(knot_zone_keys_t *zone_keys,
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

/*- private API - DNSKEY handling --------------------------------------------*/

/*!
 * \brief Check if a DNSKEY (RDATA given) exist in zone keys database.
 *
 * \param zone_keys   Zone keys.
 * \param rdata       Pointer to DNSKEY RDATA.
 * \param rdata_size  Size of DNSKEY RDATA.
 *
 * \return DNSKEY exists in the key database.
 */
static bool dnskey_exists_in_keydb(const knot_zone_keys_t *zone_keys,
                                   const uint8_t *rdata,
                                   size_t rdata_size)
{
	assert(zone_keys);
	assert(rdata);

	for (int i = 0; i < zone_keys->count; i++) {
		const knot_dnssec_key_t *key = &zone_keys->keys[i];

		if (key->dnskey_rdata.size == rdata_size &&
		    memcmp(key->dnskey_rdata.data, rdata, rdata_size) == 0
		) {
			return true;
		}
	}

	return false;
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
                                  const knot_dnssec_key_t *key)
{
	assert(dnskeys);
	assert(key);

	for (int i = 0; i < dnskeys->rdata_count; i++) {
		uint8_t *rdata = knot_rrset_get_rdata(dnskeys, i);
		size_t rdata_size = rrset_rdata_item_size(dnskeys, i);

		if (rdata_size == key->dnskey_rdata.size &&
		    memcmp(rdata, key->dnskey_rdata.data, rdata_size) == 0
		) {
			return true;
		}
	}

	return false;
}

/*!
 * \brief Remove unknown DNSKEYs from the zone by updating the changeset.
 *
 * \param soa        RR set with SOA (to get TTL value from).
 * \param dnskeys    RR set with DNSKEYs.
 * \param zone_keys  Zone keys.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int remove_unknown_dnskeys(const knot_rrset_t *soa,
                                  const knot_rrset_t *dnskeys,
                                  knot_zone_keys_t *zone_keys,
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
		if (dnskey_exists_in_keydb(zone_keys, rdata, rdata_size)) {
			continue;
		}

		dbg_dnssec_detail("removing DNSKEY with tag %d\n",
		                  knot_keytag(rdata, rdata_size));

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
		knot_rrset_deep_free(&to_remove, 1, 1);
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
                               knot_zone_keys_t *zone_keys,
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

	for (int i = 0; i < zone_keys->count; i++) {
		knot_dnssec_key_t *key = &zone_keys->keys[i];
		if (!add_all && dnskey_exists_in_zone(dnskeys, key)) {
			continue;
		}

		dbg_dnssec_detail("adding DNSKEY with tag %d\n", key->keytag);

		if (to_add == NULL) {
			to_add = create_dnskey_rrset_from_soa(soa);
			if (to_add == NULL) {
				return KNOT_ENOMEM;
			}
		}

		result = knot_rrset_add_rdata(to_add, key->dnskey_rdata.data,
		                              key->dnskey_rdata.size);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (to_add != NULL && result == KNOT_EOK) {
		result = knot_changeset_add_rrset(changeset, to_add,
		                                  KNOT_CHANGESET_ADD);
	}

	if (to_add != NULL && result != KNOT_EOK) {
		knot_rrset_deep_free(&to_add, 1, 1);
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
                                 knot_zone_keys_t *zone_keys,
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

	for (int i = 0; i < zone_keys->count; i++) {
		knot_dnssec_key_t *key = &zone_keys->keys[i];
		knot_binary_t *rdata = &key->dnskey_rdata;
		result = knot_rrset_add_rdata(new_dnskeys, rdata->data,
		                              rdata->size);
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

	knot_rrset_deep_free(&new_dnskeys, 1, 1);

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
                          knot_zone_keys_t *zone_keys,
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

	result = remove_unknown_dnskeys(soa, dnskeys, zone_keys, changeset);
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

/*- public API ---------------------------------------------------------------*/

/*!
 * \brief Update zone signatures and store performed changes in changeset.
 */
int knot_zone_sign(const knot_zone_contents_t *zone,
                   knot_zone_keys_t *zone_keys,
                   const knot_dnssec_policy_t *policy,
                   knot_changeset_t *changeset)
{
	if (!zone || !zone_keys || !policy || !changeset) {
		return KNOT_EINVAL;
	}

	int result;

	result = update_dnskeys(zone, zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("update_dnskeys() failed\n");
		return result;
	}

	result = zone_tree_sign(zone->nodes, zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("zone_tree_sign() on normal nodes failed\n");
		return result;
	}

	result = zone_tree_sign(zone->nsec3_nodes, zone_keys, policy,
	                        changeset);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("zone_tree_sign() on nsec3 nodes failed\n");
		return result;
	}

	result = sign_nsecs_in_changeset(zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		dbg_dnssec_detail("sign_nsecs_in_changeset() failed\n");
		return result;
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
int knot_zone_sign_update_soa(const knot_zone_contents_t *zone,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              knot_changeset_t *changeset)
{
	if (!zone || !zone_keys || !policy || !changeset) {
		return KNOT_EINVAL;
	}

	knot_rrset_t *soa = knot_node_get_rrset(zone->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL || soa->rdata_count != 1) {
		return KNOT_EINVAL;
	}

	dbg_dnssec_verb("Updating SOA...\n");

	uint32_t serial = knot_rdata_soa_serial(soa);
	if (serial == UINT32_MAX && policy->soa_up == KNOT_SOA_SERIAL_INC) {
		return KNOT_EINVAL;
	}

	uint32_t new_serial = serial;
	if (policy->soa_up == KNOT_SOA_SERIAL_INC) {
		new_serial += 1;
	} else {
		assert(policy->soa_up == KNOT_SOA_SERIAL_KEEP);
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
			knot_rrset_deep_free(&soa_copy, 1, 1);
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
		knot_rrset_deep_free(&soa_from, 1, 1);
		return result;
	}

	knot_rdata_soa_serial_set(soa_to, new_serial);

	// add signatures for new SOA

	result = add_missing_rrsigs(soa_to, NULL, zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		knot_rrset_deep_free(&soa_from, 1, 1);
		knot_rrset_deep_free(&soa_to, 1, 1);
		return result;
	}

	// save the result

	changeset->soa_from = soa_from;
	changeset->soa_to = soa_to;
	changeset->serial_from = serial;
	changeset->serial_to = new_serial;

	return KNOT_EOK;
}
