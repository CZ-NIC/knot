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
#include <sys/types.h>
#include <time.h>

#include "common/debug.h"
#include "common/descriptor.h"
#include "common/errcode.h"
#include "common/hattrie/hat-trie.h"
#include "libknot/common.h"
#include "libknot/dname.h"
#include "libknot/rrset.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/rrset-sign.h"
#include "libknot/dnssec/sign.h"
#include "libknot/rrtype/rdname.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/rrtype/soa.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/updates/changesets.h"
#include "knot/zone/node.h"
#include "knot/zone/contents.h"

/*- private API - common functions -------------------------------------------*/

/*!
 * \brief Create empty RRSIG RR set for a given RR set to be covered.
 */
static knot_rrset_t *create_empty_rrsigs_for(const knot_rrset_t *covered)
{
	assert(!knot_rrset_empty(covered));

	return knot_rrset_new(covered->owner, KNOT_RRTYPE_RRSIG,
			      covered->rclass, NULL);
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

	if (knot_rrset_empty(rrsigs)) {
		return false;
	}

	uint16_t rrsigs_rdata_count = rrsigs->rrs.rr_count;
	for (uint16_t i = 0; i < rrsigs_rdata_count; i++) {
		uint16_t keytag = knot_rrsig_key_tag(&rrsigs->rrs, i);
		uint16_t type_covered = knot_rrsig_type_covered(&rrsigs->rrs, i);
		if (keytag != key->keytag || type_covered != covered->type) {
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
	assert(!knot_rrset_empty(covered));
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

	uint16_t keytag = knot_rrsig_key_tag(&rrsigs->rrs, pos);

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

	const uint32_t current = knot_rrsig_sig_expiration(&rrsigs->rrs, pos);
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
                                 changeset_t *changeset,
                                 uint32_t *expires_at)
{
	assert(changeset);

	if (knot_rrset_empty(rrsigs)) {
		return KNOT_EOK;
	}

	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);

	knot_rrset_t *to_remove = NULL;
	int result = KNOT_EOK;

	knot_rrset_t synth_rrsig;
	knot_rrset_init(&synth_rrsig, rrsigs->owner, KNOT_RRTYPE_RRSIG,
	                KNOT_CLASS_IN);
	result = knot_synth_rrsig(covered->type, &rrsigs->rrs,
	                          &synth_rrsig.rrs, NULL);
	if (result != KNOT_EOK) {
		if (result != KNOT_ENOENT) {
			return result;
		}
		return KNOT_EOK;
	}

	uint16_t rrsig_rdata_count = synth_rrsig.rrs.rr_count;
	for (uint16_t i = 0; i < rrsig_rdata_count; i++) {
		const knot_zone_key_t *key;
		key = get_matching_zone_key(&synth_rrsig, i, zone_keys);

		if (key && key->is_active && key->context) {
			result = knot_is_valid_signature(covered, &synth_rrsig, i,
			                                 &key->dnssec_key,
			                                 key->context, policy);
			if (result == KNOT_EOK) {
				// valid signature
				note_earliest_expiration(&synth_rrsig, i, expires_at);
				continue;
			}

			if (result != KNOT_DNSSEC_EINVALID_SIGNATURE) {
				break;
			}
		}

		if (to_remove == NULL) {
			to_remove = create_empty_rrsigs_for(&synth_rrsig);
			if (to_remove == NULL) {
				result = KNOT_ENOMEM;
				break;
			}
		}

		knot_rdata_t *rr_rem = knot_rdataset_at(&synth_rrsig.rrs, i);
		result = knot_rdataset_add(&to_remove->rrs, rr_rem, NULL);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (to_remove != NULL && result == KNOT_EOK) {
		result = changeset_add_rrset(changeset, to_remove,
		                             CHANGESET_REMOVE);
	}

	if (to_remove != NULL && result != KNOT_EOK) {
		knot_rrset_free(&to_remove, NULL);
	}

	knot_rdataset_clear(&synth_rrsig.rrs, NULL);

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
                              changeset_t *changeset)
{
	assert(!knot_rrset_empty(covered));
	assert(zone_keys);
	assert(changeset);

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
		result = changeset_add_rrset(changeset, to_add, CHANGESET_ADD);
	}

	if (to_add != NULL && result != KNOT_EOK) {
		knot_rrset_free(&to_add, NULL);
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
static int remove_rrset_rrsigs(const knot_dname_t *owner, uint16_t type,
                               const knot_rrset_t *rrsigs,
                               changeset_t *changeset)
{
	assert(owner);
	assert(changeset);
	knot_rrset_t *synth_rrsig =
		knot_rrset_new(owner, KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, NULL);
	if (synth_rrsig == NULL) {
		return KNOT_ENOMEM;
	}
	int ret = knot_synth_rrsig(type, &rrsigs->rrs, &synth_rrsig->rrs, NULL);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&synth_rrsig, NULL);
		if (ret != KNOT_ENOENT) {
			return ret;
		}
		return KNOT_EOK;
	}

	ret = changeset_add_rrset(changeset, synth_rrsig, CHANGESET_REMOVE);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&synth_rrsig, NULL);
	}

	return ret;
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
                              const knot_rrset_t *rrsigs,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              changeset_t *changeset)
{
	assert(!knot_rrset_empty(covered));

	if (!knot_rrset_empty(rrsigs)) {
		int result = remove_rrset_rrsigs(covered->owner, covered->type,
		                                 rrsigs, changeset);
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
                        const knot_rrset_t *rrsigs,
                        const knot_zone_keys_t *zone_keys,
                        const knot_dnssec_policy_t *policy,
                        changeset_t *changeset,
                        uint32_t *expires_at)
{
	assert(!knot_rrset_empty(covered));

	// TODO this function creates some signatures twice (for checking)
	// maybe merge the two functions into one
	// jvcelak: Not really, maybe for RSA. The digest is computed twice,
	// but the verification process can differ from signature computation.
	// TODO reuse digest for RSA then, RSA is the most used algo family,
	// and we create all the signatures twice, that is not cool I think.

	int result = remove_expired_rrsigs(covered, rrsigs, zone_keys,
	                                   policy, changeset, expires_at);
	if (result != KNOT_EOK) {
		return result;
	}

	return add_missing_rrsigs(covered, rrsigs, zone_keys, policy,
	                          changeset);
}

static int remove_standalone_rrsigs(const zone_node_t *node,
                                    const knot_rrset_t *rrsigs,
                                    changeset_t *changeset)
{
	if (rrsigs == NULL) {
		return KNOT_EOK;
	}

	uint16_t rrsigs_rdata_count = rrsigs->rrs.rr_count;
	for (uint16_t i = 0; i < rrsigs_rdata_count; ++i) {
		uint16_t type_covered = knot_rrsig_type_covered(&rrsigs->rrs, i);
		if (!node_rrtype_exists(node, type_covered)) {
			knot_rrset_t *to_remove = knot_rrset_new(rrsigs->owner,
			                                         rrsigs->type,
			                                         rrsigs->rclass,
			                                         NULL);
			if (to_remove == NULL) {
				return KNOT_ENOMEM;
			}
			knot_rdata_t *rr_rem = knot_rdataset_at(&rrsigs->rrs, i);
			int ret = knot_rdataset_add(&to_remove->rrs, rr_rem, NULL);
			if (ret != KNOT_EOK) {
				knot_rrset_free(&to_remove, NULL);
				return ret;
			}
			ret = changeset_add_rrset(changeset, to_remove,
			                          CHANGESET_REMOVE);
			if (ret != KNOT_EOK) {
				knot_rrset_free(&to_remove, NULL);
				return ret;
			}
		}
	}

	return KNOT_EOK;
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
static int sign_node_rrsets(const zone_node_t *node,
                            const knot_zone_keys_t *zone_keys,
                            const knot_dnssec_policy_t *policy,
                            changeset_t *changeset,
                            uint32_t *expires_at)
{
	assert(node);
	assert(policy);

	int result = KNOT_EOK;
	knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);

	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}
		bool should_sign = false;
		result = knot_zone_sign_rr_should_be_signed(node, &rrset,
		                                            &should_sign);
		if (result != KNOT_EOK) {
			return result;
		}
		if (!should_sign) {
			continue;
		}

		if (policy->forced_sign) {
			result = force_resign_rrset(&rrset, &rrsigs, zone_keys, policy,
			         changeset);
		} else {
			result = resign_rrset(&rrset, &rrsigs, zone_keys, policy,
			                      changeset, expires_at);
		}

		if (result != KNOT_EOK) {
			return result;
		}
	}

	return remove_standalone_rrsigs(node, &rrsigs, changeset);
}

/*!
 * \brief Struct to carry data for 'sign_data' callback function.
 */
typedef struct node_sign_args {
	const knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	changeset_t *changeset;
	uint32_t expires_at;
} node_sign_args_t;

/*!
 * \brief Sign node (callback function).
 *
 * \param node  Node to be signed.
 * \param data  Callback data, node_sign_args_t.
 */
static int sign_node(zone_node_t **node, void *data)
{
	assert(node && *node);
	assert(data);

	node_sign_args_t *args = (node_sign_args_t *)data;

	if ((*node)->rrset_count == 0) {
		return KNOT_EOK;
	}

	if ((*node)->flags & NODE_FLAGS_NONAUTH) {
		return KNOT_EOK;
	}

	int result = sign_node_rrsets(*node, args->zone_keys, args->policy,
	                              args->changeset, &args->expires_at);
	(*node)->flags &= ~NODE_FLAGS_REMOVED_NSEC;

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
static int zone_tree_sign(zone_tree_t *tree,
                          const knot_zone_keys_t *zone_keys,
                          const knot_dnssec_policy_t *policy,
                          changeset_t *changeset,
                          uint32_t *expires_at)
{
	assert(zone_keys);
	assert(policy);
	assert(changeset);

	node_sign_args_t args = {
		.zone_keys = zone_keys,
		.policy = policy,
		.changeset = changeset,
		.expires_at = time(NULL) + policy->sign_lifetime
	};

	int result = zone_tree_apply(tree, sign_node, &args);
	*expires_at = args.expires_at;

	return result;
}

/*- private API - signing of NSEC(3) in changeset ----------------------------*/

/*!
 * \brief Struct to carry data for 'add_rrsigs_for_nsec' callback function.
 */
typedef struct {
	const zone_contents_t *zone;
	const knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	changeset_t *changeset;
	hattrie_t *signed_tree;
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
	assert(!knot_rrset_empty(dnskeys));
	assert(key);

	uint16_t dnskeys_rdata_count = dnskeys->rrs.rr_count;
	for (uint16_t i = 0; i < dnskeys_rdata_count; i++) {
		const knot_rdata_t *rr_data = knot_rdataset_at(&dnskeys->rrs, i);
		uint8_t *rdata = knot_rdata_data(rr_data);
		uint16_t rdata_size = knot_rdata_rdlen(rr_data);
		if (dnskey_rdata_match(key, rdata, rdata_size)) {
			return true;
		}
	}

	return false;
}

static int rrset_add_zone_key(knot_rrset_t *rrset,
                              const knot_zone_key_t *zone_key,
                              uint32_t ttl)
{
	assert(rrset);
	assert(zone_key);

	const knot_binary_t *key_rdata = &zone_key->dnssec_key.dnskey_rdata;

	return knot_rrset_add_rdata(rrset, key_rdata->data, key_rdata->size, ttl,
	                         NULL);
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
                                  changeset_t *changeset)
{
	assert(soa->type == KNOT_RRTYPE_SOA);
	assert(changeset);

	if (knot_rrset_empty(dnskeys)) {
		return KNOT_EOK;
	}
	assert(dnskeys->type == KNOT_RRTYPE_DNSKEY);

	knot_rrset_t *to_remove = NULL;
	int result = KNOT_EOK;

	const knot_rdata_t *dnskeys_data = knot_rdataset_at(&dnskeys->rrs, 0);
	const knot_rdata_t *soa_data = knot_rdataset_at(&soa->rrs, 0);
	if (knot_rdata_ttl(dnskeys_data) != knot_rdata_ttl(soa_data)) {
		dbg_dnssec_detail("removing DNSKEYs (SOA TTL differs)\n");
		to_remove = knot_rrset_copy(dnskeys, NULL);
		result = to_remove ? KNOT_EOK : KNOT_ENOMEM;
		goto done;
	}

	uint16_t dnskeys_rdata_count = dnskeys->rrs.rr_count;
	for (uint16_t i = 0; i < dnskeys_rdata_count; i++) {
		dnskeys_data = knot_rdataset_at(&dnskeys->rrs, i);
		uint8_t *rdata = knot_rdata_data(dnskeys_data);
		uint16_t rdata_size = knot_rdata_rdlen(dnskeys_data);
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
			to_remove = knot_rrset_new(dnskeys->owner,
			                           dnskeys->type,
			                           dnskeys->rclass,
			                           NULL);
			if (to_remove == NULL) {
				result = KNOT_ENOMEM;
				break;
			}
		}

		knot_rdata_t *to_rem = knot_rdataset_at(&dnskeys->rrs, i);
		result = knot_rdataset_add(&to_remove->rrs, to_rem, NULL);
		if (result != KNOT_EOK) {
			break;
		}
	}

done:

	if (to_remove != NULL && result == KNOT_EOK) {
		result = changeset_add_rrset(changeset, to_remove,
		                             CHANGESET_REMOVE);
	}

	if (to_remove != NULL && result != KNOT_EOK) {
		knot_rrset_free(&to_remove, NULL);
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

	return knot_rrset_new(soa->owner, KNOT_RRTYPE_DNSKEY, soa->rclass, NULL);
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
                               changeset_t *changeset)
{
	assert(soa);
	assert(soa->type == KNOT_RRTYPE_SOA);
	assert(knot_rrset_empty(dnskeys) || dnskeys->type == KNOT_RRTYPE_DNSKEY);
	assert(zone_keys);
	assert(changeset);

	knot_rrset_t *to_add = NULL;
	int result = KNOT_EOK;
	const knot_rdata_t *dnskeys_data = knot_rdataset_at(&dnskeys->rrs, 0);
	const knot_rdata_t *soa_data = knot_rdataset_at(&soa->rrs, 0);
	bool add_all = (knot_rrset_empty(dnskeys) ||
	                knot_rdata_ttl(dnskeys_data) != knot_rdata_ttl(soa_data));

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

		result = rrset_add_zone_key(to_add, key, knot_rdata_ttl(soa_data));
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (to_add != NULL && result == KNOT_EOK) {
		result = changeset_add_rrset(changeset, to_add, CHANGESET_ADD);
	}

	if (to_add != NULL && result != KNOT_EOK) {
		knot_rrset_free(&to_add, NULL);
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
                                 const knot_rrset_t *rrsigs,
                                 const knot_rrset_t *soa,
                                 const knot_zone_keys_t *zone_keys,
                                 const knot_dnssec_policy_t *policy,
                                 changeset_t *changeset)
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
	uint16_t dnskeys_rdata_count = dnskeys->rrs.rr_count;
	for (uint16_t i = 0; i < dnskeys_rdata_count; i++) {
		const knot_rdata_t *rr_data = knot_rdataset_at(&dnskeys->rrs, i);
		uint8_t *rdata = knot_rdata_data(rr_data);
		uint16_t rdata_size = knot_rdata_rdlen(rr_data);
		uint16_t keytag = knot_keytag(rdata, rdata_size);
		if (knot_get_zone_key(zone_keys, keytag) != NULL) {
			continue;
		}

		knot_rdata_t *to_add = knot_rdataset_at(&dnskeys->rrs, i);
		result = knot_rdataset_add(&new_dnskeys->rrs, to_add, NULL);
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

		const knot_rdata_t *soa_data = knot_rdataset_at(&soa->rrs, 0);
		result = rrset_add_zone_key(new_dnskeys, key,
		                            knot_rdata_ttl(soa_data));
		if (result != KNOT_EOK) {
			goto fail;
		}
	}

	result = add_missing_rrsigs(new_dnskeys, NULL, zone_keys, policy,
	                            changeset);
	if (result != KNOT_EOK) {
		goto fail;
	}

	if (!knot_rrset_empty(dnskeys)) {
		result = remove_rrset_rrsigs(dnskeys->owner, dnskeys->type,
		                             rrsigs, changeset);
	}

fail:

	knot_rrset_free(&new_dnskeys, NULL);
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
static int update_dnskeys(const zone_contents_t *zone,
                          const knot_zone_keys_t *zone_keys,
                          const knot_dnssec_policy_t *policy,
                          changeset_t *changeset)
{
	assert(zone);
	assert(zone->apex);
	assert(changeset);

	const zone_node_t *apex = zone->apex;
	knot_rrset_t dnskeys = node_rrset(apex, KNOT_RRTYPE_DNSKEY);
	knot_rrset_t soa = node_rrset(apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(apex, KNOT_RRTYPE_RRSIG);
	if (knot_rrset_empty(&soa)) {
		return KNOT_EINVAL;
	}

	int result;
	size_t changes_before = changeset_size(changeset);

	result = remove_invalid_dnskeys(&soa, &dnskeys, zone_keys, changeset);
	if (result != KNOT_EOK) {
		return result;
	}

	result = add_missing_dnskeys(&soa, &dnskeys, zone_keys, changeset);
	if (result != KNOT_EOK) {
		return result;
	}
	knot_rrset_t dnskey_rrsig;
	knot_rrset_init(&dnskey_rrsig, apex->owner, KNOT_RRTYPE_RRSIG,
	                KNOT_CLASS_IN);
	result = knot_synth_rrsig(KNOT_RRTYPE_DNSKEY, &rrsigs.rrs,
	                          &dnskey_rrsig.rrs, NULL);
	if (result != KNOT_EOK) {
		if (result != KNOT_ENOENT) {
			return result;
		}
	}

	bool modified = (changeset_size(changeset) != changes_before);
	bool signatures_exist = (!knot_rrset_empty(&dnskeys) &&
	                        all_signatures_exist(&dnskeys, &dnskey_rrsig,
	                                             zone_keys, policy));
	knot_rdataset_clear(&dnskey_rrsig.rrs, NULL);
	if (!modified && signatures_exist) {
		return KNOT_EOK;
	}

	dbg_dnssec_detail("Creating new signatures for DNSKEYs\n");
	return update_dnskeys_rrsigs(&dnskeys, &rrsigs, &soa, zone_keys, policy, changeset);
}

/*!
 * \brief Goes through list and looks for RRSet type there.
 *
 * \return True if RR type is in the list, false otherwise.
 */
static bool rr_type_in_list(const knot_rrset_t *rr, const list_t *l)
{
	if (l == NULL || EMPTY_LIST(*l)) {
		return false;
	}
	assert(rr);

	type_node_t *n = NULL;
	WALK_LIST(n, *l) {
		type_node_t *type_node = (type_node_t *)n;
		if (type_node->type == rr->type) {
			return true;
		}
	};

	return false;
}

static int add_rr_type_to_list(const knot_rrset_t *rr, list_t *l)
{
	assert(rr);
	assert(l);

	type_node_t *n = malloc(sizeof(type_node_t));
	if (n == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}
	n->type = rr->type;

	add_head(l, (node_t *)n);
	return KNOT_EOK;
}

/*!
 * \brief Checks whether RRSet is not already in the hash table, automatically
 *        stores its pointer to the table if not found, but returns false in
 *        that case.
 *
 * \param rrset      RRSet to be checked for.
 * \param tree       Tree with already signed RRs.
 * \param rr_signed  Set to true if RR is signed already, false otherwise.
 *
 * \return KNOT_E*
 */
static int rr_already_signed(const knot_rrset_t *rrset, hattrie_t *t,
                             bool *rr_signed)
{
	assert(rrset);
	assert(t);
	*rr_signed = false;
	// Create a key = RRSet owner converted to sortable format
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, rrset->owner, NULL);
	value_t stored_info = (signed_info_t *)hattrie_tryget(t, (char *)lf+1,
	                                                      *lf);
	if (stored_info == NULL) {
		// Create new info struct
		signed_info_t *info = malloc(sizeof(signed_info_t));
		if (info == NULL) {
			ERR_ALLOC_FAILED;
			return KNOT_ENOMEM;
		}
		memset(info, 0, sizeof(signed_info_t));
		// Store actual dname repr
		info->dname = knot_dname_copy(rrset->owner, NULL);
		if (info->dname == NULL) {
			free(info);
			return KNOT_ENOMEM;
		}
		// Create new list to insert as a value
		info->type_list = malloc(sizeof(list_t));
		if (info->type_list == NULL) {
			ERR_ALLOC_FAILED;
			free(info->dname);
			free(info);
			return KNOT_ENOMEM;
		}
		init_list(info->type_list);
		// Insert type to list
		int ret = add_rr_type_to_list(rrset, info->type_list);
		if (ret != KNOT_EOK) {
			free(info->type_list);
			free(info->dname);
			free(info);
			return ret;
		}
		*hattrie_get(t, (char *)lf+1, *lf) = info;
	} else {
		signed_info_t *info = *((signed_info_t **)stored_info);
		assert(info->type_list);
		// Check whether the type is in the list already
		if (rr_type_in_list(rrset, info->type_list)) {
			*rr_signed = true;
			return KNOT_EOK;
		}
		// Just update the existing list
		int ret = add_rr_type_to_list(rrset, info->type_list);
		if (ret != KNOT_EOK) {
			*rr_signed = false;
			return KNOT_EOK;
		}
	}

	*rr_signed = false;
	return KNOT_EOK;
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
	const zone_node_t *node =
		zone_contents_find_node(args->zone, chg_rrset->owner);

	// If node is not in zone, all its RRSIGs were dropped - no-op
	if (node) {
		knot_rrset_t zone_rrset = node_rrset(node, chg_rrset->type);
		knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);
		bool should_sign = false;

		int ret = knot_zone_sign_rr_should_be_signed(node, &zone_rrset,
		                                             &should_sign);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Check for RRSet in the 'already_signed' table
		if (args->signed_tree && (should_sign && knot_rrset_empty(&zone_rrset))) {
			bool already_signed = false;

			int ret = rr_already_signed(chg_rrset, args->signed_tree,
			                            &already_signed);
			if (ret != KNOT_EOK) {
				return ret;
			}
			if (already_signed) {
				/* Do not sign again. */
				should_sign = false;
			}
		}

		if (should_sign) {
			return force_resign_rrset(&zone_rrset, &rrsigs,
			                          args->zone_keys,
			                          args->policy,
			                          args->changeset);
		} else {
			/*
			 * If RRSet in zone DOES have RRSIGs although we
			 * should not sign it, DDNS-caused change to node/rr
			 * occured and we have to drop all RRSIGs.
			 *
			 * OR
			 *
			 * The whole RRSet was removed, but RRSIGs remained in
			 * the zone. We need to drop them as well.
			 */
			return remove_rrset_rrsigs(chg_rrset->owner,
			                           chg_rrset->type, &rrsigs,
			                           args->changeset);
		}
	}

	return KNOT_EOK;
}

/*!
 * \brief Frees info node about update signing.
 *
 * \param val  Node to free.
 * \param d    Unused.
 */
static int free_helper_trie_node(value_t *val, void *d)
{
	UNUSED(d);
	signed_info_t *info = (signed_info_t *)*val;
	if (info->type_list && !EMPTY_LIST(*(info->type_list))) {
		WALK_LIST_FREE(*(info->type_list));
	}
	free(info->type_list);
	knot_dname_free(&info->dname, NULL);
	knot_dname_free(&info->hashed_dname, NULL);
	free(info);
	return KNOT_EOK;
}

/*!
 * \brief Clears trie with info about update signing.
 *
 * \param t  Trie to clear.
 */
static void knot_zone_clear_sorted_changes(hattrie_t *t)
{
	if (t) {
		hattrie_apply_rev(t, free_helper_trie_node, NULL);
	}
}

/*- public API ---------------------------------------------------------------*/

/*!
 * \brief Update zone signatures and store performed changes in changeset.
 */
int knot_zone_sign(const zone_contents_t *zone,
                   const knot_zone_keys_t *zone_keys,
                   const knot_dnssec_policy_t *policy,
                   changeset_t *changeset,
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
bool knot_zone_sign_soa_expired(const zone_contents_t *zone,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy)
{
	if (!zone || !zone_keys || !policy) {
		return KNOT_EINVAL;
	}

	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(&soa));
	return !all_signatures_exist(&soa, &rrsigs, zone_keys, policy);
}

/*!
 * \brief Update and sign SOA and store performed changes in changeset.
 */
int knot_zone_sign_update_soa(const knot_rrset_t *soa,
                              const knot_rrset_t *rrsigs,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              uint32_t new_serial,
                              changeset_t *changeset)
{
	if (knot_rrset_empty(soa) || !zone_keys || !policy || !changeset) {
		return KNOT_EINVAL;
	}

	dbg_dnssec_verb("Updating SOA...\n");

	uint32_t serial = knot_soa_serial(&soa->rrs);
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

	if (!knot_rrset_empty(rrsigs)) {
		result = remove_rrset_rrsigs(soa->owner, soa->type, rrsigs,
		                             changeset);
		if (result != KNOT_EOK) {
			return result;
		}
	}

	// copy old SOA and create new SOA with updated serial

	knot_rrset_t *soa_from = NULL;
	knot_rrset_t *soa_to = NULL;

	soa_from = knot_rrset_copy(soa, NULL);
	if (soa_from == NULL) {
		return KNOT_ENOMEM;
	}

	soa_to =  knot_rrset_copy(soa, NULL);
	if (soa_to == NULL) {
		knot_rrset_free(&soa_from, NULL);
		return KNOT_ENOMEM;
	}

	knot_soa_serial_set(&soa_to->rrs, new_serial);

	// add signatures for new SOA

	result = add_missing_rrsigs(soa_to, NULL, zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		knot_rrset_free(&soa_from, NULL);
		knot_rrset_free(&soa_to, NULL);
		return result;
	}

	// save the result

	assert(changeset->soa_from == NULL);
	assert(changeset->soa_to == NULL);

	changeset->soa_from = soa_from;
	changeset->soa_to = soa_to;

	return KNOT_EOK;
}

/*!
 * \brief Sign changeset created by DDNS or zone-diff.
 */
int knot_zone_sign_changeset(const zone_contents_t *zone,
                             const changeset_t *in_ch,
                             changeset_t *out_ch,
                             const knot_zone_keys_t *zone_keys,
                             const knot_dnssec_policy_t *policy)
{
	if (zone == NULL || in_ch == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	// Create args for wrapper function - hattrie for duplicate sigs
	changeset_signing_data_t args = {
		.zone = zone,
		.zone_keys = zone_keys,
		.policy = policy,
		.changeset = out_ch,
		.signed_tree = hattrie_create()
	};

	if (args.signed_tree == NULL) {
		return KNOT_ENOMEM;
	}

	// Sign all RRs that are new in changeset
	int ret = changeset_apply((changeset_t *)in_ch,
	                          CHANGESET_ADD,
	                          sign_changeset_wrap, &args);

	// Sign all RRs that are removed in changeset
	if (ret == KNOT_EOK) {
		ret = changeset_apply((changeset_t *)in_ch,
		                      CHANGESET_REMOVE,
		                      sign_changeset_wrap, &args);
	}

	knot_zone_clear_sorted_changes(args.signed_tree);
	hattrie_free(args.signed_tree);

	return ret;
}

/*!
 * \brief Sign NSEC/NSEC3 nodes in changeset and update the changeset.
 */
int knot_zone_sign_nsecs_in_changeset(const knot_zone_keys_t *zone_keys,
                                      const knot_dnssec_policy_t *policy,
                                      changeset_t *changeset)
{
	assert(zone_keys);
	assert(policy);
	assert(changeset);

	changeset_signing_data_t data = {.zone = NULL,
	                                 .zone_keys = zone_keys,
	                                 .policy = policy,
	                                 .changeset = changeset };

	return changeset_apply(changeset, CHANGESET_ADD,
	                       add_rrsigs_for_nsec, &data);
}

/*!
 * \brief Checks whether RRSet in a node has to be signed. Will not return
 *        true for all types that should be signed, do not use this as an
 *        universal function, it is implementation specific.
 */
int knot_zone_sign_rr_should_be_signed(const zone_node_t *node,
                                       const knot_rrset_t *rrset,
                                       bool *should_sign)
{
	if (should_sign == NULL) {
		return KNOT_EINVAL;
	}

	*should_sign = false; // Only one case at the end is set to true
	if (node == NULL || knot_rrset_empty(rrset)) {
		return KNOT_EOK;
	}

	// We do not want to sign RRSIGs
	if (rrset->type == KNOT_RRTYPE_RRSIG) {
		return KNOT_EOK;
	}

	// SOA and DNSKEYs are handled separately in the zone apex
	if (node_rrtype_exists(node, KNOT_RRTYPE_SOA)) {
		if (rrset->type == KNOT_RRTYPE_SOA) {
			return KNOT_EOK;
		}

		if (rrset->type == KNOT_RRTYPE_DNSKEY) {
			return KNOT_EOK;
		}
	}

	// At delegation points we only want to sign NSECs and DSs
	if ((node->flags & NODE_FLAGS_DELEG)) {
		if (!(rrset->type == KNOT_RRTYPE_NSEC ||
		    rrset->type == KNOT_RRTYPE_DS)) {
			return KNOT_EOK;
		}
	}

	// These RRs have their signatures stored in changeset already
	if (node->flags & NODE_FLAGS_REMOVED_NSEC
	    && ((rrset->type == KNOT_RRTYPE_NSEC)
	         || (rrset->type == KNOT_RRTYPE_NSEC3))) {
		return KNOT_EOK;
	}

	*should_sign = true;
	return KNOT_EOK;
}
