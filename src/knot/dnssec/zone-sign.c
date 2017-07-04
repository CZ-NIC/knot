/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/error.h"
#include "dnssec/key.h"
#include "dnssec/keytag.h"
#include "dnssec/sign.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/updates/changesets.h"
#include "libknot/descriptor.h"
#include "libknot/dname.h"
#include "libknot/libknot.h"
#include "libknot/rrset.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/rrtype/soa.h"
#include "contrib/dynarray.h"
#include "contrib/macros.h"
#include "contrib/wire_ctx.h"

typedef struct type_node {
	node_t n;
	uint16_t type;
} type_node_t;

typedef struct signed_info {
	knot_dname_t *dname;
	knot_dname_t *hashed_dname;
	list_t *type_list;
} signed_info_t;

/*- private API - common functions -------------------------------------------*/

/*!
 * \brief Initializes RR set and set owner and rclass from template RR set.
 */
static knot_rrset_t rrset_init_from(const knot_rrset_t *src, uint16_t type)
{
	assert(src);
	knot_rrset_t rrset;
	knot_rrset_init(&rrset, src->owner, type, src->rclass);
	return rrset;
}

/*!
 * \brief Create empty RRSIG RR set for a given RR set to be covered.
 */
static knot_rrset_t create_empty_rrsigs_for(const knot_rrset_t *covered)
{
	assert(!knot_rrset_empty(covered));
	return rrset_init_from(covered, KNOT_RRTYPE_RRSIG);
}

static bool apex_rr_changed(const zone_node_t *old_apex,
                            const zone_node_t *new_apex,
                            uint16_t type)
{
	assert(old_apex);
	assert(new_apex);
	knot_rrset_t old_rr = node_rrset(old_apex, type);
	knot_rrset_t new_rr = node_rrset(new_apex, type);

	return !knot_rrset_equal(&old_rr, &new_rr, KNOT_RRSET_COMPARE_WHOLE);
}

static bool apex_dnssec_changed(zone_update_t *update)
{
	const zone_node_t *new_apex = zone_update_get_apex(update);
	if (update->zone->contents != NULL) {
		const zone_node_t *old_apex = update->zone->contents->apex;
		return !changeset_empty(&update->change) &&
		       (apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_DNSKEY) ||
			apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_NSEC3PARAM));
	} else if (new_apex != NULL) {
		return true;
	}

	return false;
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
				   const dnssec_key_t *key,
				   dnssec_sign_ctx_t *ctx,
				   const kdnssec_ctx_t *dnssec_ctx)
{
	assert(key);

	if (knot_rrset_empty(rrsigs)) {
		return false;
	}

	uint16_t rrsigs_rdata_count = rrsigs->rrs.rr_count;
	for (uint16_t i = 0; i < rrsigs_rdata_count; i++) {
		uint16_t rr_keytag = knot_rrsig_key_tag(&rrsigs->rrs, i);
		uint16_t rr_covered = knot_rrsig_type_covered(&rrsigs->rrs, i);

		uint16_t keytag = dnssec_key_get_keytag(key);
		if (rr_keytag != keytag || rr_covered != covered->type) {
			continue;
		}

		if (knot_check_signature(covered, rrsigs, i, key, ctx,
		                         dnssec_ctx) == KNOT_EOK) {
			return true;
		}
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
static bool use_key(const zone_key_t *key, const knot_rrset_t *covered)
{
	assert(key);
	assert(covered);

	if (!key->is_active && !key->is_ready) {
		return false;
	}

	bool is_apex = knot_dname_is_equal(covered->owner,
	                                   dnssec_key_get_dname(key->key));

	bool is_zone_key = is_apex && covered->type == KNOT_RRTYPE_DNSKEY;

	return (key->is_ksk && is_zone_key) || (key->is_zsk && !is_zone_key);
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
                                 const zone_keyset_t *zone_keys,
                                 const kdnssec_ctx_t *dnssec_ctx)
{
	assert(!knot_rrset_empty(covered));
	assert(zone_keys);

	for (int i = 0; i < zone_keys->count; i++) {
		zone_key_t *key = &zone_keys->keys[i];
		if (!use_key(key, covered)) {
			continue;
		}

		if (!valid_signature_exists(covered, rrsigs, key->key,
		                            key->ctx, dnssec_ctx)) {
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
 * \return Dynarray of such keys.
 */
static keyptr_dynarray_t get_matching_zone_keys(const knot_rrset_t *rrsigs,
                                                     size_t pos, const zone_keyset_t *keys)
{
	assert(rrsigs && rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(keys);

	uint16_t keytag = knot_rrsig_key_tag(&rrsigs->rrs, pos);

	return get_zone_keys(keys, keytag);
}

/*!
 * \brief Note earliest expiration of a signature.
 *
 * \param rrsigs      RR set with RRSIGs.
 * \param pos         Position of RR in rrsigs.
 * \param expires_at  Current earliest expiration, will be updated.
 */
static void note_earliest_expiration(const knot_rrset_t *rrsigs, size_t pos,
                                     knot_time_t *expires_at)
{
	assert(rrsigs);
	assert(expires_at);

	uint32_t curr_rdata = knot_rrsig_sig_expiration(&rrsigs->rrs, pos);
	knot_time_t current = knot_time_from_u32(curr_rdata);
	*expires_at = knot_time_min(current, *expires_at);
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
                                 const zone_keyset_t *zone_keys,
                                 const kdnssec_ctx_t *dnssec_ctx,
                                 changeset_t *changeset,
                                 knot_time_t *expires_at)
{
	assert(changeset);

	if (knot_rrset_empty(rrsigs)) {
		return KNOT_EOK;
	}

	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);

	knot_rrset_t to_remove;
	knot_rrset_init_empty(&to_remove);
	int result = KNOT_EOK;

	knot_rrset_t synth_rrsig = rrset_init_from(rrsigs, KNOT_RRTYPE_RRSIG);
	result = knot_synth_rrsig(covered->type, &rrsigs->rrs, &synth_rrsig.rrs, NULL);
	if (result != KNOT_EOK) {
		if (result != KNOT_ENOENT) {
			return result;
		}
		return KNOT_EOK;
	}

	uint16_t rrsig_rdata_count = synth_rrsig.rrs.rr_count;
	for (uint16_t i = 0; i < rrsig_rdata_count; i++) {
		struct keyptr_dynarray keys = get_matching_zone_keys(&synth_rrsig, i, zone_keys);
		int endloop = 0; // 1 - continue; 2 - break

		dynarray_foreach(keyptr, zone_key_t *, key, keys) {
			if (!(*key)->is_active) {
				continue;
			}
			result = knot_check_signature(covered, &synth_rrsig, i,
			                              (*key)->key, (*key)->ctx, dnssec_ctx);
			if (result == KNOT_EOK) {
				// valid signature
				note_earliest_expiration(&synth_rrsig, i, expires_at);
				endloop = 1;
				break;
			} else if (result != DNSSEC_INVALID_SIGNATURE) {
				endloop = 2;
				break;
			}
		}
		keyptr_dynarray_free(&keys);

		if (endloop == 2) {
			break;
		} else if (endloop == 1) {
			continue;
		}

		if (knot_rrset_empty(&to_remove)) {
			to_remove = create_empty_rrsigs_for(&synth_rrsig);
		}

		knot_rdata_t *rr_rem = knot_rdataset_at(&synth_rrsig.rrs, i);
		result = knot_rdataset_add(&to_remove.rrs, rr_rem, NULL);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (!knot_rrset_empty(&to_remove) && result == KNOT_EOK) {
		result = changeset_add_removal(changeset, &to_remove, 0);
	}

	knot_rdataset_clear(&synth_rrsig.rrs, NULL);
	knot_rdataset_clear(&to_remove.rrs, NULL);

	return result;
}

/*!
 * \brief Add missing RRSIGs into the changeset for adding.
 *
 * \param covered     RR set with covered records.
 * \param rrsigs      RR set with RRSIGs.
 * \param zone_keys   Zone keys.
 * \param dnssec_ctx  DNSSEC signing context
 * \param changeset   Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int add_missing_rrsigs(const knot_rrset_t *covered,
                              const knot_rrset_t *rrsigs,
                              const zone_keyset_t *zone_keys,
                              const kdnssec_ctx_t *dnssec_ctx,
                              changeset_t *changeset)
{
	assert(!knot_rrset_empty(covered));
	assert(zone_keys);
	assert(changeset);

	int result = KNOT_EOK;
	knot_rrset_t to_add;
	knot_rrset_init_empty(&to_add);

	for (int i = 0; i < zone_keys->count; i++) {
		const zone_key_t *key = &zone_keys->keys[i];
		if (!use_key(key, covered)) {
			continue;
		}

		if (valid_signature_exists(covered, rrsigs, key->key, key->ctx, dnssec_ctx)) {
			continue;
		}

		if (knot_rrset_empty(&to_add)) {
			to_add = create_empty_rrsigs_for(covered);
		}

		result = knot_sign_rrset(&to_add, covered, key->key, key->ctx, dnssec_ctx, NULL);
		if (result != KNOT_EOK) {
			break;
		}
	}

	if (!knot_rrset_empty(&to_add) && result == KNOT_EOK) {
		result = changeset_add_addition(changeset, &to_add, 0);
	}

	knot_rdataset_clear(&to_add.rrs, NULL);

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
	knot_rrset_t synth_rrsig;
	knot_rrset_init(&synth_rrsig, (knot_dname_t *)owner,
	                KNOT_RRTYPE_RRSIG, rrsigs->rclass);
	int ret = knot_synth_rrsig(type, &rrsigs->rrs, &synth_rrsig.rrs, NULL);
	if (ret != KNOT_EOK) {
		if (ret != KNOT_ENOENT) {
			return ret;
		}
		return KNOT_EOK;
	}

	ret = changeset_add_removal(changeset, &synth_rrsig, 0);
	knot_rdataset_clear(&synth_rrsig.rrs, NULL);

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
                              const zone_keyset_t *zone_keys,
                              const kdnssec_ctx_t *dnssec_ctx,
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

	return add_missing_rrsigs(covered, NULL, zone_keys, dnssec_ctx, changeset);
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
                        const zone_keyset_t *zone_keys,
                        const kdnssec_ctx_t *dnssec_ctx,
                        changeset_t *changeset,
                        knot_time_t *expires_at)
{
	assert(!knot_rrset_empty(covered));

	// TODO this function creates some signatures twice (for checking)
	int result = remove_expired_rrsigs(covered, rrsigs, zone_keys,
	                                   dnssec_ctx, changeset, expires_at);
	if (result != KNOT_EOK) {
		return result;
	}

	return add_missing_rrsigs(covered, rrsigs, zone_keys, dnssec_ctx,
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
			knot_rrset_t to_remove;
			knot_rrset_init(&to_remove, rrsigs->owner, rrsigs->type,
			                rrsigs->rclass);
			knot_rdata_t *rr_rem = knot_rdataset_at(&rrsigs->rrs, i);
			int ret = knot_rdataset_add(&to_remove.rrs, rr_rem, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
			ret = changeset_add_removal(changeset, &to_remove, 0);
			knot_rdataset_clear(&to_remove.rrs, NULL);
			if (ret != KNOT_EOK) {
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
                            const zone_keyset_t *zone_keys,
                            const kdnssec_ctx_t *dnssec_ctx,
                            changeset_t *changeset,
                            knot_time_t *expires_at)
{
	assert(node);
	assert(dnssec_ctx);

	int result = KNOT_EOK;
	knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);

	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		if (rrset.type == KNOT_RRTYPE_RRSIG) {
			continue;
		}

		if (!knot_zone_sign_rr_should_be_signed(node, &rrset)) {
			continue;
		}

		if (dnssec_ctx->rrsig_drop_existing) {
			result = force_resign_rrset(&rrset, &rrsigs, zone_keys,
			                            dnssec_ctx, changeset);
		} else {
			result = resign_rrset(&rrset, &rrsigs, zone_keys,
			                      dnssec_ctx, changeset, expires_at);
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
	const zone_keyset_t *zone_keys;
	const kdnssec_ctx_t *dnssec_ctx;
	changeset_t *changeset;
	knot_time_t expires_at;
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

	int result = sign_node_rrsets(*node, args->zone_keys, args->dnssec_ctx,
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
                          const zone_keyset_t *zone_keys,
                          const kdnssec_ctx_t *dnssec_ctx,
                          changeset_t *changeset,
                          knot_time_t *expires_at)
{
	assert(zone_keys);
	assert(dnssec_ctx);
	assert(changeset);

	node_sign_args_t args = {
		.zone_keys = zone_keys,
		.dnssec_ctx = dnssec_ctx,
		.changeset = changeset,
		.expires_at = knot_time_add(dnssec_ctx->now, dnssec_ctx->policy->rrsig_lifetime),
	};

	int result = zone_tree_apply(tree, sign_node, &args);
	*expires_at = args.expires_at;

	return result;
}

/*- private API - signing of NSEC(3) in changeset ----------------------------*/

/*!
 * \brief Struct to carry data for changeset signing callback functions.
 */
typedef struct {
	const zone_contents_t *zone;
	const zone_keyset_t *zone_keys;
	const kdnssec_ctx_t *dnssec_ctx;
	changeset_t *changeset;
	trie_t *signed_tree;
} changeset_signing_data_t;

/*- private API - DNSKEY handling --------------------------------------------*/

/*!
 * \brief Check if DNSKEY RDATA match with DNSSEC key.
 *
 * \param zone_key    Zone key.
 * \param rdata       DNSKEY RDATA.
 *
 * \return DNSKEY RDATA match with DNSSEC key.
 */
static bool dnskey_rdata_match(zone_key_t *key,
                               const dnssec_binary_t *rdata)
{
	assert(key);
	assert(rdata);

	dnssec_binary_t dnskey_rdata = { 0 };
	dnssec_key_get_rdata(key->key, &dnskey_rdata);

	return dnssec_binary_cmp(&dnskey_rdata, rdata) == 0;
}

static bool cds_rdata_match(zone_key_t *key,
                            const dnssec_binary_t *rdata)
{
        assert(key);
        assert(rdata);
        dnssec_binary_t cds_rdata = { 0 };
        int ret = zone_key_calculate_ds(key, &cds_rdata);
        int res = dnssec_binary_cmp(&cds_rdata, rdata);
        return (ret == KNOT_EOK && res == 0);
}

bool knot_match_key_ds(zone_key_t *key, const knot_rdata_t *rdata)
{
        dnssec_binary_t rdata_bin = {
                .data = knot_rdata_data(rdata),
		.size = knot_rdata_rdlen(rdata)
	};
        return cds_rdata_match(key, &rdata_bin);
}

/*!
 * \brief Check if DNSKEY/DS is present in public zone key set.
 */
static bool is_from_keyset(zone_keyset_t *keyset,
                           const knot_rdata_t *record,
                           bool is_ds, // otherwise, it's DNSKEY
                           bool is_cds_cdnskey, // in this case we match only ready keys
                           zone_key_t **matching_key) // out, optional
{
	assert(keyset);
	assert(record);

	dnssec_binary_t rdata = {
		.data = knot_rdata_data(record),
		.size = knot_rdata_rdlen(record)
	};

	uint16_t tag = 0;
	bool (*match_fce)(zone_key_t *, const dnssec_binary_t *);
	if (is_ds) {
		wire_ctx_t wrdata = wire_ctx_init(rdata.data, rdata.size);
		tag = wire_ctx_read_u16(&wrdata); // key tag in DS is just at beginning of wire
		match_fce = cds_rdata_match;
	} else {
		dnssec_keytag(&rdata, &tag);
		match_fce = dnskey_rdata_match;
	}
	bool found = false;

	struct keyptr_dynarray keys = get_zone_keys(keyset, tag);

	for (size_t i = 0; i < keys.size; i++) {
		bool usekey = (is_cds_cdnskey ? (keys.arr(&keys)[i]->is_ready && !keys.arr(&keys)[i]->is_active) : keys.arr(&keys)[i]->is_public);
		if (usekey && match_fce(keys.arr(&keys)[i], &rdata)) {
			found = true;
			if (matching_key != NULL) {
				*matching_key = keys.arr(&keys)[i];
			}
			break;
		}
	}
	keyptr_dynarray_free(&keys);

	return found;
}

static int rrset_add_zone_key(knot_rrset_t *rrset,
                              zone_key_t *zone_key,
                              uint32_t ttl)
{
	assert(rrset);
	assert(zone_key);

	dnssec_binary_t dnskey_rdata = { 0 };
	dnssec_key_get_rdata(zone_key->key, &dnskey_rdata);

	return knot_rrset_add_rdata(rrset, dnskey_rdata.data,
	                            dnskey_rdata.size, ttl, NULL);
}

static int rrset_add_zone_ds(knot_rrset_t *rrset,
                             zone_key_t *zone_key,
                             uint32_t ttl)
{
	assert(rrset);
	assert(zone_key);

	dnssec_binary_t cds_rdata = { 0 };
	zone_key_calculate_ds(zone_key, &cds_rdata);

	return knot_rrset_add_rdata(rrset, cds_rdata.data,
	                            cds_rdata.size, ttl, NULL);
}

/*!
 * \brief Adds/removes DNSKEY (and CDNSKEY, CDS) records to zone according to zone keyset.
 *
 * \param update     Structure holding zone contents and to be updated with changes.
 * \param zone_keys  Keyset with private keys.
 * \param dnssec_ctx KASP context.
 *
 * \return KNOT_E*
 */
static int sign_update_dnskeys(zone_update_t *update, zone_keyset_t *zone_keys,
                               const kdnssec_ctx_t *dnssec_ctx)
{
        assert(update != NULL && zone_keys != NULL && dnssec_ctx != NULL);

	const zone_node_t *apex = update->new_cont->apex;
	knot_rrset_t dnskeys = node_rrset(apex, KNOT_RRTYPE_DNSKEY);
	knot_rrset_t cdnskeys = node_rrset(apex, KNOT_RRTYPE_CDNSKEY);
	knot_rrset_t cdss = node_rrset(apex, KNOT_RRTYPE_CDS);
	knot_rrset_t soa = node_rrset(apex, KNOT_RRTYPE_SOA);
	knot_rrset_t *add_dnskeys = NULL;
	knot_rrset_t *add_cdnskeys = NULL;
	knot_rrset_t *add_cdss = NULL;
	//knot_rrset_t rrsigs = node_rrset(apex, KNOT_RRTYPE_RRSIG);
	uint32_t dnskey_ttl = dnssec_ctx->policy->dnskey_ttl;
	if (knot_rrset_empty(&soa)) {
		return KNOT_EINVAL;
	}

	changeset_t ch;
	int ret = changeset_init(&ch, apex->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// remove invalid/old DNSKEYS
	knot_rrset_t to_remove;
	knot_rrset_init(&to_remove, apex->owner, KNOT_RRTYPE_DNSKEY, dnskeys.rclass);
	for (uint16_t i = 0; i < dnskeys.rrs.rr_count; i++) {
		const knot_rdata_t *r = knot_rdataset_at(&dnskeys.rrs, i);
		uint32_t r_ttl = knot_rdata_ttl(r);
		if (r_ttl == dnskey_ttl && is_from_keyset(zone_keys, r, false, false, NULL)) {
			continue;
		}

		ret = knot_rdataset_add(&to_remove.rrs, r, NULL);
		if (ret != KNOT_EOK) {
			break;
		}
	}
	if (!knot_rrset_empty(&to_remove) && ret == KNOT_EOK) {
		ret = changeset_add_removal(&ch, &to_remove, 0);
	}
	knot_rdataset_clear(&to_remove.rrs, NULL);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	// remove CDS and CDNSKEY if no submission
	if (!zone_has_key_sbm(dnssec_ctx)) {
		if (!knot_rrset_empty(&cdnskeys)) {
			ret = changeset_add_removal(&ch, &cdnskeys, 0);
		}
		if (ret == KNOT_EOK && !knot_rrset_empty(&cdss)) {
			ret = changeset_add_removal(&ch, &cdss, 0);
		}
	}

	// add DNSKEYs, CDNSKEYs and CDSs
	add_dnskeys = knot_rrset_new(apex->owner, KNOT_RRTYPE_DNSKEY, soa.rclass, NULL);
	add_cdnskeys = knot_rrset_new(apex->owner, KNOT_RRTYPE_CDNSKEY, soa.rclass, NULL);
	add_cdss = knot_rrset_new(apex->owner, KNOT_RRTYPE_CDS, soa.rclass, NULL);
	if (add_dnskeys == NULL || add_cdnskeys == NULL || add_cdss == NULL) {
		ret = KNOT_ENOMEM;
	}
	for (int i = 0; i < zone_keys->count && ret == KNOT_EOK; i++) {
		zone_key_t *key = &zone_keys->keys[i];
		if (!key->is_public) {
			continue;
		}

		ret = rrset_add_zone_key(add_dnskeys, key, dnskey_ttl);
		if (key->is_ready && !key->is_active && ret == KNOT_EOK) {
			ret = rrset_add_zone_key(add_cdnskeys, key, 0);
			if (ret == KNOT_EOK) {
				ret = rrset_add_zone_ds(add_cdss, key, 0);
			}
		}
	}

	knot_rrset_t *add_rrsets[3] = { add_dnskeys, add_cdnskeys, add_cdss };
	for (int i = 0; i < 3 && ret == KNOT_EOK; i++) {
		if (!knot_rrset_empty(add_rrsets[i])) {
			ret = changeset_add_addition(&ch, add_rrsets[i], 0);
		}
	}

	if (ret == KNOT_EOK) {
		ret = zone_update_apply_changeset_fix(update, &ch);
	}

cleanup:
	knot_rrset_free(&add_dnskeys, NULL);
	knot_rrset_free(&add_cdnskeys, NULL);
	knot_rrset_free(&add_cdss, NULL);
	changeset_clear(&ch);
	return ret;
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
static int rr_already_signed(const knot_rrset_t *rrset, trie_t *t,
                             bool *rr_signed)
{
	assert(rrset);
	assert(t);
	*rr_signed = false;
	// Create a key = RRSet owner converted to sortable format
	uint8_t lf[KNOT_DNAME_MAXLEN];
	knot_dname_lf(lf, rrset->owner, NULL);
	trie_val_t stored_info = (signed_info_t *)trie_get_try(t, (char *)lf+1,
	                                                      *lf);
	if (stored_info == NULL) {
		// Create new info struct
		signed_info_t *info = malloc(sizeof(signed_info_t));
		if (info == NULL) {
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
		*trie_get_ins(t, (char *)lf+1, *lf) = info;
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
static int sign_changeset_wrap(knot_rrset_t *chg_rrset, changeset_signing_data_t *args)
{
	// Find RR's node in zone, find out if we need to sign this RR
	const zone_node_t *node =
		zone_contents_find_node(args->zone, chg_rrset->owner);

	// If node is not in zone, all its RRSIGs were dropped - no-op
	if (node) {
		knot_rrset_t zone_rrset = node_rrset(node, chg_rrset->type);
		knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);

		bool should_sign = knot_zone_sign_rr_should_be_signed(node, &zone_rrset);

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
			                          args->dnssec_ctx,
			                          args->changeset);
		} else {
			/*
			 * If RRSet in zone DOES have RRSIGs although we
			 * should not sign it, DDNS-caused change to node/rr
			 * occurred and we have to drop all RRSIGs.
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
static int free_helper_trie_node(trie_val_t *val, void *d)
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
static void knot_zone_clear_sorted_changes(trie_t *t)
{
	if (t) {
		trie_apply(t, free_helper_trie_node, NULL);
	}
}

/*- public API ---------------------------------------------------------------*/

int knot_zone_sign(zone_update_t *update,
                   zone_keyset_t *zone_keys,
                   const kdnssec_ctx_t *dnssec_ctx,
                   knot_time_t *expire_at)
{
	if (!update || !zone_keys || !dnssec_ctx || !expire_at) {
		return KNOT_EINVAL;
	}

	int result;

	result = sign_update_dnskeys(update, zone_keys, dnssec_ctx);
	if (result != KNOT_EOK) {
		return result;
	}

	changeset_t ch;
	result = changeset_init(&ch, update->new_cont->apex->owner);
	if (result != KNOT_EOK) {
		return result;
	}

	knot_time_t normal_expire = 0;
	result = zone_tree_sign(update->new_cont->nodes, zone_keys, dnssec_ctx, &ch, &normal_expire);
	if (result != KNOT_EOK) {
		changeset_clear(&ch);
		return result;
	}

	knot_time_t nsec3_expire = 0;
	result = zone_tree_sign(update->new_cont->nsec3_nodes, zone_keys, dnssec_ctx,
				&ch, &nsec3_expire);
	if (result != KNOT_EOK) {
		changeset_clear(&ch);
		return result;
	}

	*expire_at = knot_time_min(normal_expire, nsec3_expire);

	result = zone_update_apply_changeset(update, &ch); // _fix not needed
	changeset_clear(&ch);

	return KNOT_EOK;
}

bool knot_zone_sign_soa_expired(const zone_contents_t *zone,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *dnssec_ctx)
{
	assert(zone);
	assert(zone_keys);
	assert(dnssec_ctx);

	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(&soa));
	return !all_signatures_exist(&soa, &rrsigs, zone_keys, dnssec_ctx);
}

static int sign_changeset(const zone_contents_t *zone,
                             const changeset_t *in_ch,
                             changeset_t *out_ch,
                             const zone_keyset_t *zone_keys,
                             const kdnssec_ctx_t *dnssec_ctx)
{
	if (zone == NULL || in_ch == NULL || out_ch == NULL) {
		return KNOT_EINVAL;
	}

	// Create args for wrapper function - trie for duplicate sigs
	changeset_signing_data_t args = {
		.zone = zone,
		.zone_keys = zone_keys,
		.dnssec_ctx = dnssec_ctx,
		.changeset = out_ch,
		.signed_tree = trie_create(NULL)
	};

	if (args.signed_tree == NULL) {
		return KNOT_ENOMEM;

	}
	changeset_iter_t itt;
	changeset_iter_all(&itt, in_ch);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr)) {
		int ret = sign_changeset_wrap(&rr, &args);
		if (ret != KNOT_EOK) {
			changeset_iter_clear(&itt);
			return ret;
		}
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	if (!knot_rrset_empty(in_ch->soa_from)) {
		int ret = sign_changeset_wrap(in_ch->soa_from, &args);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	if (!knot_rrset_empty(in_ch->soa_to)) {
		int ret = sign_changeset_wrap(in_ch->soa_to, &args);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	knot_zone_clear_sorted_changes(args.signed_tree);
	trie_free(args.signed_tree);

	return KNOT_EOK;
}

int knot_zone_sign_nsecs_in_changeset(const zone_keyset_t *zone_keys,
                                      const kdnssec_ctx_t *dnssec_ctx,
                                      changeset_t *changeset)
{
	if (zone_keys == NULL || dnssec_ctx == NULL || changeset == NULL) {
		return KNOT_EINVAL;
	}

	changeset_iter_t itt;
	changeset_iter_add(&itt, changeset);

	knot_rrset_t rr = changeset_iter_next(&itt);
	while (!knot_rrset_empty(&rr)) {
		if (rr.type == KNOT_RRTYPE_NSEC ||
		    rr.type == KNOT_RRTYPE_NSEC3 ||
		    rr.type == KNOT_RRTYPE_NSEC3PARAM) {
			int ret =  add_missing_rrsigs(&rr, NULL, zone_keys,
			                              dnssec_ctx, changeset);
			if (ret != KNOT_EOK) {
				changeset_iter_clear(&itt);
				return ret;
			}
		}
		rr = changeset_iter_next(&itt);
	}
	changeset_iter_clear(&itt);

	return KNOT_EOK;
}

bool knot_zone_sign_rr_should_be_signed(const zone_node_t *node,
                                        const knot_rrset_t *rrset)
{
	if (node == NULL || knot_rrset_empty(rrset)) {
		return false;
	}

	// We do not want to sign RRSIGs
	if (rrset->type == KNOT_RRTYPE_RRSIG) {
		return false;
	}

	// At delegation points we only want to sign NSECs and DSs
	if (node->flags & NODE_FLAGS_DELEG) {
		if (!(rrset->type == KNOT_RRTYPE_NSEC ||
		      rrset->type == KNOT_RRTYPE_DS)) {
			return false;
		}
	}

	// These RRs have their signatures stored in changeset already
	if ((node->flags & NODE_FLAGS_REMOVED_NSEC) &&
	    (rrset->type == KNOT_RRTYPE_NSEC || rrset->type == KNOT_RRTYPE_NSEC3)) {
		return false;
	}

	return true;
}

int knot_zone_sign_update(zone_update_t *update,
                          zone_keyset_t *zone_keys,
                          const kdnssec_ctx_t *dnssec_ctx,
                          knot_time_t *expire_at)
{
	if (update == NULL || zone_keys == NULL || dnssec_ctx == NULL || expire_at == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;


	ret = apply_prepare_to_sign(&update->a_ctx);
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* Check if the UPDATE changed DNSKEYs or NSEC3PARAM.
	 * If so, we have to sign the whole zone. */
	const bool full_sign = changeset_empty(&update->change) ||
			       apex_dnssec_changed(update);
	if (full_sign) {
		ret = knot_zone_sign(update, zone_keys, dnssec_ctx, expire_at);
	} else {
		changeset_t sec_ch;
		ret = changeset_init(&sec_ch, update->zone->name);
		if (ret != KNOT_EOK) {
			return ret;
		}
		ret = sign_changeset(update->new_cont, &update->change, &sec_ch, zone_keys, dnssec_ctx);
		if (ret == KNOT_EOK) {
			ret = zone_update_apply_changeset_fix(update, &sec_ch);
		}
		changeset_clear(&sec_ch);
	}

	return ret;
}

int knot_zone_sign_soa(zone_update_t *update,
		       const zone_keyset_t *zone_keys,
		       const kdnssec_ctx_t *dnssec_ctx)
{
	knot_rrset_t soa_to = node_rrset(update->new_cont->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t soa_rrsig = node_rrset(update->new_cont->apex, KNOT_RRTYPE_RRSIG);
	changeset_t ch;
	int ret = changeset_init(&ch, update->zone->name);
	if (ret == KNOT_EOK) {
		ret = force_resign_rrset(&soa_to, &soa_rrsig, zone_keys, dnssec_ctx, &ch);
		if (ret == KNOT_EOK) {
			ret = zone_update_apply_changeset_fix(update, &ch);
		}
	}
	changeset_clear(&ch);
	return ret;
}
