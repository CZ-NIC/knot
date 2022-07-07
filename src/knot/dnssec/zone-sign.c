/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <pthread.h>
#include <sys/types.h>

#include "libdnssec/error.h"
#include "libdnssec/key.h"
#include "libdnssec/keytag.h"
#include "libdnssec/sign.h"
#include "knot/common/log.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/key_records.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-sign.h"
#include "libknot/libknot.h"
#include "libknot/dynarray.h"
#include "contrib/wire_ctx.h"

typedef struct {
	node_t n;
	uint16_t type;
} type_node_t;

typedef struct {
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
	knot_rrset_init(&rrset, src->owner, type, src->rclass, src->ttl);
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

	return !knot_rrset_equal(&old_rr, &new_rr, false);
}

static bool apex_dnssec_changed(zone_update_t *update)
{
	if (update->zone->contents == NULL || update->new_cont == NULL) {
		return false;
	}
	return apex_rr_changed(update->zone->contents->apex,
			       update->new_cont->apex, KNOT_RRTYPE_DNSKEY) ||
	       apex_rr_changed(update->zone->contents->apex,
			       update->new_cont->apex, KNOT_RRTYPE_NSEC3PARAM);
}

/*- private API - signing of in-zone nodes -----------------------------------*/

/*!
 * \brief Check if there is a valid signature for a given RR set and key.
 *
 * \param covered         RR set with covered records.
 * \param rrsigs          RR set with RRSIGs.
 * \param key             Signing key.
 * \param ctx             Signing context.
 * \param policy          DNSSEC policy.
 * \param skip_crypto     All RRSIGs in this node have been verified, just check validity.
 * \param refresh         Consider RRSIG expired when gonna expire this soon.
 * \param found_invalid   Out: some matching but expired%invalid RRSIG found.
 * \param at              Out: RRSIG position.
 *
 * \return The signature exists and is valid.
 */
static bool valid_signature_exists(const knot_rrset_t *covered,
				   const knot_rrset_t *rrsigs,
				   const dnssec_key_t *key,
				   dnssec_sign_ctx_t *ctx,
				   const kdnssec_ctx_t *dnssec_ctx,
				   knot_timediff_t refresh,
				   bool skip_crypto,
				   int *found_invalid,
				   uint16_t *at)
{
	assert(key);

	if (knot_rrset_empty(rrsigs)) {
		return false;
	}

	uint16_t rrsigs_rdata_count = rrsigs->rrs.count;
	knot_rdata_t *rdata = rrsigs->rrs.rdata;
	bool found_valid = false;
	for (uint16_t i = 0; i < rrsigs_rdata_count; i++) {
		uint16_t rr_keytag = knot_rrsig_key_tag(rdata);
		uint16_t rr_covered = knot_rrsig_type_covered(rdata);
		uint8_t rr_algo = knot_rrsig_alg(rdata);
		rdata = knot_rdataset_next(rdata);

		uint16_t keytag = dnssec_key_get_keytag(key);
		uint8_t algo = dnssec_key_get_algorithm(key);
		if (rr_keytag != keytag || rr_algo != algo || rr_covered != covered->type) {
			continue;
		}

		int ret = knot_check_signature(covered, rrsigs, i, key, ctx,
					       dnssec_ctx, refresh, skip_crypto);
		if (ret == KNOT_EOK) {
			if (at != NULL) {
				*at = i;
			}
			if (found_invalid == NULL) {
				return true;
			} else {
				found_valid = true; // continue searching for invalid RRSIG
			}
		} else if (found_invalid != NULL) {
			*found_invalid = ret;
		}
	}

	return found_valid;
}

/*!
 * \brief Note earliest expiration of a signature.
 *
 * \param rrsig       RRSIG rdata.
 * \param now         Current 64-bit timestamp.
 * \param expires_at  Current earliest expiration, will be updated.
 */
static void note_earliest_expiration(const knot_rdata_t *rrsig, knot_time_t now,
                                     knot_time_t *expires_at)
{
	assert(rrsig);
	if (expires_at == NULL) {
		return;
	}

	uint32_t curr_rdata = knot_rrsig_sig_expiration(rrsig);
	knot_time_t current = knot_time_from_u32(curr_rdata, now);

	*expires_at = knot_time_min(current, *expires_at);
}

bool rrsig_covers_type(const knot_rrset_t *rrsig, uint16_t type)
{
	if (knot_rrset_empty(rrsig)) {
		return false;
	}
	assert(rrsig->type == KNOT_RRTYPE_RRSIG);
	knot_rdata_t *one_rr = rrsig->rrs.rdata;
	for (int i = 0; i < rrsig->rrs.count; i++) {
		if (type == knot_rrsig_type_covered(one_rr)) {
			return true;
		}
		one_rr = knot_rdataset_next(one_rr);
	}
	return false;
}

/*!
 * \brief Add missing RRSIGs into the changeset for adding.
 *
 * \note Also removes invalid RRSIGs.
 *
 * \param covered     RR set with covered records.
 * \param rrsigs      RR set with RRSIGs.
 * \param sign_ctx    Local zone signing context.
 * \param skip_crypto All RRSIGs in this node have been verified, just check validity.
 * \param changeset   Changeset to be updated.
 * \param update      Zone update to be updated. Exactly one of "changeset" and "update" must be NULL!
 * \param expires_at  Earliest RRSIG expiration.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int add_missing_rrsigs(const knot_rrset_t *covered,
                              const knot_rrset_t *rrsigs,
                              zone_sign_ctx_t *sign_ctx,
                              bool skip_crypto,
                              changeset_t *changeset,
                              zone_update_t *update,
                              knot_time_t *expires_at)
{
	assert(!knot_rrset_empty(covered));
	assert(sign_ctx);
	assert((bool)changeset != (bool)update);

	knot_rrset_t to_add = create_empty_rrsigs_for(covered);
	knot_rrset_t to_remove = create_empty_rrsigs_for(covered);
	int result = (!rrsig_covers_type(rrsigs, covered->type) ? KNOT_EOK :
	             knot_synth_rrsig(covered->type, &rrsigs->rrs, &to_remove.rrs, NULL));

	if (result == KNOT_EOK && sign_ctx->dnssec_ctx->offline_records.rrsig.rrs.count > 0 &&
	    knot_dname_cmp(sign_ctx->dnssec_ctx->offline_records.rrsig.owner, covered->owner) == 0 &&
	    rrsig_covers_type(&sign_ctx->dnssec_ctx->offline_records.rrsig, covered->type)) {
		result = knot_synth_rrsig(covered->type,
		    &sign_ctx->dnssec_ctx->offline_records.rrsig.rrs, &to_add.rrs, NULL);
		if (result == KNOT_EOK) {
			// don't remove what shall be added
			result = knot_rdataset_subtract(&to_remove.rrs, &to_add.rrs, NULL);
		}
		if (result == KNOT_EOK && !knot_rrset_empty(rrsigs)) {
			// don't add what's already present
			result = knot_rdataset_subtract(&to_add.rrs, &rrsigs->rrs, NULL);
		}
	}

	for (size_t i = 0; i < sign_ctx->count && result == KNOT_EOK; i++) {
		const zone_key_t *key = &sign_ctx->keys[i];
		if (!knot_zone_sign_use_key(key, covered)) {
			continue;
		}

		uint16_t valid_at;
		knot_timediff_t refresh = sign_ctx->dnssec_ctx->policy->rrsig_refresh_before +
		                          sign_ctx->dnssec_ctx->policy->rrsig_prerefresh;
		if (valid_signature_exists(covered, rrsigs, key->key, sign_ctx->sign_ctxs[i],
		                           sign_ctx->dnssec_ctx, refresh, skip_crypto, NULL, &valid_at)) {
			knot_rdata_t *valid_rr = knot_rdataset_at(&rrsigs->rrs, valid_at);
			result = knot_rdataset_remove(&to_remove.rrs, valid_rr, NULL);
			note_earliest_expiration(valid_rr, sign_ctx->dnssec_ctx->now, expires_at);
			continue;
		}
		result = knot_sign_rrset(&to_add, covered, key->key, sign_ctx->sign_ctxs[i],
		                         sign_ctx->dnssec_ctx, NULL, expires_at);
	}

	if (!knot_rrset_empty(&to_remove) && result == KNOT_EOK) {
		if (changeset != NULL) {
			result = changeset_add_removal(changeset, &to_remove, 0);
		} else {
			result = zone_update_remove(update, &to_remove);
		}
	}

	if (!knot_rrset_empty(&to_add) && result == KNOT_EOK) {
		if (changeset != NULL) {
			result = changeset_add_addition(changeset, &to_add, 0);
		} else {
			result = zone_update_add(update, &to_add);
		}
	}

	knot_rdataset_clear(&to_add.rrs, NULL);
	knot_rdataset_clear(&to_remove.rrs, NULL);

	return result;
}

static bool key_used(bool ksk, bool zsk, uint16_t type,
                     const knot_dname_t *owner, const knot_dname_t *zone_apex)
{
	if (knot_dname_cmp(owner, zone_apex) != 0) {
		return zsk;
	}
	switch (type) {
	case KNOT_RRTYPE_DNSKEY:
	case KNOT_RRTYPE_CDNSKEY:
	case KNOT_RRTYPE_CDS:
		return ksk;
	default:
		return zsk;
	}
}

int knot_validate_rrsigs(const knot_rrset_t *covered,
                         const knot_rrset_t *rrsigs,
                         zone_sign_ctx_t *sign_ctx,
                         bool skip_crypto)
{
	if (covered == NULL || rrsigs == NULL || sign_ctx == NULL) {
		return KNOT_EINVAL;
	}

	bool valid_exists = false;
	int ret = KNOT_EOK;
	for (size_t i = 0; i < sign_ctx->count; i++) {
		const knot_kasp_key_t *key = &sign_ctx->dnssec_ctx->zone->keys[i];
		if (!key_used(key->is_ksk, key->is_zsk, covered->type,
		              covered->owner, sign_ctx->dnssec_ctx->zone->dname)) {
			continue;
		}

		uint16_t valid_at;
		if (valid_signature_exists(covered, rrsigs, key->key, sign_ctx->sign_ctxs[i],
		                           sign_ctx->dnssec_ctx, 0, skip_crypto, &ret, &valid_at)) {
			valid_exists = true;
		}
	}

	return valid_exists ? ret : KNOT_DNSSEC_ENOSIG;
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
	                KNOT_RRTYPE_RRSIG, rrsigs->rclass, rrsigs->ttl);
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
 * \param rrsigs     Existing RRSIGs for covered RR set.
 * \param sign_ctx   Local zone signing context.
 * \param changeset  Changeset to be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int force_resign_rrset(const knot_rrset_t *covered,
                              const knot_rrset_t *rrsigs,
                              zone_sign_ctx_t *sign_ctx,
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

	return add_missing_rrsigs(covered, NULL, sign_ctx, false, changeset, NULL, NULL);
}

/*!
 * \brief Drop all expired and create new RRSIGs for covered records.
 *
 * \param covered     RR set with covered records.
 * \param rrsigs      Existing RRSIGs for covered RR set.
 * \param sign_ctx    Local zone signing context.
 * \param skip_crypto All RRSIGs in this node have been verified, just check validity.
 * \param changeset   Changeset to be updated.
 * \param expires_at  Current earliest expiration, will be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int resign_rrset(const knot_rrset_t *covered,
                        const knot_rrset_t *rrsigs,
                        zone_sign_ctx_t *sign_ctx,
                        bool skip_crypto,
                        changeset_t *changeset,
                        knot_time_t *expires_at)
{
	assert(!knot_rrset_empty(covered));

	return add_missing_rrsigs(covered, rrsigs, sign_ctx, skip_crypto, changeset, NULL, expires_at);
}

static int remove_standalone_rrsigs(const zone_node_t *node,
                                    const knot_rrset_t *rrsigs,
                                    changeset_t *changeset)
{
	if (rrsigs == NULL) {
		return KNOT_EOK;
	}

	uint16_t rrsigs_rdata_count = rrsigs->rrs.count;
	knot_rdata_t *rdata = rrsigs->rrs.rdata;
	for (uint16_t i = 0; i < rrsigs_rdata_count; ++i) {
		uint16_t type_covered = knot_rrsig_type_covered(rdata);
		if (!node_rrtype_exists(node, type_covered)) {
			knot_rrset_t to_remove;
			knot_rrset_init(&to_remove, rrsigs->owner, rrsigs->type,
			                rrsigs->rclass, rrsigs->ttl);
			int ret = knot_rdataset_add(&to_remove.rrs, rdata, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
			ret = changeset_add_removal(changeset, &to_remove, 0);
			knot_rdataset_clear(&to_remove.rrs, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
		rdata = knot_rdataset_next(rdata);
	}

	return KNOT_EOK;
}

/*!
 * \brief Update RRSIGs in a given node by updating changeset.
 *
 * \param node        Node to be signed.
 * \param sign_ctx    Local zone signing context.
 * \param changeset   Changeset to be updated.
 * \param expires_at  Current earliest expiration, will be updated.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int sign_node_rrsets(const zone_node_t *node,
                            zone_sign_ctx_t *sign_ctx,
                            changeset_t *changeset,
                            knot_time_t *expires_at,
                            dnssec_validation_hint_t *hint)
{
	assert(node);
	assert(sign_ctx);

	int result = KNOT_EOK;
	knot_rrset_t rrsigs = node_rrset(node, KNOT_RRTYPE_RRSIG);
	bool skip_crypto = (node->flags & NODE_FLAGS_RRSIGS_VALID) &&
	                   !sign_ctx->dnssec_ctx->keytag_conflict;

	for (int i = 0; result == KNOT_EOK && i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		assert(rrset.type != KNOT_RRTYPE_ANY);

		if (!knot_zone_sign_rr_should_be_signed(node, &rrset)) {
			if (!sign_ctx->dnssec_ctx->validation_mode) {
				result = remove_rrset_rrsigs(rrset.owner, rrset.type, &rrsigs, changeset);
			} else {
				if (knot_synth_rrsig_exists(rrset.type, &rrsigs.rrs)) {
					hint->node = node->owner;
					hint->rrtype = rrset.type;
					result = KNOT_DNSSEC_ENOSIG;
				}
			}
			continue;
		}

		if (sign_ctx->dnssec_ctx->validation_mode) {
			result = knot_validate_rrsigs(&rrset, &rrsigs, sign_ctx, skip_crypto);
			if (result != KNOT_EOK) {
				hint->node = node->owner;
				hint->rrtype = rrset.type;
			}
		} else if (sign_ctx->dnssec_ctx->rrsig_drop_existing) {
			result = force_resign_rrset(&rrset, &rrsigs,
			                            sign_ctx, changeset);
		} else {
			result = resign_rrset(&rrset, &rrsigs, sign_ctx, skip_crypto,
			                      changeset, expires_at);
		}
	}

	if (result == KNOT_EOK) {
		result = remove_standalone_rrsigs(node, &rrsigs, changeset);
	}
	return result;
}

/*!
 * \brief Struct to carry data for 'sign_data' callback function.
 */
typedef struct {
	zone_tree_t *tree;
	zone_sign_ctx_t *sign_ctx;
	changeset_t changeset;
	knot_time_t expires_at;
	dnssec_validation_hint_t *hint;
	size_t num_threads;
	size_t thread_index;
	size_t rrset_index;
	int errcode;
	int thread_init_errcode;
	pthread_t thread;
} node_sign_args_t;

/*!
 * \brief Sign node (callback function).
 *
 * \param node  Node to be signed.
 * \param data  Callback data, node_sign_args_t.
 */
static int sign_node(zone_node_t *node, void *data)
{
	assert(node);
	assert(data);

	node_sign_args_t *args = (node_sign_args_t *)data;

	if (node->rrset_count == 0) {
		return KNOT_EOK;
	}

	if (args->rrset_index++ % args->num_threads != args->thread_index) {
		return KNOT_EOK;
	}

	int result = sign_node_rrsets(node, args->sign_ctx,
	                              &args->changeset, &args->expires_at,
	                              args->hint);

	return result;
}

static void *tree_sign_thread(void *_arg)
{
	node_sign_args_t *arg = _arg;
	arg->errcode = zone_tree_apply(arg->tree, sign_node, _arg);
	return NULL;
}

static int set_signed(zone_node_t *node, _unused_ void *data)
{
	node->flags |= NODE_FLAGS_RRSIGS_VALID;
	return KNOT_EOK;
}

/*!
 * \brief Update RRSIGs in a given zone tree by updating changeset.
 *
 * \param tree        Zone tree to be signed.
 * \param num_threads Number of threads to use for parallel signing.
 * \param zone_keys   Zone keys.
 * \param policy      DNSSEC policy.
 * \param update      Zone update structure to be updated.
 * \param expires_at  Expiration time of the oldest signature in zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int zone_tree_sign(zone_tree_t *tree,
                          size_t num_threads,
                          zone_keyset_t *zone_keys,
                          const kdnssec_ctx_t *dnssec_ctx,
                          zone_update_t *update,
                          knot_time_t *expires_at)
{
	assert(zone_keys || dnssec_ctx->validation_mode);
	assert(dnssec_ctx);
	assert(update || dnssec_ctx->validation_mode);

	int ret = KNOT_EOK;
	node_sign_args_t args[num_threads];
	memset(args, 0, sizeof(args));
	*expires_at = knot_time_plus(dnssec_ctx->now, dnssec_ctx->policy->rrsig_lifetime);

	// init context structures
	for (size_t i = 0; i < num_threads; i++) {
		args[i].tree = tree;
		args[i].sign_ctx = dnssec_ctx->validation_mode
		                 ? zone_validation_ctx(dnssec_ctx)
		                 : zone_sign_ctx(zone_keys, dnssec_ctx);
		if (args[i].sign_ctx == NULL) {
			ret = KNOT_ENOMEM;
			break;
		}
		ret = changeset_init(&args[i].changeset, dnssec_ctx->zone->dname);
		if (ret != KNOT_EOK) {
			break;
		}
		args[i].expires_at = 0;
		args[i].hint = &update->validation_hint;
		args[i].num_threads = num_threads;
		args[i].thread_index = i;
		args[i].rrset_index = 0;
		args[i].errcode = KNOT_EOK;
		args[i].thread_init_errcode = -1;
	}
	if (ret != KNOT_EOK) {
		for (size_t i = 0; i < num_threads; i++) {
			changeset_clear(&args[i].changeset);
			zone_sign_ctx_free(args[i].sign_ctx);
		}
		return ret;
	}

	if (num_threads == 1) {
		args[0].thread_init_errcode = 0;
		tree_sign_thread(&args[0]);
	} else {
		// start working threads
		for (size_t i = 0; i < num_threads; i++) {
			args[i].thread_init_errcode =
				pthread_create(&args[i].thread, NULL, tree_sign_thread, &args[i]);
		}

		// join those threads that have been really started
		for (size_t i = 0; i < num_threads; i++) {
			if (args[i].thread_init_errcode == 0) {
				args[i].thread_init_errcode = pthread_join(args[i].thread, NULL);
			}
		}
	}

	// collect return code and results
	for (size_t i = 0; i < num_threads; i++) {
		if (ret == KNOT_EOK) {
			if (args[i].thread_init_errcode != 0) {
				ret = knot_map_errno_code(args[i].thread_init_errcode);
			} else {
				ret = args[i].errcode;
				if (ret == KNOT_EOK && !dnssec_ctx->validation_mode) {
					ret = zone_update_apply_changeset(update, &args[i].changeset); // _fix not needed
					*expires_at = knot_time_min(*expires_at, args[i].expires_at);
				}
			}
		}
		assert(!dnssec_ctx->validation_mode || changeset_empty(&args[i].changeset));
		changeset_clear(&args[i].changeset);
		zone_sign_ctx_free(args[i].sign_ctx);
	}

	return ret;
}

/*- private API - signing of NSEC(3) in changeset ----------------------------*/

/*!
 * \brief Struct to carry data for changeset signing callback functions.
 */
typedef struct {
	const zone_contents_t *zone;
	changeset_iter_t itt;
	zone_sign_ctx_t *sign_ctx;
	changeset_t changeset;
	knot_time_t expires_at;
	size_t num_threads;
	size_t thread_index;
	size_t rrset_index;
	int errcode;
	int thread_init_errcode;
	pthread_t thread;
} changeset_signing_data_t;

int rrset_add_zone_key(knot_rrset_t *rrset, zone_key_t *zone_key)
{
	if (rrset == NULL || zone_key == NULL) {
		return KNOT_EINVAL;
	}

	dnssec_binary_t dnskey_rdata = { 0 };
	dnssec_key_get_rdata(zone_key->key, &dnskey_rdata);

	return knot_rrset_add_rdata(rrset, dnskey_rdata.data, dnskey_rdata.size, NULL);
}

static int rrset_add_zone_ds(knot_rrset_t *rrset, zone_key_t *zone_key, dnssec_key_digest_t dt)
{
	assert(rrset);
	assert(zone_key);

	dnssec_binary_t cds_rdata = { 0 };
	zone_key_calculate_ds(zone_key, dt, &cds_rdata);

	return knot_rrset_add_rdata(rrset, cds_rdata.data, cds_rdata.size, NULL);
}

int knot_zone_sign(zone_update_t *update,
                   zone_keyset_t *zone_keys,
                   const kdnssec_ctx_t *dnssec_ctx,
                   knot_time_t *expire_at)
{
	if (!update || !dnssec_ctx || !expire_at ||
	    dnssec_ctx->policy->signing_threads < 1 ||
	    (zone_keys == NULL && !dnssec_ctx->validation_mode)) {
		return KNOT_EINVAL;
	}

	int result;

	knot_time_t normal_expire = 0;
	result = zone_tree_sign(update->new_cont->nodes, dnssec_ctx->policy->signing_threads,
	                        zone_keys, dnssec_ctx, update, &normal_expire);
	if (result != KNOT_EOK) {
		return result;
	}

	knot_time_t nsec3_expire = 0;
	result = zone_tree_sign(update->new_cont->nsec3_nodes, dnssec_ctx->policy->signing_threads,
	                        zone_keys, dnssec_ctx, update, &nsec3_expire);
	if (result != KNOT_EOK) {
		return result;
	}

	bool whole = !(update->flags & UPDATE_INCREMENTAL);
	result = zone_tree_apply(whole ? update->new_cont->nodes : update->a_ctx->node_ptrs, set_signed, NULL);
	if (result == KNOT_EOK) {
		result = zone_tree_apply(whole ? update->new_cont->nsec3_nodes : update->a_ctx->nsec3_ptrs, set_signed, NULL);
	}

	*expire_at = knot_time_min(normal_expire, nsec3_expire);

	return result;
}

keyptr_dynarray_t knot_zone_sign_get_cdnskeys(const kdnssec_ctx_t *ctx,
					      zone_keyset_t *zone_keys)
{
	keyptr_dynarray_t r = { 0 };
	unsigned crp = ctx->policy->cds_cdnskey_publish;
	unsigned cds_published = 0;
	uint8_t ready_alg = 0;

	if (crp == CDS_CDNSKEY_ROLLOVER || crp == CDS_CDNSKEY_ALWAYS ||
	    crp == CDS_CDNSKEY_DOUBLE_DS) {
		// first, add strictly-ready keys
		for (int i = 0; i < zone_keys->count; i++) {
			zone_key_t *key = &zone_keys->keys[i];
			if (key->is_ready) {
				assert(key->is_ksk);
				ready_alg = dnssec_key_get_algorithm(key->key);
				keyptr_dynarray_add(&r, &key);
				if (!key->is_pub_only) {
					cds_published++;
				}
			}
		}

		// second, add active keys
		if ((crp == CDS_CDNSKEY_ALWAYS && cds_published == 0) ||
		    (crp == CDS_CDNSKEY_DOUBLE_DS)) {
			for (int i = 0; i < zone_keys->count; i++) {
				zone_key_t *key = &zone_keys->keys[i];
				if (key->is_ksk && key->is_active && !key->is_ready &&
				    (cds_published == 0 || ready_alg == dnssec_key_get_algorithm(key->key))) {
					keyptr_dynarray_add(&r, &key);
				}
			}
		}

		if ((crp != CDS_CDNSKEY_DOUBLE_DS && cds_published > 1) ||
		    (cds_published > 2)) {
			log_zone_warning(ctx->zone->dname, "DNSSEC, published CDS/CDNSKEY records for too many (%u) keys", cds_published);
		}
	}

	return r;
}

int knot_zone_sign_add_dnskeys(zone_keyset_t *zone_keys, const kdnssec_ctx_t *dnssec_ctx,
                               key_records_t *add_r, key_records_t *rem_r, key_records_t *orig_r)
{
	if (add_r == NULL || (rem_r != NULL && orig_r == NULL)) {
		return KNOT_EINVAL;
	}

	bool incremental = (dnssec_ctx->policy->incremental && rem_r != NULL);
	dnssec_key_digest_t cds_dt = dnssec_ctx->policy->cds_dt;
	int ret = KNOT_EOK;

	for (int i = 0; i < zone_keys->count; i++) {
		zone_key_t *key = &zone_keys->keys[i];
		if (key->is_public) {
			ret = rrset_add_zone_key(&add_r->dnskey, key);
		} else if (incremental) {
			ret = rrset_add_zone_key(&rem_r->dnskey, key);
		}

		// add all possible known CDNSKEYs and CDSs to removals. Sort it out later
		if (incremental && ret == KNOT_EOK) {
			ret = rrset_add_zone_key(&rem_r->cdnskey, key);
		}
		if (incremental && ret == KNOT_EOK) {
			ret = rrset_add_zone_ds(&rem_r->cds, key, cds_dt);
		}

		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	keyptr_dynarray_t kcdnskeys = knot_zone_sign_get_cdnskeys(dnssec_ctx, zone_keys);
	knot_dynarray_foreach(keyptr, zone_key_t *, ksk_for_cds, kcdnskeys) {
		ret = rrset_add_zone_key(&add_r->cdnskey, *ksk_for_cds);
		if (ret == KNOT_EOK) {
			ret = rrset_add_zone_ds(&add_r->cds, *ksk_for_cds, cds_dt);
		}
	}

	if (incremental && ret == KNOT_EOK) { // else rem_r is empty
		ret = key_records_subtract(rem_r, add_r);
		if (ret == KNOT_EOK) {
			ret = key_records_intersect(rem_r, orig_r);
		}
		if (ret == KNOT_EOK) {
			ret = key_records_subtract(add_r, orig_r);
		}
	}

	if (dnssec_ctx->policy->cds_cdnskey_publish == CDS_CDNSKEY_EMPTY && ret == KNOT_EOK) {
		const uint8_t cdnskey_empty[5] = { 0, 0, 3, 0, 0 };
		const uint8_t cds_empty[5] = { 0, 0, 0, 0, 0 };
		ret = knot_rrset_add_rdata(&add_r->cdnskey, cdnskey_empty, sizeof(cdnskey_empty), NULL);
		if (ret == KNOT_EOK) {
			ret = knot_rrset_add_rdata(&add_r->cds, cds_empty, sizeof(cds_empty), NULL);
		}
	}

	keyptr_dynarray_free(&kcdnskeys);
	return ret;
}

int knot_zone_sign_update_dnskeys(zone_update_t *update,
                                  zone_keyset_t *zone_keys,
                                  kdnssec_ctx_t *dnssec_ctx)
{
	if (update == NULL || zone_keys == NULL || dnssec_ctx == NULL) {
		return KNOT_EINVAL;
	}

	if (dnssec_ctx->policy->unsafe & UNSAFE_DNSKEY) {
		return KNOT_EOK;
	}

	const zone_node_t *apex = update->new_cont->apex;
	knot_rrset_t soa = node_rrset(apex, KNOT_RRTYPE_SOA);
	if (knot_rrset_empty(&soa)) {
		return KNOT_EINVAL;
	}

	key_records_t orig_r;
	key_records_from_apex(apex, &orig_r);

	changeset_t ch;
	int ret = changeset_init(&ch, apex->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (!dnssec_ctx->policy->incremental) {
		// remove all. This will cancel out with additions later
		ret = key_records_to_changeset(&orig_r, &ch, true, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	key_records_t add_r, rem_r;
	key_records_init(dnssec_ctx, &add_r);
	key_records_init(dnssec_ctx, &rem_r);

#define CHECK_RET if (ret != KNOT_EOK) goto cleanup

	if (dnssec_ctx->policy->offline_ksk) {
		key_records_t *r = &dnssec_ctx->offline_records;
		log_zone_info(dnssec_ctx->zone->dname,
		              "DNSSEC, using offline records, DNSKEYs %hu, CDNSKEYs %hu, CDs %hu, RRSIGs %hu",
		              r->dnskey.rrs.count, r->cdnskey.rrs.count, r->cds.rrs.count, r->rrsig.rrs.count);
		ret = key_records_to_changeset(r, &ch, false, CHANGESET_CHECK);
		CHECK_RET;
	} else {
		ret = knot_zone_sign_add_dnskeys(zone_keys, dnssec_ctx, &add_r, &rem_r, &orig_r);
		CHECK_RET;
		ret = key_records_to_changeset(&rem_r, &ch, true, CHANGESET_CHECK);
		CHECK_RET;
		ret = key_records_to_changeset(&add_r, &ch, false, CHANGESET_CHECK);
		CHECK_RET;
	}

	if (dnssec_ctx->policy->ds_push && node_rrtype_exists(ch.add->apex, KNOT_RRTYPE_CDS)) {
		// there is indeed a change to CDS
		update->zone->timers.next_ds_push = time(NULL) + dnssec_ctx->policy->propagation_delay;
		zone_events_schedule_at(update->zone, ZONE_EVENT_DS_PUSH, update->zone->timers.next_ds_push);
	}

	ret = zone_update_apply_changeset(update, &ch);

#undef CHECK_RET

cleanup:
	key_records_clear(&add_r);
	key_records_clear(&rem_r);
	changeset_clear(&ch);
	return ret;
}

bool knot_zone_sign_use_key(const zone_key_t *key, const knot_rrset_t *covered)
{
	if (key == NULL || covered == NULL) {
		return false;
	}

	bool active_ksk = ((key->is_active || key->is_ksk_active_plus) && key->is_ksk);
	bool active_zsk = ((key->is_active || key->is_zsk_active_plus) && key->is_zsk);;

	// this may be a problem with offline KSK
	bool cds_sign_by_ksk = true;

	assert(key->is_zsk || key->is_ksk);
	bool is_apex = knot_dname_is_equal(covered->owner,
	                                   dnssec_key_get_dname(key->key));
	if (!is_apex) {
		return active_zsk;
	}

	switch (covered->type) {
	case KNOT_RRTYPE_DNSKEY:
		return active_ksk;
	case KNOT_RRTYPE_CDS:
	case KNOT_RRTYPE_CDNSKEY:
		return (cds_sign_by_ksk ? active_ksk : active_zsk);
	default:
		return active_zsk;
	}
}

static int sign_in_changeset(zone_node_t *node, uint16_t rrtype, knot_rrset_t *rrsigs,
                             zone_sign_ctx_t *sign_ctx, int ret_prev,
                             bool skip_crypto, zone_update_t *up)
{
	if (ret_prev != KNOT_EOK) {
		return ret_prev;
	}
	knot_rrset_t rr = node_rrset(node, rrtype);
	if (knot_rrset_empty(&rr)) {
		return KNOT_EOK;
	}
	return add_missing_rrsigs(&rr, rrsigs, sign_ctx, skip_crypto, NULL, up, NULL);
}

int knot_zone_sign_nsecs_in_changeset(const zone_keyset_t *zone_keys,
                                      const kdnssec_ctx_t *dnssec_ctx,
                                      zone_update_t *update)
{
	if (zone_keys == NULL || dnssec_ctx == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	zone_sign_ctx_t *sign_ctx = zone_sign_ctx(zone_keys, dnssec_ctx);
	if (sign_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	zone_tree_it_t it = { 0 };
	int ret = zone_tree_it_double_begin(update->a_ctx->node_ptrs, update->a_ctx->nsec3_ptrs, &it);

	while (!zone_tree_it_finished(&it) && ret == KNOT_EOK) {
		zone_node_t *n = zone_tree_it_val(&it);
		bool skip_crypto = (n->flags & NODE_FLAGS_RRSIGS_VALID) && !dnssec_ctx->keytag_conflict;

		knot_rrset_t rrsigs = node_rrset(n, KNOT_RRTYPE_RRSIG);
		ret = sign_in_changeset(n, KNOT_RRTYPE_NSEC, &rrsigs, sign_ctx, ret, skip_crypto, update);
		ret = sign_in_changeset(n, KNOT_RRTYPE_NSEC3, &rrsigs, sign_ctx, ret, skip_crypto, update);
		ret = sign_in_changeset(n, KNOT_RRTYPE_NSEC3PARAM, &rrsigs, sign_ctx, ret, skip_crypto, update);

		if (ret == KNOT_EOK) {
			n->flags |= NODE_FLAGS_RRSIGS_VALID; // non-NSEC RRSIGs had been validated in knot_dnssec_sign_update()
		}

		zone_tree_it_next(&it);
	}
	zone_tree_it_free(&it);
	zone_sign_ctx_free(sign_ctx);

	return ret;
}

bool knot_zone_sign_rr_should_be_signed(const zone_node_t *node,
                                        const knot_rrset_t *rrset)
{
	if (node == NULL || knot_rrset_empty(rrset)) {
		return false;
	}

	if (rrset->type == KNOT_RRTYPE_RRSIG || (node->flags & NODE_FLAGS_NONAUTH)) {
		return false;
	}

	// At delegation points we only want to sign NSECs and DSs
	if (node->flags & NODE_FLAGS_DELEG) {
		if (!(rrset->type == KNOT_RRTYPE_NSEC ||
		      rrset->type == KNOT_RRTYPE_DS)) {
			return false;
		}
	}

	return true;
}

int knot_zone_sign_update(zone_update_t *update,
                          zone_keyset_t *zone_keys,
                          const kdnssec_ctx_t *dnssec_ctx,
                          knot_time_t *expire_at)
{
	if (update == NULL || dnssec_ctx == NULL || expire_at == NULL ||
	    dnssec_ctx->policy->signing_threads < 1 ||
	    (zone_keys == NULL && !dnssec_ctx->validation_mode)) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	/* Check if the UPDATE changed DNSKEYs or NSEC3PARAM.
	 * If so, we have to sign the whole zone. */
	const bool full_sign = apex_dnssec_changed(update);
	if (full_sign) {
		ret = knot_zone_sign(update, zone_keys, dnssec_ctx, expire_at);
	} else {
		ret = zone_tree_sign(update->a_ctx->node_ptrs, dnssec_ctx->policy->signing_threads,
				     zone_keys, dnssec_ctx, update, expire_at);
		if (ret == KNOT_EOK) {
			ret = zone_tree_apply(update->a_ctx->node_ptrs, set_signed, NULL);
		}
		if (ret == KNOT_EOK && dnssec_ctx->validation_mode) {
			ret = zone_tree_sign(update->a_ctx->nsec3_ptrs, dnssec_ctx->policy->signing_threads,
			                     zone_keys, dnssec_ctx, update, expire_at);
		}
		if (ret == KNOT_EOK && dnssec_ctx->validation_mode) {
			ret = zone_tree_apply(update->a_ctx->nsec3_ptrs, set_signed, NULL);
		}
	}

	return ret;
}

int knot_zone_sign_apex_rr(zone_update_t *update, uint16_t rrtype,
                           const zone_keyset_t *zone_keys,
                           const kdnssec_ctx_t *dnssec_ctx)
{
	knot_rrset_t rr = node_rrset(update->new_cont->apex, rrtype);
	knot_rrset_t rrsig = node_rrset(update->new_cont->apex, KNOT_RRTYPE_RRSIG);
	changeset_t ch;
	int ret = changeset_init(&ch, update->zone->name);
	if (ret == KNOT_EOK) {
		zone_sign_ctx_t *sign_ctx = zone_sign_ctx(zone_keys, dnssec_ctx);
		if (sign_ctx == NULL) {
			changeset_clear(&ch);
			return KNOT_ENOMEM;
		}
		ret = force_resign_rrset(&rr, &rrsig, sign_ctx, &ch);
		if (ret == KNOT_EOK) {
			ret = zone_update_apply_changeset(update, &ch);
		}
		zone_sign_ctx_free(sign_ctx);
	}
	changeset_clear(&ch);
	return ret;
}
