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
#include <stdio.h> // TMP
#include <sys/types.h>
#include <time.h>
#include "common/descriptor.h"
#include "common/errcode.h"
#include "common/hattrie/hat-trie.h"
#include "libknot/dname.h"
#include "libknot/dnssec/key.h"
#include "libknot/dnssec/policy.h"
#include "libknot/dnssec/sign.h"
#include "libknot/dnssec/zone-keys.h"
#include "libknot/rrset.h"
#include "libknot/updates/changesets.h"
#include "libknot/zone/node.h"
#include "libknot/zone/zone-contents.h"

//! \todo Check if defined elsewhere.
#define MAX_RR_WIREFORMAT_SIZE (64 * 1024 * sizeof(uint8_t))
#define RRSIG_RDATA_OFFSET 18

static uint32_t time_now(void)
{
	return (uint32_t)time(NULL);
}

// COPIED FROM SIG(0) AND MODIFIED
static size_t rrsig_rdata_size(const knot_dnssec_key_t *key)
{
	assert(key);

	size_t size;

	// static part

	size = sizeof(uint16_t)		// type covered
	     + sizeof(uint8_t)		// algorithm
	     + sizeof(uint8_t)		// labels
	     + sizeof(uint32_t)		// original TTL
	     + sizeof(uint32_t)		// signature expiration
	     + sizeof(uint32_t)		// signature inception
	     + sizeof(uint16_t);	// key tag (footprint)

	// variable part

	size += sizeof(knot_dname_t *); // pointer to signer
	size += knot_dnssec_sign_size(key);

	return size;
}

// COPIED FROM SIG(0) AND MODIFIED
static void rrsig_write_rdata(uint8_t *rdata,
                              const knot_dnssec_key_t *key,
                              const knot_dname_t *owner,
                              const knot_rrset_t *covered,
                              uint32_t sig_incepted,
                              uint32_t sig_expires)
{
	assert(key);
	assert(rdata);

	uint8_t *w = rdata;

	uint8_t owner_labels = knot_dname_labels(owner, NULL);
	if (knot_dname_is_wildcard(owner))
		owner_labels -= 1;

	knot_wire_write_u16(w, covered->type);	// type covered
	w += sizeof(uint16_t);
	*w = key->algorithm;			// algorithm
	w += sizeof(uint8_t);
	*w = owner_labels;			// labels
	w += sizeof(uint8_t);
	knot_wire_write_u32(w, covered->ttl);	// original TTL
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_expires);	// signature expiration
	w += sizeof(uint32_t);
	knot_wire_write_u32(w, sig_incepted);	// signature inception
	w += sizeof(uint32_t);
	knot_wire_write_u16(w, key->keytag);	// key footprint
	w += sizeof(uint16_t);

	assert(w == rdata + 18);

	// dname must be copied, no pointer copying now!
	knot_dname_t *dname = knot_dname_copy(key->name);
	memcpy(w, &dname, sizeof(knot_dname_t *)); // pointer to signer
}

static int sign_rrset_one(knot_rrset_t *rrsigs,
                          const knot_rrset_t *covered,
                          const knot_dnssec_key_t *key,
                          knot_dnssec_sign_context_t *sign_ctx,
                          const knot_dnssec_policy_t *policy)
{
	uint8_t *rdata = knot_rrset_create_rdata(rrsigs, rrsig_rdata_size(key));
	if (!rdata)
		return KNOT_ENOMEM;

	uint32_t sig_incept = policy->now;
	uint32_t sig_expire = sig_incept + policy->sign_lifetime;

	rrsig_write_rdata(rdata, key, knot_rrset_owner(covered), covered,
	                  sig_incept, sig_expire);

	// RFC 4034: The signature covers RRSIG RDATA field (excluding the
	// signature) and all matching RR records, which are ordered
	// canonically.

	int result = knot_dnssec_sign_new(sign_ctx);
	if (result != KNOT_EOK)
		return result;

	// static
	result = knot_dnssec_sign_add(sign_ctx, rdata, RRSIG_RDATA_OFFSET);
	if (result != KNOT_EOK)
		return result;
	result = knot_dnssec_sign_add(sign_ctx, key->name,
	                              knot_dname_size(key->name));
	if (result != KNOT_EOK)
		return result;

	// huge block of rrsets can be optionally created
	uint8_t *rrwf = malloc(MAX_RR_WIREFORMAT_SIZE);
	if (!rrwf)
		return KNOT_ENOMEM;

	uint16_t rr_count = knot_rrset_rdata_rr_count(covered);
	for (uint16_t i = 0; i < rr_count; i++) {
		size_t rr_size;
		result = knot_rrset_to_wire_one(covered, i, rrwf,
		                                MAX_RR_WIREFORMAT_SIZE,
		                                &rr_size, NULL);
		if (result != KNOT_EOK) {
			free(rrwf);
			return result;
		}

		result = knot_dnssec_sign_add(sign_ctx, rrwf, rr_size);
		if (result != KNOT_EOK)
			return result;
	}

	uint8_t *rdata_signature =
		rdata + RRSIG_RDATA_OFFSET + sizeof(knot_dname_t *);
	result = knot_dnssec_sign_write(sign_ctx, rdata_signature);

	free(rrwf);

	return result;
}

static knot_rrset_t *create_empty_rrsigs_for(const knot_rrset_t *covered)
{
	assert(covered);

	// Owner must be copied
	knot_dname_t *owner_copy = knot_dname_copy(knot_rrset_owner(covered));
	return knot_rrset_new(owner_copy, KNOT_RRTYPE_RRSIG,
	                      knot_rrset_class(covered),
	                      knot_rrset_ttl(covered));
}

static bool is_valid_signature(const knot_rrset_t *rrsigs, size_t pos,
			       const knot_dnssec_policy_t *policy)
{
	assert(rrsigs);
	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(policy);

	// Check expiration.
	uint32_t now = policy->now;
	uint32_t refresh = policy->sign_refresh;
	uint32_t expiration = knot_rrset_rdata_rrsig_sig_expiration(rrsigs, pos);

	return expiration - refresh > now;
}

static bool full_sig_check(const knot_rrset_t *covered,
                           const knot_rrset_t *rrsigs, size_t pos,
                           const knot_dnssec_key_t *key,
                           knot_dnssec_sign_context_t *ctx,
                           const knot_dnssec_policy_t *policy)
{
	assert(rrsigs && covered && policy);
	if (key == NULL || ctx == NULL) {
		return false;
	}
	// Do cheaper check first
	if (!is_valid_signature(rrsigs, pos, policy)) {
		return false;
	}

	// Create new RRSigs
	knot_rrset_t *new_rrsigs = create_empty_rrsigs_for(covered);
	if (new_rrsigs == NULL) {
		return false;
	}

	// Create the signature, use times from old RRSIG
	knot_dnssec_policy_t old_policy =
		{.now = knot_rrset_rdata_rrsig_sig_inception(rrsigs, pos),
		 .sign_lifetime = knot_rrset_rdata_rrsig_sig_expiration(rrsigs, pos) -
		                  knot_rrset_rdata_rrsig_sig_inception(rrsigs, pos),
		 .sign_refresh = policy->sign_refresh,
		 .forced_sign = policy->forced_sign};
	int ret = sign_rrset_one(new_rrsigs, covered, key, ctx, &old_policy);
	if (ret != KNOT_EOK) {
		knot_rrset_deep_free(&new_rrsigs, 1, 1);
		return false;
	}

	// Signatures have to match
	int cmp = rrset_rdata_compare_one(rrsigs, new_rrsigs, pos, 0);
	knot_rrset_deep_free(&new_rrsigs, 1, 1);
	return cmp == 0;
}

static bool valid_signature_exists(const knot_rrset_t *covered,
				   const knot_rrset_t *rrsigs,
				   const knot_dnssec_key_t *key,
				   knot_dnssec_sign_context_t *ctx,
				   const knot_dnssec_policy_t *policy)
{
	assert(key);
	assert(policy);

	if (!rrsigs)
		return false;

	for (int i = 0; i < rrsigs->rdata_count; i++) {
		uint16_t keytag = knot_rrset_rdata_rrsig_key_tag(rrsigs, i);
		if (keytag != key->keytag)
			continue;

		return full_sig_check(covered, rrsigs, i, key, ctx, policy);
	}

	return false;
}

static bool all_signatures_valid(const knot_rrset_t *covered,
                                 const knot_rrset_t *rrsigs,
                                 const knot_zone_keys_t *zone_keys,
                                 const knot_dnssec_policy_t *policy)
{
	bool use_ksk = covered->type == KNOT_RRTYPE_DNSKEY;
	for (int i = 0; i < zone_keys->count; i++) {
		if (zone_keys->is_ksk[i] && !use_ksk)
			continue;

		const knot_dnssec_key_t *key = &zone_keys->keys[i];
		knot_dnssec_sign_context_t *ctx = zone_keys->contexts[i];

		if (!valid_signature_exists(covered, rrsigs, key, ctx, policy)) {
			return false;
		}
	}

	return true;
}

static void get_matching_signing_data(const knot_rrset_t *rrsigs,
				      size_t pos,
				      const knot_zone_keys_t *keys,
				      const knot_dnssec_key_t **key,
				      knot_dnssec_sign_context_t **ctx)
{
	uint16_t keytag = knot_rrset_rdata_rrsig_key_tag(rrsigs, pos);
	for (int i = 0; i < keys->count; i++) {
		const knot_dnssec_key_t *found_key = &keys->keys[i];
		if (keytag != found_key->keytag)
			continue;
		*ctx = keys->contexts[i];
		*key = &keys->keys[i];
		return;
	}

	*ctx = NULL;
	*key = NULL;
	return;
}

static int remove_expired_rrsigs(const knot_rrset_t *covered,
				 const knot_rrset_t *rrsigs,
				 const knot_zone_keys_t *zone_keys,
				 const knot_dnssec_policy_t *policy,
				 knot_changeset_t *changeset)
{
	if (!rrsigs)
		return KNOT_EOK;

	assert(rrsigs->type == KNOT_RRTYPE_RRSIG);
	assert(policy);
	assert(changeset);

	knot_rrset_t *to_remove = NULL;
	int result = KNOT_EOK;

	for (int i = 0; i < rrsigs->rdata_count; i++) {
		// Get key that matches RRSIGs'
		const knot_dnssec_key_t *key = NULL;
		knot_dnssec_sign_context_t *ctx = NULL;
		get_matching_signing_data(rrsigs, i, zone_keys, &key, &ctx);
		if (full_sig_check(covered, rrsigs, i, key, ctx, policy))
			continue;
		assert(key && ctx);

		if (to_remove == NULL) {
			to_remove = create_empty_rrsigs_for(rrsigs);
			if (to_remove == NULL)
				return KNOT_ENOMEM;
		}

		result = knot_rrset_add_rr_from_rrset(to_remove, rrsigs, i);
		if (result != KNOT_EOK)
			break;
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

static int add_missing_rrsigs(const knot_rrset_t *covered,
                              const knot_rrset_t *rrsigs,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              knot_changeset_t *changeset)
{
	assert(covered);
	assert(zone_keys);
	assert(policy);
	assert(changeset);

	int result = KNOT_EOK;
	knot_rrset_t *to_add = NULL;
	bool use_ksk = covered->type == KNOT_RRTYPE_DNSKEY;

	for (int i = 0; i < zone_keys->count; i++) {
		// DNSKEY must be signed with both ZSK and KSK
		// all other records only with ZSK
		if (zone_keys->is_ksk[i] && !use_ksk)
			continue;

		const knot_dnssec_key_t *key = &zone_keys->keys[i];
		knot_dnssec_sign_context_t *ctx = zone_keys->contexts[i];
		if (valid_signature_exists(covered, rrsigs, key, ctx, policy))
			continue;

		if (to_add == NULL) {
			to_add = create_empty_rrsigs_for(covered);
			if (to_add == NULL)
				return KNOT_ENOMEM;
		}

		result = sign_rrset_one(to_add, covered, key, ctx, policy);
		if (result != KNOT_EOK)
			break;
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

static int remove_rrset_rrsigs(const knot_rrset_t *rrset,
                               knot_changeset_t *changeset)
{
	assert(rrset && rrset->rrsigs);
	knot_rrset_t *to_remove = NULL;
	int res = knot_rrset_deep_copy(rrset->rrsigs, &to_remove, 1);
	if (res != KNOT_EOK) {
		return res;
	}

	return knot_changeset_add_rrset(changeset, to_remove,
	                                KNOT_CHANGESET_REMOVE);
}

static int force_resign_rrset(const knot_rrset_t *rrset,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              knot_changeset_t *ch)
{
	// Remove all RRSIGs from rrset
	if (rrset->rrsigs) {
		int ret = remove_rrset_rrsigs(rrset, ch);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Create all signatures from scratch
	return add_missing_rrsigs(rrset, NULL, zone_keys, policy, ch);
}

static int resign_rrset(const knot_rrset_t *rrset,
                        const knot_zone_keys_t *zone_keys,
                        const knot_dnssec_policy_t *policy,
                        knot_changeset_t *ch)
{
	int ret = remove_expired_rrsigs(rrset, rrset->rrsigs, zone_keys,
	                                policy, ch);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return add_missing_rrsigs(rrset, rrset->rrsigs, zone_keys, policy,
				  ch);
}

static int sign_node_rrsets(const knot_node_t *node,
                            const knot_zone_keys_t *zone_keys,
                            const knot_dnssec_policy_t *policy,
                            knot_changeset_t *changeset)
{
	assert(node);
	assert(zone_keys);
	assert(policy);
	assert(changeset);

	int result = KNOT_EOK;

	for (int i = 0; i < node->rrset_count; i++) {
		const knot_rrset_t *rrset = node->rrset_tree[i];
		if (rrset->type == KNOT_RRTYPE_SOA) {
			continue;
		}

		// We only want to sign NSEC and DS at delegation points
		if (knot_node_is_deleg_point(node) &&
		    (rrset->type != KNOT_RRTYPE_NSEC ||
		    rrset->type != KNOT_RRTYPE_DS)) {
			continue;
		}

		// These RRs have their signatures stored in changeset already
		if (knot_node_is_replaced_nsec(node)
		    && ((knot_rrset_type(rrset) == KNOT_RRTYPE_NSEC)
		         || (knot_rrset_type(rrset) == KNOT_RRTYPE_NSEC3))) {
			continue;
		}

		// Remove standalone RRSIGs (without the RRSet they sign)
		if (knot_rrset_rdata_rr_count(rrset) == 0
		    && knot_rrset_rdata_rr_count(rrset->rrsigs) != 0) {
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

typedef struct node_sign_args {
	const knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	knot_changeset_t *changeset;
	int ret;
} node_sign_args_t;

static void sign_node(knot_node_t **node, void *data)
{
	assert(node);
	assert(*node);
	node_sign_args_t *args = (node_sign_args_t *)data;
	assert(data);

	if (args->ret != KNOT_EOK) {
		return;
	}

	if ((*node)->rrset_count == 0) {
		return;
	}

	if (knot_node_is_non_auth(*node)) {
		return;
	}
	args->ret = sign_node_rrsets(*node, args->zone_keys, args->policy,
	                             args->changeset);
	knot_node_clear_replaced_nsec(*node);
}

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
	                         .changeset = changeset, .ret = KNOT_EOK};
	knot_zone_tree_apply(tree, sign_node, &args);
	return args.ret;
}

typedef struct {
	const knot_zone_contents_t *zone;
	knot_zone_keys_t *zone_keys;
	const knot_dnssec_policy_t *policy;
	knot_changeset_t *out_ch;
} changeset_signing_data_t;

static int add_rrsigs_for_nsec(knot_rrset_t *rrset, void *data)
{
	if (rrset == NULL) {
		return KNOT_EINVAL;
	}

	int res = KNOT_EOK;
	changeset_signing_data_t *nsec_data = (changeset_signing_data_t *)data;

	if (knot_rrset_type(rrset) == KNOT_RRTYPE_NSEC
	    || knot_rrset_type(rrset) == KNOT_RRTYPE_NSEC3) {
		res = add_missing_rrsigs(rrset, NULL, nsec_data->zone_keys,
		                         nsec_data->policy,
		                         nsec_data->out_ch);
	}

	if (res != KNOT_EOK) {
		fprintf(stderr, "add_rrsigs_for_nsec() for NSEC"
		        "failed\n");
	}

	return res;
}

static int sign_nsec(knot_zone_keys_t *zone_keys,
                     const knot_dnssec_policy_t *policy,
                     knot_changeset_t *ch)
{
	assert(zone_keys != NULL);
	assert(policy != NULL);
	assert(ch != NULL);

	int res = KNOT_EOK;

	changeset_signing_data_t data = {.zone = NULL,
	                                 .zone_keys = zone_keys,
	                                 .policy = policy,
	                                 .out_ch = ch };

	// Sign each NSEC or NSEC3 in the ADD section of the changeset
	return knot_changeset_apply(ch, KNOT_CHANGESET_ADD,
	                            add_rrsigs_for_nsec, &data);
}

/*- public API ---------------------------------------------------------------*/

int knot_zone_sign(const knot_zone_contents_t *zone,
                   knot_zone_keys_t *zone_keys,
                   const knot_dnssec_policy_t *policy,
                   knot_changeset_t *out_ch)
{
	assert(zone);
	assert(zone_keys);
	assert(policy);
	assert(out_ch);

	int result;

	result = zone_tree_sign(zone->nodes, zone_keys, policy, out_ch);
	if (result != KNOT_EOK) {
		fprintf(stderr, "zone_tree_sign() on normal nodes failed\n");
		return result;
	}

	result = zone_tree_sign(zone->nsec3_nodes, zone_keys, policy,
	                        out_ch);
	if (result != KNOT_EOK) {
		fprintf(stderr, "zone_tree_sign() on nsec3 nodes failed\n");
		return result;
	}

	// sign all NSEC and NSEC3 RRs in changeset
	result = sign_nsec(zone_keys, policy, out_ch);
	if (result != KNOT_EOK) {
		fprintf(stderr, "sign_nsec() failed\n");
		return result;
	}

	return KNOT_EOK;
}

bool knot_zone_sign_soa_expired(const knot_zone_contents_t *zone,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy)
{
	assert(zone);
	// Get SOA from zone.
	const knot_rrset_t *soa_rr =
		knot_node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	assert(soa_rr);

	return !all_signatures_valid(soa_rr, soa_rr->rrsigs, zone_keys, policy);
}

int knot_zone_sign_update_soa(const knot_zone_contents_t *zone,
                              const knot_zone_keys_t *zone_keys,
                              const knot_dnssec_policy_t *policy,
                              knot_changeset_t *changeset)
{
	knot_node_t *apex = knot_zone_contents_get_apex(zone);
	knot_rrset_t *soa = knot_node_get_rrset(apex, KNOT_RRTYPE_SOA);

	int result;

	// Remove SOA's old RRSIGs (if there are any)
	if (soa->rrsigs) {
		knot_rrset_t *soa_copy = NULL;
		result = knot_rrset_deep_copy(soa->rrsigs, &soa_copy, 1);
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

	if (soa == NULL || soa->rdata_count != 1)
		return KNOT_EINVAL;

	uint32_t serial = knot_rrset_rdata_soa_serial(soa);
	if (serial == UINT32_MAX)
		return KNOT_EINVAL;

	// TODO: proper increment, no check
	uint32_t new_serial = serial;
	if (policy->soa_up == KNOT_SOA_SERIAL_INC) {
		new_serial += 1;
	} else {
		assert(policy->soa_up == KNOT_SOA_SERIAL_KEEP);
	}

	// create SOA and new SOA with updated serial
	knot_rrset_t *soa_from = NULL;
	knot_rrset_t *soa_to = NULL;
	int copy_rdata_dnames = true;

	result = knot_rrset_deep_copy_no_sig(soa, &soa_from, copy_rdata_dnames);
	if (result != KNOT_EOK)
		return result;

	result = knot_rrset_deep_copy_no_sig(soa, &soa_to, copy_rdata_dnames);
	if (result != KNOT_EOK) {
		knot_rrset_deep_free(&soa_from, 1, 1);
		return result;
	}

	knot_rrset_rdata_soa_serial_set(soa_to, new_serial);

	// Create signature for new SOA
	result = add_missing_rrsigs(soa_to, NULL, zone_keys, policy, changeset);
	if (result != KNOT_EOK) {
		return result;
	}
	
	// save the result

	changeset->soa_from = soa_from;
	changeset->soa_to = soa_to;
	changeset->serial_from = serial;
	changeset->serial_to = new_serial;

	return KNOT_EOK;
}
