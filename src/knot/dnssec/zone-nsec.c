/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "libdnssec/error.h"
#include "libknot/descriptor.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/soa.h"
#include "knot/common/log.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/zone-diff.h"
#include "contrib/base32hex.h"
#include "contrib/wire_ctx.h"

/*!
 * \brief Deletes NSEC3 chain if NSEC should be used.
 *
 * \param zone       Zone to fix.
 * \param changeset  Changeset to be used.
 */
static int delete_nsec3_chain(const zone_contents_t *zone, changeset_t *changeset)
{
	assert(zone);
	assert(changeset);

	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	zone_tree_t *empty_tree = zone_tree_create();
	if (!empty_tree) {
		return KNOT_ENOMEM;
	}

	int ret = zone_tree_add_diff(zone->nsec3_nodes, empty_tree, changeset);

	zone_tree_free(&empty_tree);

	return ret;
}

/*!
 * \brief Finds a node with the same owner as the given NSEC3 RRSet and marks it
 *        as 'removed'.
 *
 * \param rrset      RRSet whose owner will be sought in the zone tree. non-NSEC3
 *                   RRSets are ignored.
 * \param nsec3tree  NSEC3 tree to search for the node in.
 */
static int mark_nsec3(knot_rrset_t *rrset, zone_tree_t *nsec3_tree)
{
	assert(rrset);
	assert(nsec3_tree);

	if (rrset->type == KNOT_RRTYPE_NSEC3) {
		zone_node_t *node = zone_tree_get(nsec3_tree, rrset->owner);
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
 * 'removed' flag.
 */
static int mark_removed_nsec3(const zone_contents_t *zone, changeset_t *ch)
{
	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	changeset_iter_t itt;
	changeset_iter_rem(&itt, ch);

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

int knot_nsec3_hash_to_dname(uint8_t *out, size_t out_size, const uint8_t *hash,
                             size_t hash_size, const knot_dname_t *zone_apex)

{
	if (out == NULL || hash == NULL || zone_apex == NULL) {
		return KNOT_EINVAL;
	}

	// Encode raw hash to the first label.
	uint8_t label[KNOT_DNAME_MAXLEN];
	int32_t label_size = base32hex_encode(hash, hash_size, label, sizeof(label));
	if (label_size <= 0) {
		return label_size;
	}

	// Write the result, which already is in lower-case.
	wire_ctx_t wire = wire_ctx_init(out, out_size);

	wire_ctx_write_u8(&wire, label_size);
	wire_ctx_write(&wire, label, label_size);
	wire_ctx_write(&wire, zone_apex, knot_dname_size(zone_apex));

	return wire.error;
}

int knot_create_nsec3_owner(uint8_t *out, size_t out_size,
                            const knot_dname_t *owner, const knot_dname_t *zone_apex,
                            const dnssec_nsec3_params_t *params)
{
	if (out == NULL || owner == NULL || zone_apex == NULL || params == NULL) {
		return KNOT_EINVAL;
	}

	dnssec_binary_t data = {
		.data = (uint8_t *)owner,
		.size = knot_dname_size(owner)
	};

	uint8_t hash_data[64];
	dnssec_binary_t hash = {
		.data = hash_data,
		.size = sizeof(hash_data)
	};

	int ret = dnssec_nsec3_hash(&data, params, &hash);
	if (ret != DNSSEC_EOK) {
		return knot_error_from_libdnssec(ret);
	}

	return knot_nsec3_hash_to_dname(out, out_size, hash.data, hash.size, zone_apex);
}

static bool nsec3param_valid(const knot_rdataset_t *rrs,
                             const dnssec_nsec3_params_t *params)
{
	assert(rrs);
	assert(params);

	// NSEC3 disabled
	if (params->algorithm == 0) {
		return false;
	}

	// multiple NSEC3 records
	if (rrs->rr_count != 1) {
		return false;
	}

	knot_rdata_t *rrd = knot_rdataset_at(rrs, 0);
	dnssec_binary_t rdata = {
		.size = rrd->len,
		.data = rrd->data,
	};

	dnssec_nsec3_params_t parsed = { 0 };
	int r = dnssec_nsec3_params_from_rdata(&parsed, &rdata);
	if (r != DNSSEC_EOK) {
		return false;
	}

	bool equal = parsed.algorithm == params->algorithm &&
	             parsed.flags == params->flags &&
	             parsed.iterations == params->iterations &&
	             dnssec_binary_cmp(&parsed.salt, &params->salt) == 0;

	dnssec_nsec3_params_free(&parsed);

	return equal;
}

static int remove_nsec3param(const zone_contents_t *zone, changeset_t *changeset)
{
	assert(zone);
	assert(changeset);

	knot_rrset_t rrset = node_rrset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);
	int ret = changeset_add_removal(changeset, &rrset, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	rrset = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	if (!knot_rrset_empty(&rrset)) {
		knot_rrset_t rrsig;
		knot_rrset_init(&rrsig, zone->apex->owner, KNOT_RRTYPE_RRSIG,
		                KNOT_CLASS_IN, 0);
		ret = knot_synth_rrsig(KNOT_RRTYPE_NSEC3PARAM, &rrset.rrs, &rrsig.rrs, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = changeset_add_removal(changeset, &rrsig, 0);
		knot_rdataset_clear(&rrsig.rrs, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int set_nsec3param(knot_rrset_t *rrset, const dnssec_nsec3_params_t *params)
{
	assert(rrset);
	assert(params);

	// Prepare wire rdata.
	size_t rdata_len = 3 * sizeof(uint8_t) + sizeof(uint16_t) + params->salt.size;
	uint8_t rdata[rdata_len];
	wire_ctx_t wire = wire_ctx_init(rdata, rdata_len);

	wire_ctx_write_u8(&wire, params->algorithm);
	wire_ctx_write_u8(&wire, 0); // (RFC 5155 Section 4.1.2)
	wire_ctx_write_u16(&wire, params->iterations);
	wire_ctx_write_u8(&wire, params->salt.size);
	wire_ctx_write(&wire, params->salt.data, params->salt.size);

	if (wire.error != KNOT_EOK) {
		return wire.error;
	}

	assert(wire_ctx_available(&wire) == 0);

	return knot_rrset_add_rdata(rrset, rdata, rdata_len, NULL);
}

static int add_nsec3param(const zone_contents_t *zone, changeset_t *changeset,
                          const dnssec_nsec3_params_t *params)
{
	assert(zone);
	assert(changeset);
	assert(params);

	knot_rrset_t *rrset = NULL;
	rrset = knot_rrset_new(zone->apex->owner, KNOT_RRTYPE_NSEC3PARAM,
	                       KNOT_CLASS_IN, 0, NULL);
	if (!rrset) {
		return KNOT_ENOMEM;
	}

	int r = set_nsec3param(rrset, params);
	if (r != KNOT_EOK) {
		knot_rrset_free(rrset, NULL);
		return r;
	}

	r = changeset_add_addition(changeset, rrset, 0);
	knot_rrset_free(rrset, NULL);
	return r;
}

static int update_nsec3param(const zone_contents_t *zone,
                             changeset_t *changeset,
                             const dnssec_nsec3_params_t *params)
{
	assert(zone);
	assert(changeset);
	assert(params);

	knot_rdataset_t *nsec3param = node_rdataset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);
	bool valid = nsec3param && nsec3param_valid(nsec3param, params);

	if (nsec3param && !valid) {
		int r = remove_nsec3param(zone, changeset);
		if (r != KNOT_EOK) {
			return r;
		}
	}

	if (params->algorithm != 0 && !valid) {
		return add_nsec3param(zone, changeset, params);
	}

	return KNOT_EOK;
}

/*!
 * \brief Initialize NSEC3PARAM based on the signing policy.
 *
 * \note For NSEC, the algorithm number is set to 0.
 */
static dnssec_nsec3_params_t nsec3param_init(const knot_kasp_policy_t *policy,
                                             const knot_kasp_zone_t *zone)
{
	assert(policy);
	assert(zone);

	dnssec_nsec3_params_t params = { 0 };
	if (policy->nsec3_enabled) {
		params.algorithm = DNSSEC_NSEC3_ALGORITHM_SHA1;
		params.iterations = policy->nsec3_iterations;
		params.salt = zone->nsec3_salt;
		params.flags = (policy->nsec3_opt_out ? KNOT_NSEC3_FLAG_OPT_OUT : 0);
	}

	return params;
}

int knot_zone_create_nsec_chain(zone_update_t *update,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *ctx,
                                bool sign_nsec_chain)
{
	if (update == NULL || ctx == NULL) {
		return KNOT_EINVAL;
	}

	const knot_rdataset_t *soa = node_rdataset(update->new_cont->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL) {
		return KNOT_EINVAL;
	}

	uint32_t nsec_ttl = knot_soa_minimum(soa);
	dnssec_nsec3_params_t params = nsec3param_init(ctx->policy, ctx->zone);

	changeset_t ch;
	int ret = changeset_init(&ch, update->new_cont->apex->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = update_nsec3param(update->new_cont, &ch, &params);
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	if (ctx->policy->nsec3_enabled) {
		ret = knot_nsec3_create_chain(update->new_cont, &params, nsec_ttl,
					      ctx->policy->nsec3_opt_out, &ch);
		if (ret != KNOT_EOK) {
			goto cleanup;
		}
	} else {
		int ret = knot_nsec_create_chain(update->new_cont, nsec_ttl, &ch);
		if (ret != KNOT_EOK) {
			goto cleanup;
		}

		ret = delete_nsec3_chain(update->new_cont, &ch);
		if (ret != KNOT_EOK) {
			goto cleanup;
		}

		// Mark removed NSEC3 nodes, so that they are not signed later.
		ret = mark_removed_nsec3(update->new_cont, &ch);
		if (ret != KNOT_EOK) {
			goto cleanup;
		}
	}

	if (sign_nsec_chain) {
		ret = knot_zone_sign_nsecs_in_changeset(zone_keys, ctx, &ch);
	}

	if (ret == KNOT_EOK) {
		ret = zone_update_apply_changeset(update, &ch);
	}

cleanup:
	changeset_clear(&ch);
	return ret;
}


int knot_zone_fix_nsec_chain(zone_update_t *update,
                             const zone_keyset_t *zone_keys,
                             const kdnssec_ctx_t *ctx,
                             bool sign_nsec_chain)
{
	if (update == NULL || ctx == NULL) {
		return KNOT_EINVAL;
	}

	const knot_rdataset_t *soa_old = node_rdataset(update->zone->contents->apex, KNOT_RRTYPE_SOA);
	const knot_rdataset_t *soa_new = node_rdataset(update->new_cont->apex, KNOT_RRTYPE_SOA);
	if (soa_old == NULL || soa_new == NULL) {
		return KNOT_EINVAL;
	}

	uint32_t nsec_ttl_old = knot_soa_minimum(soa_old);
	uint32_t nsec_ttl_new = knot_soa_minimum(soa_new);
	dnssec_nsec3_params_t params = nsec3param_init(ctx->policy, ctx->zone);

	changeset_t ch;
	int ret = changeset_init(&ch, update->new_cont->apex->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (nsec_ttl_old != nsec_ttl_new) {
		ret = KNOT_ENORECORD;
	} else if (ctx->policy->nsec3_enabled) {
		ret = knot_nsec3_fix_chain(update, &params, nsec_ttl_new,
		                           ctx->policy->nsec3_opt_out, &ch);
	} else {
		ret = knot_nsec_fix_chain(update->zone->contents, update->new_cont,
		                          nsec_ttl_new, &ch);
	}
	if (ret == KNOT_ENORECORD) {
		log_zone_info(update->zone->name, "DNSSEC, re-creating whole NSEC%s chain",
		              (ctx->policy->nsec3_enabled ? "3" : ""));
		changeset_clear(&ch);
		ret = changeset_init(&ch, update->new_cont->apex->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		if (ctx->policy->nsec3_enabled) {
			ret = knot_nsec3_create_chain(update->new_cont, &params, nsec_ttl_new,
			                              ctx->policy->nsec3_opt_out, &ch);
		} else {
			ret = knot_nsec_create_chain(update->new_cont, nsec_ttl_new, &ch);
		}
	}
	if (ret != KNOT_EOK) {
		goto cleanup;
	}

	if (sign_nsec_chain) {
		ret = knot_zone_sign_nsecs_in_changeset(zone_keys, ctx, &ch);
	}

	if (ret == KNOT_EOK) {
		ret = zone_update_apply_changeset(update, &ch);
	}

cleanup:
	changeset_clear(&ch);
	return ret;
}
