/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

int knot_nsec3_hash_to_dname(uint8_t *out, size_t out_size, const uint8_t *hash,
                             size_t hash_size, const knot_dname_t *zone_apex)

{
	if (out == NULL || hash == NULL || zone_apex == NULL) {
		return KNOT_EINVAL;
	}

	// Encode raw hash to the first label.
	uint8_t label[KNOT_DNAME_MAXLABELLEN];
	int32_t label_size = knot_base32hex_encode(hash, hash_size, label, sizeof(label));
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

	dnssec_binary_t hash = { 0 };

	int ret = dnssec_nsec3_hash(&data, params, &hash);
	if (ret != DNSSEC_EOK) {
		return knot_error_from_libdnssec(ret);
	}

	ret = knot_nsec3_hash_to_dname(out, out_size, hash.data, hash.size, zone_apex);

	dnssec_binary_free(&hash);

	return ret;
}

knot_dname_t *node_nsec3_hash(zone_node_t *node, const zone_contents_t *zone)
{
	if (node->nsec3_hash == NULL && knot_is_nsec3_enabled(zone)) {
		assert(!(node->flags & NODE_FLAGS_NSEC3_NODE));
		size_t hash_size = zone_nsec3_name_len(zone);
		knot_dname_t *hash = malloc(hash_size);
		if (hash == NULL) {
			return NULL;
		}
		if (knot_create_nsec3_owner(hash, hash_size, node->owner, zone->apex->owner,
		                            &zone->nsec3_params) != KNOT_EOK) {
			free(hash);
			return NULL;
		}
		node->nsec3_hash = hash;
	}

	if (node->flags & NODE_FLAGS_NSEC3_NODE) {
		return node->nsec3_node->owner;
	} else {
		return node->nsec3_hash;
	}
}

zone_node_t *node_nsec3_node(zone_node_t *node, const zone_contents_t *zone)
{
	if (!(node->flags & NODE_FLAGS_NSEC3_NODE) && knot_is_nsec3_enabled(zone)) {
		knot_dname_t *hash = node_nsec3_hash(node, zone);
		zone_node_t *nsec3 = zone_tree_get(zone->nsec3_nodes, hash);
		if (nsec3 != NULL) {
			if (node->nsec3_hash != binode_counterpart(node)->nsec3_hash) {
				free(node->nsec3_hash);
			}
			node->nsec3_node = binode_first(nsec3);
			node->flags |= NODE_FLAGS_NSEC3_NODE;
		}
	}

	return node_nsec3_get(node);
}

int binode_fix_nsec3_pointer(zone_node_t *node, const zone_contents_t *zone)
{
	zone_node_t *counter = binode_counterpart(node);
	if (counter->nsec3_hash == NULL) {
		(void)node_nsec3_node(node, zone);
		return KNOT_EOK;
	}
	assert(counter->nsec3_node != NULL); // shut up cppcheck

	zone_node_t *nsec3_counter = (counter->flags & NODE_FLAGS_NSEC3_NODE) ?
	                             counter->nsec3_node : NULL;
	if (nsec3_counter != NULL && !(binode_node_as(nsec3_counter, node)->flags & NODE_FLAGS_DELETED)) {
		assert(node->flags & NODE_FLAGS_NSEC3_NODE);
		node->flags |= NODE_FLAGS_NSEC3_NODE;
		assert(!(nsec3_counter->flags & NODE_FLAGS_SECOND));
		node->nsec3_node = nsec3_counter;
	} else {
		node->flags &= ~NODE_FLAGS_NSEC3_NODE;
		if (counter->flags & NODE_FLAGS_NSEC3_NODE) {
			// downgrade the NSEC3 node pointer to NSEC3 name
			node->nsec3_hash = knot_dname_copy(counter->nsec3_node->owner, NULL);
		} else {
			node->nsec3_hash = counter->nsec3_hash;
		}
		(void)node_nsec3_node(node, zone);
	}
	return KNOT_EOK;
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
	if (rrs->count != 1) {
		return false;
	}

	dnssec_binary_t rdata = {
		.size = rrs->rdata->len,
		.data = rrs->rdata->data,
	};

	dnssec_nsec3_params_t parsed = { 0 };
	int r = dnssec_nsec3_params_from_rdata(&parsed, &rdata);
	if (r != DNSSEC_EOK) {
		return false;
	}

	bool equal = parsed.algorithm == params->algorithm &&
	             parsed.flags == 0 && // opt-out flag is always 0 in NSEC3PARAM
	             parsed.iterations == params->iterations &&
	             dnssec_binary_cmp(&parsed.salt, &params->salt) == 0;

	dnssec_nsec3_params_free(&parsed);

	return equal;
}

static int remove_nsec3param(zone_update_t *update, bool also_rrsig)
{
	knot_rrset_t rrset = node_rrset(update->new_cont->apex, KNOT_RRTYPE_NSEC3PARAM);
	int ret = zone_update_remove(update, &rrset);

	rrset = node_rrset(update->new_cont->apex, KNOT_RRTYPE_RRSIG);
	if (!knot_rrset_empty(&rrset) && ret == KNOT_EOK && also_rrsig) {
		knot_rrset_t rrsig;
		knot_rrset_init(&rrsig, update->new_cont->apex->owner,
		                KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, 0);
		ret = knot_synth_rrsig(KNOT_RRTYPE_NSEC3PARAM, &rrset.rrs, &rrsig.rrs, NULL);
		if (ret == KNOT_EOK) {
			ret = zone_update_remove(update, &rrsig);
		}
		knot_rdataset_clear(&rrsig.rrs, NULL);
	}

	return ret;
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

static int add_nsec3param(zone_update_t *update,
                          const dnssec_nsec3_params_t *params,
                          uint32_t ttl)
{
	assert(update);
	assert(params);

	knot_rrset_t *rrset = NULL;
	rrset = knot_rrset_new(update->new_cont->apex->owner, KNOT_RRTYPE_NSEC3PARAM,
	                       KNOT_CLASS_IN, ttl, NULL);
	if (rrset == NULL) {
		return KNOT_ENOMEM;
	}

	int r = set_nsec3param(rrset, params);
	if (r == KNOT_EOK) {
		r = zone_update_add(update, rrset);
	}
	knot_rrset_free(rrset, NULL);
	return r;
}

bool knot_nsec3param_uptodate(const zone_contents_t *zone,
                              const dnssec_nsec3_params_t *params)
{
	assert(zone);
	assert(params);

	knot_rdataset_t *nsec3param = node_rdataset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);

	return (nsec3param != NULL && nsec3param_valid(nsec3param, params));
}

int knot_nsec3param_update(zone_update_t *update,
                           const dnssec_nsec3_params_t *params,
                           uint32_t ttl)
{
	assert(update);
	assert(params);

	knot_rdataset_t *nsec3param = node_rdataset(update->new_cont->apex, KNOT_RRTYPE_NSEC3PARAM);
	bool valid = nsec3param && nsec3param_valid(nsec3param, params);

	if (nsec3param && !valid) {
		int r = remove_nsec3param(update, params->algorithm == 0);
		if (r != KNOT_EOK) {
			return r;
		}
	}

	if (params->algorithm != 0 && !valid) {
		return add_nsec3param(update, params, ttl);
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

// int: returns KNOT_E* if error
static int zone_nsec_ttl(zone_contents_t *zone)
{
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	if (knot_rrset_empty(&soa)) {
		return KNOT_EINVAL;
	}

	return MIN(knot_soa_minimum(soa.rrs.rdata), soa.ttl);
}

int knot_zone_create_nsec_chain(zone_update_t *update, const kdnssec_ctx_t *ctx)
{
	if (update == NULL || ctx == NULL) {
		return KNOT_EINVAL;
	}

	if (ctx->policy->unsafe & UNSAFE_NSEC) {
		return KNOT_EOK;
	}

	int nsec_ttl = zone_nsec_ttl(update->new_cont);
	if (nsec_ttl < 0) {
		return nsec_ttl;
	}

	dnssec_nsec3_params_t params = nsec3param_init(ctx->policy, ctx->zone);

	int ret = knot_nsec3param_update(update, &params, nsec_ttl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (ctx->policy->nsec3_enabled) {
		ret = knot_nsec3_create_chain(update->new_cont, &params, nsec_ttl,
		                              update);
	} else {
		ret = knot_nsec_create_chain(update, nsec_ttl);
		if (ret == KNOT_EOK) {
			ret = delete_nsec3_chain(update);
		}
	}
	return ret;
}

int knot_zone_fix_nsec_chain(zone_update_t *update,
                             const zone_keyset_t *zone_keys,
                             const kdnssec_ctx_t *ctx)
{
	if (update == NULL || ctx == NULL) {
		return KNOT_EINVAL;
	}

	if (ctx->policy->unsafe & UNSAFE_NSEC) {
		return KNOT_EOK;
	}

	int nsec_ttl_old = zone_nsec_ttl(update->zone->contents);
	int nsec_ttl_new = zone_nsec_ttl(update->new_cont);
	if (nsec_ttl_old < 0 || nsec_ttl_new < 0) {
		return MIN(nsec_ttl_old, nsec_ttl_new);
	}

	dnssec_nsec3_params_t params = nsec3param_init(ctx->policy, ctx->zone);

	int ret;
	if (nsec_ttl_old != nsec_ttl_new || (update->flags & UPDATE_CHANGED_NSEC)) {
		ret = KNOT_ENORECORD;
	} else if (ctx->policy->nsec3_enabled) {
		ret = knot_nsec3_fix_chain(update, &params, nsec_ttl_new);
	} else {
		ret = knot_nsec_fix_chain(update, nsec_ttl_new);
	}
	if (ret == KNOT_ENORECORD) {
		log_zone_info(update->zone->name, "DNSSEC, re-creating whole NSEC%s chain",
		              (ctx->policy->nsec3_enabled ? "3" : ""));
		if (ctx->policy->nsec3_enabled) {
			ret = knot_nsec3_create_chain(update->new_cont, &params,
			                              nsec_ttl_new, update);
		} else {
			ret = knot_nsec_create_chain(update, nsec_ttl_new);
		}
	}
	if (ret == KNOT_EOK) {
		ret = knot_zone_sign_nsecs_in_changeset(zone_keys, ctx, update);
	}
	return ret;
}

int knot_zone_check_nsec_chain(zone_update_t *update, const kdnssec_ctx_t *ctx,
                               bool incremental)
{
	int ret = KNOT_EOK;
	dnssec_nsec3_params_t params = nsec3param_init(ctx->policy, ctx->zone);

	if (incremental) {
		ret = ctx->policy->nsec3_enabled
		    ? knot_nsec3_check_chain_fix(update, &params)
		    : knot_nsec_check_chain_fix(update);
	}
	if (ret == KNOT_ENORECORD) {
		log_zone_info(update->zone->name, "DNSSEC, re-validating whole NSEC%s chain",
		              (ctx->policy->nsec3_enabled ? "3" : ""));
		incremental = false;
	}

	if (incremental) {
		return ret;
	}

	return ctx->policy->nsec3_enabled ? knot_nsec3_check_chain(update, &params) :
	                                    knot_nsec_check_chain(update);
}
