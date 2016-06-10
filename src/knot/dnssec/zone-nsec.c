/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/error.h"
#include "libknot/descriptor.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/soa.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
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
		zone_node_t *node = NULL;
		int ret = zone_tree_get(nsec3_tree, rrset->owner, &node);
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
 * 'removed' flag.
 */
static int mark_removed_nsec3(const zone_contents_t *zone, changeset_t *ch)
{
	if (zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	changeset_iter_t itt;
	changeset_iter_rem(&itt, ch, false);

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

bool knot_is_nsec3_enabled(const zone_contents_t *zone)
{
	if (zone == NULL) {
		return false;
	}

	return zone->nsec3_params.algorithm != 0;
}

knot_dname_t *knot_nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
                                       const knot_dname_t *zone_apex)
{
	if (hash == NULL || zone_apex == NULL) {
		return NULL;
	}

	// encode raw hash to first label

	uint8_t label[KNOT_DNAME_MAXLEN];
	int32_t label_size;
	label_size = base32hex_encode(hash, hash_size, label, sizeof(label));
	if (label_size <= 0) {
		return NULL;
	}

	// allocate result

	size_t zone_apex_size = knot_dname_size(zone_apex);
	size_t result_size = 1 + label_size + zone_apex_size;
	knot_dname_t *result = malloc(result_size);
	if (result == NULL) {
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

knot_dname_t *knot_create_nsec3_owner(const knot_dname_t *owner,
                                      const knot_dname_t *zone_apex,
                                      const knot_nsec3_params_t *params)
{
	if (owner == NULL || zone_apex == NULL || params == NULL) {
		return NULL;
	}

	int owner_size = knot_dname_size(owner);
	if (owner_size < 0) {
		return NULL;
	}

	dnssec_binary_t data = {
		.data = (uint8_t *)owner,
		.size = owner_size
	};

	dnssec_nsec3_params_t xparams = {
		.algorithm = params->algorithm,
		.flags = params->flags,
		.iterations = params->iterations,
		.salt = {
			.data = params->salt,
			.size = params->salt_length
		}
	};

	dnssec_binary_t hash = { 0 };

	int ret = dnssec_nsec3_hash(&data, &xparams, &hash);
	if (ret != DNSSEC_EOK) {
		return NULL;
	}

	knot_dname_t *result = knot_nsec3_hash_to_dname(hash.data, hash.size, zone_apex);

	dnssec_binary_free(&hash);

	return result;
}

static int set_nsec3param(knot_rrset_t *rrset, const kdnssec_ctx_t *dnssec_ctx)
{
	assert(rrset);
	assert(dnssec_ctx);

	dnssec_nsec3_params_t *new_params = &dnssec_ctx->policy->nsec3_params;
	dnssec_binary_t *new_salt = dnssec_ctx->zone->nsec3_salt;

	// Prepare wire rdata.
	size_t rdata_len = 3 * sizeof(uint8_t) + sizeof(uint16_t) + new_salt->size;
	uint8_t rdata[rdata_len];
	wire_ctx_t wire = wire_ctx_init(rdata, rdata_len);

	wire_ctx_write_u8(&wire, new_params->algorithm);
	wire_ctx_write_u8(&wire, new_params->flags);
	wire_ctx_write_u16(&wire, new_params->iterations);
	wire_ctx_write_u8(&wire, new_salt->size);
	wire_ctx_write(&wire, new_salt->data, new_salt->size);

	if (wire.error != KNOT_EOK) {
		return wire.error;
	}

	return knot_rrset_add_rdata(rrset, rdata, rdata_len, 0, NULL);
}

static bool match_nsec3param(const knot_nsec3_params_t *params,
                             const kdnssec_ctx_t *dnssec_ctx)
{
	assert(params);
	assert(dnssec_ctx);

	dnssec_nsec3_params_t *new_params = &dnssec_ctx->policy->nsec3_params;
	dnssec_binary_t *new_salt = dnssec_ctx->zone->nsec3_salt;

	return params->algorithm == new_params->algorithm &&
	       params->flags == new_params->flags &&
	       params->iterations == new_params->iterations &&
	       params->salt_length == new_salt->size &&
	       memcmp(params->salt, new_salt->data, new_salt->size) == 0;
}

static int update_nsec3param(const zone_contents_t *zone,
                             const kdnssec_ctx_t *dnssec_ctx,
                             changeset_t *changeset)
{
	assert(zone);
	assert(dnssec_ctx);
	assert(changeset);

	dnssec_kasp_policy_t *policy = dnssec_ctx->policy;
	knot_rdataset_t *nsec3param = node_rdataset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);

	// Check for changed NSEC3PARAM record.
	bool changed = false;
	if (nsec3param != NULL && policy->nsec3_enabled &&
	    match_nsec3param(&zone->nsec3_params, dnssec_ctx)) {
		changed = true;
	}

	// Remove redundant or changed NSEC3PARAM record and its RRSIG.
	if ((nsec3param != NULL && !policy->nsec3_enabled) || changed) {
		knot_rrset_t rrset = node_rrset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);
		int ret = changeset_rem_rrset(changeset, &rrset, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}

		rrset = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
		if (!knot_rrset_empty(&rrset)) {
			knot_rrset_t synth_rrsig;
			knot_rrset_init(&synth_rrsig, zone->apex->owner,
			                KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN);

			ret = knot_synth_rrsig(KNOT_RRTYPE_NSEC3PARAM, &rrset.rrs,
			                       &synth_rrsig.rrs, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}

			ret = changeset_rem_rrset(changeset, &synth_rrsig, 0);
			knot_rdataset_clear(&synth_rrsig.rrs, NULL);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}

		// Also remove the record from the zone.
		knot_rdataset_clear(nsec3param, NULL);
		node_remove_rdataset(zone->apex, KNOT_RRTYPE_NSEC3PARAM);

		// Reset zone nsec3 paramaters.
		knot_nsec3param_free((knot_nsec3_params_t *)&zone->nsec3_params);
		memset((knot_nsec3_params_t *)&zone->nsec3_params, 0,
		       sizeof(knot_nsec3_params_t));
	}

	// Add new NSEC3PARAM record.
	if ((nsec3param == NULL && policy->nsec3_enabled) || changed) {
		knot_rrset_t *rrset = knot_rrset_new(zone->apex->owner,
		                                     KNOT_RRTYPE_NSEC3PARAM,
		                                     KNOT_CLASS_IN, NULL);
		if (rrset == NULL) {
			return KNOT_ENOMEM;
		}

		int ret = set_nsec3param(rrset, dnssec_ctx);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&rrset, NULL);
			return ret;
		}

		ret = changeset_add_rrset(changeset, rrset, 0);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&rrset, NULL);
			return ret;
		}

		// Update zone nsec3 paramaters.
		ret = knot_nsec3param_from_wire((knot_nsec3_params_t *)&zone->nsec3_params,
		                                 &rrset->rrs);
		knot_rrset_free(&rrset, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int knot_zone_create_nsec_chain(const zone_contents_t *zone,
                                changeset_t *changeset,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *dnssec_ctx)
{
	if (zone == NULL || changeset == NULL || dnssec_ctx == NULL) {
		return KNOT_EINVAL;
	}

	const knot_rdataset_t *soa = node_rdataset(zone->apex, KNOT_RRTYPE_SOA);
	if (soa == NULL) {
		return KNOT_EINVAL;
	}
	uint32_t nsec_ttl = knot_soa_minimum(soa);

	// Update NSEC3PARAM record.
	if (!dnssec_ctx->legacy) {
		int ret = update_nsec3param(zone, dnssec_ctx, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (dnssec_ctx->policy->nsec3_enabled) {
		int ret = knot_nsec3_create_chain(zone, nsec_ttl, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		int ret = knot_nsec_create_chain(zone, nsec_ttl, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = delete_nsec3_chain(zone, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}

		// Mark removed NSEC3 nodes, so that they are not signed later.
		ret = mark_removed_nsec3(zone, changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Sign newly created records right away.
	return knot_zone_sign_nsecs_in_changeset(zone_keys, dnssec_ctx, changeset);
}
