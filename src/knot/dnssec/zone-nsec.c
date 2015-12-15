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

#include "dnssec/error.h"
#include "dnssec/nsec.h"
#include "libknot/descriptor.h"
#include "libknot/packet/wire.h"
#include "libknot/rrtype/nsec3.h"
#include "libknot/rrtype/soa.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone-diff.h"
#include "contrib/base32hex.h"

/*!
 * \brief Deletes NSEC3 chain if NSEC should be used.
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

	return zone->nsec3_params.algorithm != 0;
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
 *        as 'removed'.
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
 * 'removed' flag.
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

	int owner_size = knot_dname_size(owner);
	if (owner_size < 0) {
		return NULL;
	}

	dnssec_binary_t data = { 0 };
	data.data = (uint8_t *)owner;
	data.size = owner_size;

	dnssec_binary_t hash = { 0 };
	dnssec_nsec3_params_t xparams = {
		.algorithm = params->algorithm,
		.flags = params->flags,
		.iterations = params->iterations,
		.salt = {
			.data = params->salt,
			.size = params->salt_length
		}
	};

	int r = dnssec_nsec3_hash(&data, &xparams, &hash);
	if (r != DNSSEC_EOK) {
		return NULL;
	}

	knot_dname_t *result = knot_nsec3_hash_to_dname(hash.data, hash.size, zone_apex);

	dnssec_binary_free(&hash);

	return result;
}

/*!
 * \brief Create NSEC3 owner name from hash and zone apex.
 */
knot_dname_t *knot_nsec3_hash_to_dname(const uint8_t *hash, size_t hash_size,
                                       const knot_dname_t *zone_apex)
{
	assert(zone_apex);

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
 * \brief Create NSEC or NSEC3 chain in the zone.
 */
int knot_zone_create_nsec_chain(const zone_contents_t *zone,
                                changeset_t *changeset,
                                const zone_keyset_t *zone_keys,
                                const kdnssec_ctx_t *dnssec_ctx)
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

	if (nsec3_enabled) {
		result = knot_nsec3_create_chain(zone, nsec_ttl, changeset);
	} else {
		result = knot_nsec_create_chain(zone, nsec_ttl, changeset);
	}

	if (result == KNOT_EOK && !nsec3_enabled) {
		result = delete_nsec3_chain(zone, changeset);
	}

	if (result == KNOT_EOK) {
		// Mark removed NSEC3 nodes, so that they are not signed later
		result = mark_removed_nsec3(changeset, zone);
	}

	if (result != KNOT_EOK) {
		return result;
	}

	// Sign newly created records right away
	return knot_zone_sign_nsecs_in_changeset(zone_keys, dnssec_ctx, changeset);
}
