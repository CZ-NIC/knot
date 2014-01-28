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
#include <string.h>
#include <limits.h>

#include "common/base32hex.h"
#include "common/descriptor.h"
#include "common/hhash.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/nsec3-chain.h"
#include "libknot/dnssec/nsec-bitmap.h"
#include "libknot/dnssec/nsec3.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "libknot/rdata.h"
#include "libknot/util/debug.h"
#include "libknot/util/utils.h"
#include "libknot/packet/wire.h"
#include "knot/zone/zone-contents.h"
#include "knot/zone/zone-diff.h"

/*!
 * \brief Deletes NSEC3 chain if NSEC should be used.
 *
 * \param zone       Zone to fix.
 * \param changeset  Changeset to be used.
 * \return KNOT_E*
 */
static int delete_nsec3_chain(const knot_zone_contents_t *zone,
                              knot_changeset_t *changeset)
{
	assert(zone);
	assert(zone->nsec3_nodes);
	assert(changeset);

	if (knot_zone_tree_is_empty(zone->nsec3_nodes)) {
		return KNOT_EOK;
	}

	dbg_dnssec_detail("deleting NSEC3 chain\n");
	knot_zone_tree_t *empty_tree = knot_zone_tree_create();
	if (!empty_tree) {
		return KNOT_ENOMEM;
	}

	int result = knot_zone_tree_add_diff(zone->nsec3_nodes, empty_tree,
	                                     changeset);

	knot_zone_tree_free(&empty_tree);

	return result;
}

/* - helper functions ------------------------------------------------------ */

/*!
 * \brief Check if NSEC3 is enabled for given zone.
 */
bool knot_is_nsec3_enabled(const knot_zone_contents_t *zone)
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
static bool get_zone_soa_min_ttl(const knot_zone_contents_t *zone,
                                 uint32_t *ttl)
{
	assert(zone);
	assert(zone->apex);
	assert(ttl);

	knot_node_t *apex = zone->apex;
	knot_rrset_t *soa = knot_node_get_rrset(apex, KNOT_RRTYPE_SOA);
	if (!soa) {
		return false;
	}

	uint32_t result =  knot_rdata_soa_minimum(soa);
	if (result == 0) {
		return false;
	}

	*ttl = result;
	return true;
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

	uint8_t *hash = NULL;
	size_t hash_size = 0;
	int owner_size = knot_dname_size(owner);

	if (owner_size < 0) {
		return NULL;
	}

	if (knot_nsec3_hash(params, owner, owner_size, &hash, &hash_size)
	    != KNOT_EOK) {
		return NULL;
	}

	knot_dname_t *result = knot_nsec3_hash_to_dname(hash, hash_size, zone_apex);
	free(hash);

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
int knot_zone_create_nsec_chain(const knot_zone_contents_t *zone,
                                knot_changeset_t *changeset,
                                const knot_zone_keys_t *zone_keys,
                                const knot_dnssec_policy_t *policy)
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

	if (result != KNOT_EOK) {
		return result;
	}

	// Sign newly created records right away
	return knot_zone_sign_nsecs_in_changeset(zone_keys, policy, changeset);
}

/*!
 * \brief Fix NSEC or NSEC3 chain in the zone.
 */
int knot_zone_fix_nsec_chain(const knot_zone_contents_t *zone,
                             hattrie_t *sorted_changes,
                             knot_changeset_t *out_ch,
                             const knot_zone_keys_t *zone_keys,
                             const knot_dnssec_policy_t *policy)
{
	if (zone == NULL || sorted_changes == NULL || zone_keys == NULL ||
	    policy == NULL) {
		return KNOT_EINVAL;
	}

	if (hattrie_weight(sorted_changes) == 0) {
		// no changes, no fix
		return KNOT_EOK;
	}

	// Prepare data for chain fixing functions
	chain_fix_data_t fix_data = { .zone = zone,
	                              .out_ch = out_ch,
	                              .next_dname = NULL,
	                              .chain_start = NULL,
	                              .old_connected = false,
	                              .last_used_dname = NULL,
	                              .last_used_node = NULL};
	get_zone_soa_min_ttl(zone, &fix_data.ttl);
	int ret = KNOT_EOK;
	if (knot_is_nsec3_enabled(zone)) {
		ret = knot_nsec3_fix_chain(sorted_changes, &fix_data);
	} else {

		// Fix NSEC chain
		ret = knot_nsec_fix_chain(sorted_changes, &fix_data);
	}

	dbg_dnssec_verb("NSEC(3) chain fixed (%s)\n", knot_strerror(ret));

	return ret;
}
