/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>

#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"

/* - NSEC chain construction ------------------------------------------------ */

/*!
 * \brief Create NSEC RR set.
 *
 * \param rrset      RRSet to be initialized.
 * \param from       Node that should contain the new RRSet.
 * \param to         Node that should be pointed to from 'from'.
 * \param ttl        Record TTL (SOA's minimum TTL).
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int create_nsec_rrset(knot_rrset_t *rrset, const zone_node_t *from,
                             const zone_node_t *to, uint32_t ttl)
{
	assert(from);
	assert(to);
	knot_rrset_init(rrset, from->owner, KNOT_RRTYPE_NSEC, KNOT_CLASS_IN);

	// Create bitmap
	dnssec_nsec_bitmap_t *rr_types = dnssec_nsec_bitmap_new();
	if (!rr_types) {
		return KNOT_ENOMEM;
	}

	bitmap_add_node_rrsets(rr_types, KNOT_RRTYPE_NSEC, from);
	dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_NSEC);
	dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_RRSIG);
	if (node_rrtype_exists(from, KNOT_RRTYPE_SOA)) {
		dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_DNSKEY);
	}

	// Create RDATA
	assert(to->owner);
	size_t next_owner_size = knot_dname_size(to->owner);
	size_t rdata_size = next_owner_size + dnssec_nsec_bitmap_size(rr_types);
	uint8_t rdata[rdata_size];

	// Fill RDATA
	memcpy(rdata, to->owner, next_owner_size);
	dnssec_nsec_bitmap_write(rr_types, rdata + next_owner_size);
	dnssec_nsec_bitmap_free(rr_types);

	return knot_rrset_add_rdata(rrset, rdata, rdata_size, ttl, NULL);
}

/*!
 * \brief Connect two nodes by adding a NSEC RR into the first node.
 *
 * Callback function, signature chain_iterate_cb.
 *
 * \param a     First node.
 * \param b     Second node (immediate follower of a).
 * \param data  Pointer to nsec_chain_iterate_data_t holding parameters
 *              including changeset.
 *
 * \return Error code, KNOT_EOK if successful.
 */
static int connect_nsec_nodes(zone_node_t *a, zone_node_t *b,
                              nsec_chain_iterate_data_t *data)
{
	assert(a);
	assert(b);
	assert(data);

	if (b->rrset_count == 0 || b->flags & NODE_FLAGS_NONAUTH) {
		return NSEC_NODE_SKIP;
	}

	int ret = KNOT_EOK;

	/*!
	 * If the node has no other RRSets than NSEC (and possibly RRSIGs),
	 * just remove the NSEC and its RRSIG, they are redundant
	 */
	if (node_rrtype_exists(b, KNOT_RRTYPE_NSEC)
	    && knot_nsec_empty_nsec_and_rrsigs_in_node(b)) {
		ret = knot_nsec_changeset_remove(b, data->changeset);
		if (ret != KNOT_EOK) {
			return ret;
		}
		// Skip the 'b' node
		return NSEC_NODE_SKIP;
	}

	// create new NSEC
	knot_rrset_t new_nsec;
	ret = create_nsec_rrset(&new_nsec, a, b, data->ttl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t old_nsec = node_rrset(a, KNOT_RRTYPE_NSEC);

	if (!knot_rrset_empty(&old_nsec)) {
		/* Convert old NSEC to lowercase, just in case it's not. */
		knot_rrset_t *old_nsec_lc = knot_rrset_copy(&old_nsec, NULL);
		ret = knot_rrset_rr_to_canonical(old_nsec_lc);
		if (ret != KNOT_EOK) {
			knot_rrset_free(&old_nsec_lc, NULL);
			return ret;
		}

		bool equal = knot_rrset_equal(&new_nsec, old_nsec_lc,
		                              KNOT_RRSET_COMPARE_WHOLE);
		knot_rrset_free(&old_nsec_lc, NULL);

		if (equal) {
			// current NSEC is valid, do nothing
			knot_rdataset_clear(&new_nsec.rrs, NULL);
			return KNOT_EOK;
		}

		// Mark the node so that we do not sign this NSEC
		a->flags |= NODE_FLAGS_REMOVED_NSEC;
		ret = knot_nsec_changeset_remove(a, data->changeset);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(&new_nsec.rrs, NULL);
			return ret;
		}
	}

	// Add new NSEC to the changeset (no matter if old was removed)
	ret = changeset_add_rrset(data->changeset, &new_nsec, 0);
	knot_rdataset_clear(&new_nsec.rrs, NULL);
	return ret;
}

/* - API - iterations ------------------------------------------------------- */

/*!
 * \brief Call a function for each piece of the chain formed by sorted nodes.
 */
int knot_nsec_chain_iterate_create(zone_tree_t *nodes,
                                   chain_iterate_create_cb callback,
                                   nsec_chain_iterate_data_t *data)
{
	assert(nodes);
	assert(callback);

	bool sorted = true;
	hattrie_iter_t *it = hattrie_iter_begin(nodes, sorted);

	if (!it) {
		return KNOT_ENOMEM;
	}

	if (hattrie_iter_finished(it)) {
		hattrie_iter_free(it);
		return KNOT_EINVAL;
	}

	zone_node_t *first = (zone_node_t *)*hattrie_iter_val(it);
	zone_node_t *previous = first;
	zone_node_t *current = first;

	hattrie_iter_next(it);

	int result = KNOT_EOK;
	while (!hattrie_iter_finished(it)) {
		current = (zone_node_t *)*hattrie_iter_val(it);

		result = callback(previous, current, data);
		if (result == NSEC_NODE_SKIP) {
			// No NSEC should be created for 'current' node, skip
			;
		} else if (result == KNOT_EOK) {
			previous = current;
		} else {
			hattrie_iter_free(it);
			return result;
		}
		hattrie_iter_next(it);
	}

	hattrie_iter_free(it);

	return result == NSEC_NODE_SKIP ? callback(previous, first, data) :
	                 callback(current, first, data);
}

/* - API - utility functions ------------------------------------------------ */

/*!
 * \brief Add entry for removed NSEC to the changeset.
 */
int knot_nsec_changeset_remove(const zone_node_t *n,
                               changeset_t *changeset)
{
	if (changeset == NULL) {
		return KNOT_EINVAL;
	}

	int result = KNOT_EOK;

	knot_rrset_t nsec = node_rrset(n, KNOT_RRTYPE_NSEC);
	if (knot_rrset_empty(&nsec)) {
		nsec = node_rrset(n, KNOT_RRTYPE_NSEC3);
	}
	if (!knot_rrset_empty(&nsec)) {
		// update changeset
		result = changeset_rem_rrset(changeset, &nsec, 0);
		if (result != KNOT_EOK) {
			return result;
		}
	}

	knot_rrset_t rrsigs = node_rrset(n, KNOT_RRTYPE_RRSIG);
	if (!knot_rrset_empty(&rrsigs)) {
		knot_rrset_t synth_rrsigs;
		knot_rrset_init(&synth_rrsigs, n->owner, KNOT_RRTYPE_RRSIG,
		                KNOT_CLASS_IN);
		result = knot_synth_rrsig(KNOT_RRTYPE_NSEC, &rrsigs.rrs,
		                          &synth_rrsigs.rrs, NULL);
		if (result == KNOT_ENOENT) {
			// Try removing NSEC3 RRSIGs
			result = knot_synth_rrsig(KNOT_RRTYPE_NSEC3, &rrsigs.rrs,
			                          &synth_rrsigs.rrs, NULL);
		}

		if (result != KNOT_EOK) {
			knot_rdataset_clear(&synth_rrsigs.rrs, NULL);
			if (result != KNOT_ENOENT) {
				return result;
			}
			return KNOT_EOK;
		}

		// store RRSIG
		result = changeset_rem_rrset(changeset, &synth_rrsigs, 0);
		knot_rdataset_clear(&synth_rrsigs.rrs, NULL);
	}

	return result;
}

/*!
 * \brief Checks whether the node is empty or eventually contains only NSEC and
 *        RRSIGs.
 */
bool knot_nsec_empty_nsec_and_rrsigs_in_node(const zone_node_t *n)
{
	assert(n);
	for (int i = 0; i < n->rrset_count; ++i) {
		knot_rrset_t rrset = node_rrset_at(n, i);
		if (rrset.type != KNOT_RRTYPE_NSEC &&
		    rrset.type != KNOT_RRTYPE_RRSIG) {
			return false;
		}
	}

	return true;
}

/* - API - Chain creation --------------------------------------------------- */

/*!
 * \brief Create new NSEC chain, add differences from current into a changeset.
 */
int knot_nsec_create_chain(const zone_contents_t *zone, uint32_t ttl,
                           changeset_t *changeset)
{
	assert(zone);
	assert(zone->nodes);
	assert(changeset);

	nsec_chain_iterate_data_t data = { ttl, changeset, zone };

	return knot_nsec_chain_iterate_create(zone->nodes,
	                                      connect_nsec_nodes, &data);
}
