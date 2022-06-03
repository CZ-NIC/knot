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

#include "contrib/base32hex.h"
#include "knot/dnssec/nsec-chain.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/adjust.h"

void bitmap_add_node_rrsets(dnssec_nsec_bitmap_t *bitmap, const zone_node_t *node,
                            bool exact)
{
	bool deleg = node->flags & NODE_FLAGS_DELEG;
	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rr = node_rrset_at(node, i);
		if (deleg && (rr.type != KNOT_RRTYPE_NS && rr.type != KNOT_RRTYPE_DS &&
		              rr.type != KNOT_RRTYPE_NSEC)) {
			if (rr.type != KNOT_RRTYPE_RRSIG) {
				continue;
			}
			if (!rrsig_covers_type(&rr, KNOT_RRTYPE_DS) &&
			    !rrsig_covers_type(&rr, KNOT_RRTYPE_NSEC)) {
				continue;
			}
		}
		if (!exact && (rr.type == KNOT_RRTYPE_NSEC || rr.type == KNOT_RRTYPE_RRSIG)) {
			continue;
		}

		dnssec_nsec_bitmap_add(bitmap, rr.type);
	}
}

/* - NSEC chain construction ------------------------------------------------ */

static int create_nsec_base(knot_rrset_t *rrset, knot_dname_t *from_owner,
                            const knot_dname_t *to_owner, uint32_t ttl,
                            size_t bitmap_size, uint8_t **bitmap_writeto)
{
	knot_rrset_init(rrset, from_owner, KNOT_RRTYPE_NSEC, KNOT_CLASS_IN, ttl);

	size_t next_owner_size = knot_dname_size(to_owner);
	size_t rdsize = next_owner_size + bitmap_size;
	uint8_t rdata[rdsize];
	memcpy(rdata, to_owner, next_owner_size);

	int ret = knot_rrset_add_rdata(rrset, rdata, rdsize, NULL);

	assert(ret != KNOT_EOK || rrset->rrs.rdata->len == rdsize);
	*bitmap_writeto = rrset->rrs.rdata->data + next_owner_size;

	return ret;
}

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
                             const knot_dname_t *to, uint32_t ttl)
{
	assert(from);
	assert(to);

	dnssec_nsec_bitmap_t *rr_types = dnssec_nsec_bitmap_new();
	if (!rr_types) {
		return KNOT_ENOMEM;
	}

	bitmap_add_node_rrsets(rr_types, from, false);
	dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_NSEC);
	dnssec_nsec_bitmap_add(rr_types, KNOT_RRTYPE_RRSIG);

	uint8_t *bitmap_write;
	int ret = create_nsec_base(rrset, from->owner, to, ttl,
	                           dnssec_nsec_bitmap_size(rr_types), &bitmap_write);
	if (ret == KNOT_EOK) {
		dnssec_nsec_bitmap_write(rr_types, bitmap_write);
	}
	dnssec_nsec_bitmap_free(rr_types);

	return ret;
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
		ret = knot_nsec_changeset_remove(b, data->update);
		if (ret != KNOT_EOK) {
			return ret;
		}
		// Skip the 'b' node
		return NSEC_NODE_SKIP;
	}

	// create new NSEC
	knot_rrset_t new_nsec;
	ret = create_nsec_rrset(&new_nsec, a, b->owner, data->ttl);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_rrset_t old_nsec = node_rrset(a, KNOT_RRTYPE_NSEC);

	if (!knot_rrset_empty(&old_nsec)) {
		/* Convert old NSEC to lowercase, just in case it's not. */
		knot_rrset_t *old_nsec_lc = knot_rrset_copy(&old_nsec, NULL);
		ret = knot_rrset_rr_to_canonical(old_nsec_lc);
		if (ret != KNOT_EOK) {
			knot_rrset_free(old_nsec_lc, NULL);
			return ret;
		}

		bool equal = knot_rrset_equal(&new_nsec, old_nsec_lc, true);
		knot_rrset_free(old_nsec_lc, NULL);

		if (equal) {
			// current NSEC is valid, do nothing
			knot_rdataset_clear(&new_nsec.rrs, NULL);
			return KNOT_EOK;
		}

		ret = knot_nsec_changeset_remove(a, data->update);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(&new_nsec.rrs, NULL);
			return ret;
		}
	}

	// Add new NSEC to the changeset (no matter if old was removed)
	ret = zone_update_add(data->update, &new_nsec);
	knot_rdataset_clear(&new_nsec.rrs, NULL);
	return ret;
}

/*!
 * \brief Replace b's NSEC "next" field with a's, keeping the NSEC bitmap.
 *
 * \param a      Node to take the NSEC "next" field from.
 * \param b      Node to update the NSEC "next" field in.
 * \param data   Contains changeset to be updated.
 *
 * \return KNOT_E*
 */
static int reconnect_nsec_nodes(zone_node_t *a, zone_node_t *b,
                                nsec_chain_iterate_data_t *data)
{
	assert(a);
	assert(b);
	assert(data);

	knot_rrset_t an = node_rrset(a, KNOT_RRTYPE_NSEC);
	assert(!knot_rrset_empty(&an));

	knot_rrset_t bnorig = node_rrset(b, KNOT_RRTYPE_NSEC);
	assert(!knot_rrset_empty(&bnorig));

	size_t b_bitmap_len = knot_nsec_bitmap_len(bnorig.rrs.rdata);

	knot_rrset_t bnnew;
	uint8_t *bitmap_write;
	int ret = create_nsec_base(&bnnew, bnorig.owner, knot_nsec_next(an.rrs.rdata),
	                           bnorig.ttl, b_bitmap_len, &bitmap_write);
	if (ret == KNOT_EOK) {
		memcpy(bitmap_write, knot_nsec_bitmap(bnorig.rrs.rdata), b_bitmap_len);
	}

	ret = zone_update_remove(data->update, &bnorig);
	if (ret == KNOT_EOK) {
		ret = zone_update_add(data->update, &bnnew);
	}

	knot_rdataset_clear(&bnnew.rrs, NULL);
	return ret;
}

static bool node_no_nsec(zone_node_t *node)
{
	return ((node->flags & NODE_FLAGS_DELETED) ||
	        (node->flags & NODE_FLAGS_NONAUTH) ||
	        node->rrset_count == 0);
}

/*!
 * \brief Create or fix the node's NSEC record with correct bitmap.
 *
 * \param node          Node to fix the NSEC bitmap in.
 * \param data_voidp    NSEC creation data.
 *
 * \return KNOT_E*
 */
static int nsec_update_bitmap(zone_node_t *node,
			      nsec_chain_iterate_data_t *data)
{
	if (node_no_nsec(node) || knot_nsec_empty_nsec_and_rrsigs_in_node(node)) {
		return knot_nsec_changeset_remove(node, data->update);
	}

	knot_rrset_t old_nsec = node_rrset(node, KNOT_RRTYPE_NSEC);
	const knot_dname_t *next = knot_rrset_empty(&old_nsec) ?
	                           (const knot_dname_t *)"" :
	                           knot_nsec_next(old_nsec.rrs.rdata);
	knot_rrset_t new_nsec;
	int ret = create_nsec_rrset(&new_nsec, node, next, data->ttl);

	if (ret == KNOT_EOK && !knot_rrset_empty(&old_nsec)) {
		ret = zone_update_remove(data->update, &old_nsec);
	}
	if (ret == KNOT_EOK) {
		ret = zone_update_add(data->update, &new_nsec);
	}
	knot_rdataset_clear(&new_nsec.rrs, NULL);
	return ret;
}

static int nsec_update_bitmaps(zone_tree_t *node_ptrs,
                               nsec_chain_iterate_data_t *data)
{
	zone_tree_delsafe_it_t it = { 0 };
	int ret = zone_tree_delsafe_it_begin(node_ptrs, &it, false);
	if (ret != KNOT_EOK) {
		return ret;
	}
	while (!zone_tree_delsafe_it_finished(&it) && ret == KNOT_EOK) {
		ret = nsec_update_bitmap(zone_tree_delsafe_it_val(&it), data);
		zone_tree_delsafe_it_next(&it);
	}
	zone_tree_delsafe_it_free(&it);
	return ret;
}

static bool node_nsec3_unmatching(const zone_node_t *node, const dnssec_nsec3_params_t *params)
{
	knot_rdataset_t *nsec3 = node_rdataset(node, KNOT_RRTYPE_NSEC3);
	if (nsec3 == NULL || nsec3->count < 1 || params == NULL) {
		return false;
	}
	knot_rdata_t *rdata = nsec3->rdata;
	for (int i = 0; i < nsec3->count; i++) {
		if (knot_nsec3_alg(rdata) == params->algorithm &&
		    knot_nsec3_iters(rdata) == params->iterations &&
		    knot_nsec3_salt_len(rdata) == params->salt.size &&
		    memcmp(knot_nsec3_salt(rdata), params->salt.data, params->salt.size) == 0) {
			return false;
		}
		rdata = knot_rdataset_next(rdata);
	}
	return true;
}

int nsec_check_connect_nodes(zone_node_t *a, zone_node_t *b,
                             nsec_chain_iterate_data_t *data)
{
	if (node_no_nsec(b) || node_nsec3_unmatching(b, data->nsec3_params)) {
		return NSEC_NODE_SKIP;
	}
	knot_rdataset_t *nsec = node_rdataset(a, data->nsec_type);
	if (nsec == NULL || nsec->count != 1) {
		data->update->validation_hint.node = a->owner;
		data->update->validation_hint.rrtype = KNOT_RRTYPE_ANY;
		return KNOT_DNSSEC_ENSEC_CHAIN;
	}
	if (data->nsec_type == KNOT_RRTYPE_NSEC) {
		const knot_dname_t *a_next = knot_nsec_next(nsec->rdata);
		if (!knot_dname_is_case_equal(a_next, b->owner)) {
			data->update->validation_hint.node = a->owner;
			data->update->validation_hint.rrtype = data->nsec_type;
			return KNOT_DNSSEC_ENSEC_CHAIN;
		}
	} else {
		uint8_t next_len = knot_nsec3_next_len(nsec->rdata);
		uint8_t bdecoded[next_len];
		int len = knot_base32hex_decode(b->owner + 1, b->owner[0], bdecoded, next_len);
		if (len != next_len ||
		    memcmp(knot_nsec3_next(nsec->rdata), bdecoded, len) != 0) {
			data->update->validation_hint.node = a->owner;
			data->update->validation_hint.rrtype = data->nsec_type;
			return KNOT_DNSSEC_ENSEC_CHAIN;
		}
	}
	return KNOT_EOK;
}

static zone_node_t *nsec_prev(zone_node_t *node, const dnssec_nsec3_params_t *matching_params)
{
	zone_node_t *res = node;
	do {
		res = node_prev(res);
	} while (res != NULL && ((res->flags & NODE_FLAGS_NONAUTH) ||
	                         res->rrset_count == 0 ||
	                         node_nsec3_unmatching(res, matching_params)));
	assert(res == NULL || !knot_nsec_empty_nsec_and_rrsigs_in_node(res));
	return res;
}

static int nsec_check_prev_next(zone_node_t *node, void *ctx)
{
	if (node_no_nsec(node)) {
		return KNOT_EOK;
	}

	nsec_chain_iterate_data_t *data = ctx;
	int ret = nsec_check_connect_nodes(nsec_prev(node, data->nsec3_params), node, data);
	if (ret == NSEC_NODE_SKIP) {
		return KNOT_EOK;
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	dnssec_validation_hint_t *hint = &data->update->validation_hint;
	knot_rdataset_t *nsec = node_rdataset(node, data->nsec_type);
	if (nsec == NULL || nsec->count != 1) {
		hint->node = node->owner;
		hint->rrtype = KNOT_RRTYPE_ANY;
		return KNOT_DNSSEC_ENSEC_CHAIN;
	}

	const zone_node_t *nn;
	if (data->nsec_type == KNOT_RRTYPE_NSEC) {
		if (knot_dname_store(hint->next, knot_nsec_next(nsec->rdata)) == 0) {
			return KNOT_EINVAL;
		}
		knot_dname_to_lower(hint->next);
		nn = zone_contents_find_node(data->update->new_cont, hint->next);
	} else {
		ret = knot_nsec3_hash_to_dname(hint->next, sizeof(hint->next),
		                               knot_nsec3_next(nsec->rdata),
		                               knot_nsec3_next_len(nsec->rdata),
		                               data->update->new_cont->apex->owner);
		if (ret != KNOT_EOK) {
			return ret;
		}
		nn = zone_contents_find_nsec3_node(data->update->new_cont, hint->next);
	}
	if (nn == NULL) {
		hint->node = hint->next;
		hint->rrtype = KNOT_RRTYPE_ANY;
		return KNOT_DNSSEC_ENSEC_CHAIN;
	}
	if (nsec_prev((zone_node_t *)nn, data->nsec3_params) != node) {
		hint->node = node->owner;
		hint->rrtype = data->nsec_type;
		return KNOT_DNSSEC_ENSEC_CHAIN;
	}
	return KNOT_EOK;
}

int nsec_check_new_connects(zone_tree_t *tree, nsec_chain_iterate_data_t *data)
{
	return zone_tree_apply(tree, nsec_check_prev_next, data);
}

static int check_subtree_optout(zone_node_t *node, void *ctx)
{
	bool *res = ctx;
	if ((node->flags & NODE_FLAGS_NONAUTH) || !*res) {
		return KNOT_EOK;
	}
	if (node_nsec3_get(node) != NULL &&
	    node_rdataset(node_nsec3_get(node), KNOT_RRTYPE_NSEC3) != NULL) {
		*res = false;
	}
	return KNOT_EOK;
}

static int check_nsec_bitmap(zone_node_t *node, void *ctx)
{
	nsec_chain_iterate_data_t *data = ctx;
	assert((bool)(data->nsec_type == KNOT_RRTYPE_NSEC3) == (bool)(data->nsec3_params != NULL));
	const zone_node_t *nsec_node = node;
	bool shall_no_nsec = node_no_nsec(node);
	if (data->nsec3_params != NULL) {
		if ((node->flags & NODE_FLAGS_DELETED) ||
		    node_rrtype_exists(node, KNOT_RRTYPE_NSEC3)) {
			// this can happen when checking nodes from adjust_ptrs
			return KNOT_EOK;
		}
		nsec_node = node_nsec3_get(node);
		shall_no_nsec = (node->flags & NODE_FLAGS_DELETED) ||
		                (node->flags & NODE_FLAGS_NONAUTH);
	}
	bool may_no_nsec = (data->nsec3_params != NULL && !(node->flags & NODE_FLAGS_SUBTREE_AUTH));
	knot_rdataset_t *nsec = node_rdataset(nsec_node, data->nsec_type);
	if (may_no_nsec && nsec == NULL) {
		int ret = zone_tree_sub_apply(data->update->new_cont->nodes, node->owner,
		                              true, check_subtree_optout, &may_no_nsec);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	if ((nsec == NULL || nsec->count != 1) && !shall_no_nsec && !may_no_nsec) {
		data->update->validation_hint.node = (nsec_node == NULL ? node->owner : nsec_node->owner);
		data->update->validation_hint.rrtype = KNOT_RRTYPE_ANY;
		return KNOT_DNSSEC_ENONSEC;
	}
	if (shall_no_nsec && nsec != NULL && nsec->count > 0) {
		data->update->validation_hint.node = nsec_node->owner;
		data->update->validation_hint.rrtype = data->nsec_type;
		return KNOT_DNSSEC_ENSEC_BITMAP;
	}
	if (shall_no_nsec) {
		return KNOT_EOK;
	}
	if (may_no_nsec && nsec == NULL) {
		assert(data->nsec_type == KNOT_RRTYPE_NSEC3);
		const zone_node_t *found_nsec3 = NULL, *prev_nsec3 = NULL;
		if (node->nsec3_hash == NULL ||
		    zone_contents_find_nsec3(data->update->new_cont, node->nsec3_hash, &found_nsec3, &prev_nsec3) != ZONE_NAME_NOT_FOUND ||
		    found_nsec3 != NULL) {
			return KNOT_ERROR;
		}
		if (prev_nsec3 == NULL) {
			data->update->validation_hint.node = (nsec_node == NULL ? node->owner : nsec_node->owner);
			data->update->validation_hint.rrtype = KNOT_RRTYPE_ANY;
			return KNOT_DNSSEC_ENONSEC;
		}
		knot_rdataset_t *nsec3 = node_rdataset(prev_nsec3, KNOT_RRTYPE_NSEC3);
		if (nsec3 == NULL) {
			return KNOT_ERROR;
		}
		if (nsec3->count != 1 || !(knot_nsec3param_flags(nsec3->rdata) & KNOT_NSEC3_FLAG_OPT_OUT)) {
			data->update->validation_hint.node = prev_nsec3->owner;
			data->update->validation_hint.rrtype = data->nsec_type;
			return KNOT_DNSSEC_ENSEC3_OPTOUT;
		}
		return KNOT_EOK;
	}

	dnssec_nsec_bitmap_t *rr_types = dnssec_nsec_bitmap_new();
	if (rr_types == NULL) {
		return KNOT_ENOMEM;
	}
	bitmap_add_node_rrsets(rr_types, node, true);

	uint16_t node_wire_size = dnssec_nsec_bitmap_size(rr_types);
	uint8_t *node_wire = malloc(node_wire_size);
	if (node_wire == NULL) {
		dnssec_nsec_bitmap_free(rr_types);
		return KNOT_ENOMEM;
	}
	dnssec_nsec_bitmap_write(rr_types, node_wire);
	dnssec_nsec_bitmap_free(rr_types);

	const uint8_t *nsec_wire = NULL;
	uint16_t nsec_wire_size = 0;
	if (data->nsec3_params == NULL) {
		nsec_wire = knot_nsec_bitmap(nsec->rdata);
		nsec_wire_size = knot_nsec_bitmap_len(nsec->rdata);
	} else {
		nsec_wire = knot_nsec3_bitmap(nsec->rdata);
		nsec_wire_size = knot_nsec3_bitmap_len(nsec->rdata);
	}

	if (node_wire_size != nsec_wire_size ||
	    memcmp(node_wire, nsec_wire, node_wire_size) != 0) {
		free(node_wire);
		data->update->validation_hint.node = node->owner;
		data->update->validation_hint.rrtype = data->nsec_type;
		return KNOT_DNSSEC_ENSEC_BITMAP;
	}
	free(node_wire);
	return KNOT_EOK;
}

int nsec_check_bitmaps(zone_tree_t *nsec_ptrs, nsec_chain_iterate_data_t *data)
{
	return zone_tree_apply(nsec_ptrs, check_nsec_bitmap, data);
}

/*! \brief Return the one from those nodes which has
 * closest lower (lexicographically) owner name to ref. */
static zone_node_t *node_nearer(zone_node_t *a, zone_node_t *b, zone_node_t *ref)
{
	if (a == NULL || a == b) {
		return b;
	} else if (b == NULL) {
		return a;
	} else {
		int abigger = knot_dname_cmp(a->owner, ref->owner) >= 0 ? 1 : 0;
		int bbigger = knot_dname_cmp(b->owner, ref->owner) >= 0 ? 1 : 0;
		int cmp = knot_dname_cmp(a->owner, b->owner);
		if (abigger != bbigger) {
			cmp = -cmp;
		}
		return cmp < 0 ? b : a;
	}
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

	zone_tree_delsafe_it_t it = { 0 };
	int result = zone_tree_delsafe_it_begin(nodes, &it, false);
	if (result != KNOT_EOK) {
		return result;
	}

	if (zone_tree_delsafe_it_finished(&it)) {
		zone_tree_delsafe_it_free(&it);
		return KNOT_EINVAL;
	}

	zone_node_t *first = zone_tree_delsafe_it_val(&it);
	zone_node_t *previous = first;
	zone_node_t *current = first;

	zone_tree_delsafe_it_next(&it);

	while (!zone_tree_delsafe_it_finished(&it)) {
		current = zone_tree_delsafe_it_val(&it);

		result = callback(previous, current, data);
		if (result == NSEC_NODE_SKIP) {
			// No NSEC should be created for 'current' node, skip
			;
		} else if (result == KNOT_EOK) {
			previous = current;
		} else {
			zone_tree_delsafe_it_free(&it);
			return result;
		}
		zone_tree_delsafe_it_next(&it);
	}

	zone_tree_delsafe_it_free(&it);

	return result == NSEC_NODE_SKIP ? callback(previous, first, data) :
	                 callback(current, first, data);
}

int knot_nsec_chain_iterate_fix(zone_tree_t *node_ptrs,
                                chain_iterate_create_cb callback,
                                chain_iterate_create_cb cb_reconn,
                                nsec_chain_iterate_data_t *data)
{
	zone_tree_delsafe_it_t it = { 0 };
	int ret = zone_tree_delsafe_it_begin(node_ptrs, &it, true);
	if (ret != KNOT_EOK) {
		return ret;
	}

	zone_node_t *prev_it = NULL;
	zone_node_t *started_with = NULL;
	while (ret == KNOT_EOK) {
		if (zone_tree_delsafe_it_finished(&it)) {
			assert(started_with != NULL);
			zone_tree_delsafe_it_restart(&it);
		}

		zone_node_t *curr_new = zone_tree_delsafe_it_val(&it);
		zone_node_t *curr_old = binode_counterpart(curr_new);
		bool del_new = node_no_nsec(curr_new);
		bool del_old = node_no_nsec(curr_old);

		if (started_with == curr_new) {
			assert(started_with != NULL);
			break;
		}
		if (!del_old && !del_new && started_with == NULL) {
			// Once this must happen since the NSEC(3) node belonging
			// to zone apex is always present.
			started_with = curr_new;
		}

		if (!del_old && del_new && started_with != NULL) {
			zone_node_t *prev_old = curr_old, *prev_new;
			do {
				prev_old = nsec_prev(prev_old, NULL);
				prev_new = binode_counterpart(prev_old);
			} while (node_no_nsec(prev_new));

			zone_node_t *prev_near = node_nearer(prev_new, prev_it, curr_old);
			ret = cb_reconn(curr_old, prev_near, data);
		}
		if (del_old && !del_new && started_with != NULL) {
			zone_node_t *prev_new = nsec_prev(curr_new, NULL);
			ret = cb_reconn(prev_new, curr_new, data);
			if (ret == KNOT_EOK) {
				ret = callback(prev_new, curr_new, data);
			}
			prev_it = curr_new;
		}

		zone_tree_delsafe_it_next(&it);
	}
	zone_tree_delsafe_it_free(&it);
	return ret;
}

/* - API - utility functions ------------------------------------------------ */

/*!
 * \brief Add entry for removed NSEC to the changeset.
 */
int knot_nsec_changeset_remove(const zone_node_t *n, zone_update_t *update)
{
	if (update == NULL) {
		return KNOT_EINVAL;
	}

	int result = KNOT_EOK;
	knot_rrset_t nsec_rem = node_rrset(n, KNOT_RRTYPE_NSEC);
	knot_rrset_t nsec3_rem = node_rrset(n, KNOT_RRTYPE_NSEC3);
	knot_rrset_t rrsigs = node_rrset(n, KNOT_RRTYPE_RRSIG);

	if (!knot_rrset_empty(&nsec_rem)) {
		result = zone_update_remove(update, &nsec_rem);
	}
	if (result == KNOT_EOK && !knot_rrset_empty(&nsec3_rem)) {
		result = zone_update_remove(update, &nsec3_rem);
	}
	if (!knot_rrset_empty(&rrsigs) && result == KNOT_EOK) {
		knot_rrset_t synth_rrsigs;
		knot_rrset_init(&synth_rrsigs, n->owner, KNOT_RRTYPE_RRSIG,
		                KNOT_CLASS_IN, rrsigs.ttl);
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
		result = zone_update_remove(update, &synth_rrsigs);
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
int knot_nsec_create_chain(zone_update_t *update, uint32_t ttl)
{
	assert(update);
	assert(update->new_cont->nodes);

	nsec_chain_iterate_data_t data = { ttl, update, KNOT_RRTYPE_NSEC };

	return knot_nsec_chain_iterate_create(update->new_cont->nodes,
	                                      connect_nsec_nodes, &data);
}

int knot_nsec_fix_chain(zone_update_t *update, uint32_t ttl)
{
	assert(update);
	assert(update->zone->contents->nodes);
	assert(update->new_cont->nodes);

	nsec_chain_iterate_data_t data = { ttl, update, KNOT_RRTYPE_NSEC };

	int ret = nsec_update_bitmaps(update->a_ctx->node_ptrs, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_adjust_contents(update->new_cont, adjust_cb_void, NULL, false, true, 1, update->a_ctx->node_ptrs);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// ensure that zone root is in list of changed nodes
	ret = zone_tree_insert(update->a_ctx->node_ptrs, &update->new_cont->apex);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return knot_nsec_chain_iterate_fix(update->a_ctx->node_ptrs,
					   connect_nsec_nodes, reconnect_nsec_nodes, &data);
}

int knot_nsec_check_chain(zone_update_t *update)
{
	if (!zone_tree_is_empty(update->new_cont->nsec3_nodes)) {
		update->validation_hint.node = update->zone->name;
		update->validation_hint.rrtype = KNOT_RRTYPE_NSEC3;
		return KNOT_DNSSEC_ENSEC_BITMAP;
	}

	nsec_chain_iterate_data_t data = { 0, update, KNOT_RRTYPE_NSEC };

	int ret = nsec_check_bitmaps(update->new_cont->nodes, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return knot_nsec_chain_iterate_create(update->new_cont->nodes,
					      nsec_check_connect_nodes, &data);
}

int knot_nsec_check_chain_fix(zone_update_t *update)
{
	if (!zone_tree_is_empty(update->new_cont->nsec3_nodes)) {
		update->validation_hint.node = update->zone->name;
		update->validation_hint.rrtype = KNOT_RRTYPE_NSEC3;
		return KNOT_DNSSEC_ENSEC_BITMAP;
	}

	nsec_chain_iterate_data_t data = { 0, update, KNOT_RRTYPE_NSEC };

	int ret = nsec_check_bitmaps(update->a_ctx->node_ptrs, &data);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return nsec_check_new_connects(update->a_ctx->node_ptrs, &data);
}
