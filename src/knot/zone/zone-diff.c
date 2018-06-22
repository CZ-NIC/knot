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
#include <stdlib.h>
#include <inttypes.h>

#include "libknot/libknot.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/serial.h"

struct zone_diff_param {
	zone_tree_t *nodes;
	changeset_t *changeset;
	bool ignore_dnssec;
};

static bool rrset_is_dnssec(const knot_rrset_t *rrset)
{
	switch (rrset->type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		return true;
	default:
		return false;
	}
}

static int load_soas(const zone_contents_t *zone1, const zone_contents_t *zone2,
                     changeset_t *changeset)
{
	assert(zone1);
	assert(zone2);
	assert(changeset);

	const zone_node_t *apex1 = zone1->apex;
	const zone_node_t *apex2 = zone2->apex;
	if (apex1 == NULL || apex2 == NULL) {
		return KNOT_EINVAL;
	}

	knot_rrset_t soa_rrset1 = node_rrset(apex1, KNOT_RRTYPE_SOA);
	knot_rrset_t soa_rrset2 = node_rrset(apex2, KNOT_RRTYPE_SOA);
	if (knot_rrset_empty(&soa_rrset1) || knot_rrset_empty(&soa_rrset2)) {
		return KNOT_EINVAL;
	}

	if (soa_rrset1.rrs.count == 0 ||
	    soa_rrset2.rrs.count == 0) {
		return KNOT_EINVAL;
	}

	uint32_t soa_serial1 = knot_soa_serial(soa_rrset1.rrs.rdata);
	uint32_t soa_serial2 = knot_soa_serial(soa_rrset2.rrs.rdata);

	if (serial_compare(soa_serial1, soa_serial2) == SERIAL_EQUAL) {
		return KNOT_ENODIFF;
	}

	if (serial_compare(soa_serial1, soa_serial2) != SERIAL_LOWER) {
		return KNOT_ERANGE;
	}

	changeset->soa_from = knot_rrset_copy(&soa_rrset1, NULL);
	if (changeset->soa_from == NULL) {
		return KNOT_ENOMEM;
	}
	changeset->soa_to = knot_rrset_copy(&soa_rrset2, NULL);
	if (changeset->soa_to == NULL) {
		knot_rrset_free(changeset->soa_from, NULL);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int add_node(const zone_node_t *node, changeset_t *changeset, bool ignore_dnssec)
{
	/* Add all rrsets from node. */
	for (unsigned i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);

		if (ignore_dnssec && rrset_is_dnssec(&rrset)) {
			continue;
		}

		int ret = changeset_add_addition(changeset, &rrset, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int remove_node(const zone_node_t *node, changeset_t *changeset, bool ignore_dnssec)
{
	/* Remove all the RRSets of the node. */
	for (unsigned i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);

		if (ignore_dnssec && rrset_is_dnssec(&rrset)) {
			continue;
		}

		int ret = changeset_add_removal(changeset, &rrset, 0);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int rdata_return_changes(const knot_rrset_t *rrset1,
                                const knot_rrset_t *rrset2,
                                knot_rrset_t *changes)
{
	if (rrset1 == NULL || rrset2 == NULL) {
		return KNOT_EINVAL;
	}

	/* Create fake RRSet, it will be easier to handle. */
	knot_rrset_init(changes, rrset1->owner, rrset1->type, rrset1->rclass, rrset1->ttl);

	/*
	* Take one rdata from first list and search through the second list
	* looking for an exact match. If no match occurs, it means that this
	* particular RR has changed.
	* After the list has been traversed, we have a list of
	* changed/removed rdatas. This has awful computation time.
	*/
	bool ttl_differ = rrset1->ttl != rrset2->ttl;
	knot_rdata_t *rr1 = rrset1->rrs.rdata;
	for (uint16_t i = 0; i < rrset1->rrs.count; ++i) {
		if (ttl_differ || !knot_rdataset_member(&rrset2->rrs, rr1)) {
			/*
			 * No such RR is present in 'rrset2'. We'll copy
			 * index 'i' into 'changes' RRSet.
			 */
			int ret = knot_rdataset_add(&changes->rrs, rr1, NULL);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(&changes->rrs, NULL);
				return ret;
			}
		}
		rr1 = knot_rdataset_next(rr1);
	}

	return KNOT_EOK;
}

static int diff_rrsets(const knot_rrset_t *rrset1, const knot_rrset_t *rrset2,
                       changeset_t *changeset)
{
	if (changeset == NULL || (rrset1 == NULL && rrset2 == NULL)) {
		return KNOT_EINVAL;
	}
	/*
	 * The easiest solution is to remove all the RRs that had no match and
	 * to add all RRs that had no match, but those from second RRSet. */

	/* Get RRs to add to zone and to remove from zone. */
	knot_rrset_t to_remove;
	knot_rrset_t to_add;
	if (rrset1 != NULL && rrset2 != NULL) {
		int ret = rdata_return_changes(rrset1, rrset2, &to_remove);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = rdata_return_changes(rrset2, rrset1, &to_add);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (!knot_rrset_empty(&to_remove)) {
		int ret = changeset_add_removal(changeset, &to_remove, 0);
		knot_rdataset_clear(&to_remove.rrs, NULL);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(&to_add.rrs, NULL);
			return ret;
		}
	}

	if (!knot_rrset_empty(&to_add)) {
		int ret = changeset_add_addition(changeset, &to_add, 0);
		knot_rdataset_clear(&to_add.rrs, NULL);
		return ret;
	}

	return KNOT_EOK;
}

/*!< \todo this could be generic function for adding / removing. */
static int knot_zone_diff_node(zone_node_t **node_ptr, void *data)
{
	if (node_ptr == NULL || *node_ptr == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	zone_node_t *node = *node_ptr;

	struct zone_diff_param *param = (struct zone_diff_param *)data;
	if (param->changeset == NULL) {
		return KNOT_EINVAL;
	}

	/*
	 * First, we have to search the second tree to see if there's according
	 * node, if not, the whole node has been removed.
	 */
	zone_node_t *node_in_second_tree = zone_tree_get(param->nodes, node->owner);
	if (node_in_second_tree == NULL) {
		return remove_node(node, param->changeset, param->ignore_dnssec);
	}

	assert(node_in_second_tree != node);

	/* The nodes are in both trees, we have to diff each RRSet. */
	if (node->rrset_count == 0) {
		/*
		 * If there are no RRs in the first tree, all of the RRs
		 * in the second tree will have to be inserted to ADD section.
		 */
		return add_node(node_in_second_tree, param->changeset, param->ignore_dnssec);
	}

	for (unsigned i = 0; i < node->rrset_count; i++) {
		/* Search for the RRSet in the node from the second tree. */
		knot_rrset_t rrset = node_rrset_at(node, i);

		/* SOAs are handled explicitly. */
		if (rrset.type == KNOT_RRTYPE_SOA) {
			continue;
		}

		if (param->ignore_dnssec && rrset_is_dnssec(&rrset)) {
			continue;
		}

		knot_rrset_t rrset_from_second_node =
			node_rrset(node_in_second_tree, rrset.type);
		if (knot_rrset_empty(&rrset_from_second_node)) {
			/* RRSet has been removed. Make a copy and remove. */
			int ret = changeset_add_removal(
				param->changeset, &rrset, 0);
			if (ret != KNOT_EOK) {
				return ret;
			}
		} else {
			/* Diff RRSets. */
			int ret = diff_rrsets(&rrset, &rrset_from_second_node,
			                      param->changeset);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	for (unsigned i = 0; i < node_in_second_tree->rrset_count; i++) {
		/* Search for the RRSet in the node from the second tree. */
		knot_rrset_t rrset = node_rrset_at(node_in_second_tree, i);

		/* SOAs are handled explicitly. */
		if (rrset.type == KNOT_RRTYPE_SOA) {
			continue;
		}

		if (param->ignore_dnssec && rrset_is_dnssec(&rrset)) {
			continue;
		}

		knot_rrset_t rrset_from_first_node = node_rrset(node, rrset.type);
		if (knot_rrset_empty(&rrset_from_first_node)) {
			/* RRSet has been added. Make a copy and add. */
			int ret = changeset_add_addition(
				param->changeset, &rrset, 0);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

/*!< \todo possibly not needed! */
static int add_new_nodes(zone_node_t **node_ptr, void *data)
{
	if (node_ptr == NULL || *node_ptr == NULL || data == NULL) {
		return KNOT_EINVAL;
	}

	zone_node_t *node = *node_ptr;

	struct zone_diff_param *param = (struct zone_diff_param *)data;
	if (param->changeset == NULL) {
		return KNOT_EINVAL;
	}

	/*
	* If a node is not present in the second zone, it is a new node
	* and has to be added to changeset. Differencies on the RRSet level are
	* already handled.
	*/
	zone_node_t *new_node = zone_tree_get(param->nodes, node->owner);
	if (new_node == NULL) {
		assert(node);
		return add_node(node, param->changeset, param->ignore_dnssec);
	}

	return KNOT_EOK;
}

static int load_trees(zone_tree_t *nodes1, zone_tree_t *nodes2,
		      changeset_t *changeset, bool ignore_dnssec)
{
	assert(changeset);

	struct zone_diff_param param = {
		.changeset = changeset,
		.ignore_dnssec = ignore_dnssec,
	};

	// Traverse one tree, compare every node, each RRSet with its rdata.
	param.nodes = nodes2;
	int ret = zone_tree_apply(nodes1, knot_zone_diff_node, &param);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Some nodes may have been added. Add missing nodes to changeset.
	param.nodes = nodes1;
	return zone_tree_apply(nodes2, add_new_nodes, &param);
}

int zone_contents_diff(const zone_contents_t *zone1, const zone_contents_t *zone2,
		       changeset_t *changeset, bool ignore_dnssec)
{
	if (zone1 == NULL || zone2 == NULL || changeset == NULL) {
		return KNOT_EINVAL;
	}

	int ret_soa = load_soas(zone1, zone2, changeset);
	if (ret_soa != KNOT_EOK && ret_soa != KNOT_ENODIFF) {
		return ret_soa;
	}

	int ret = load_trees(zone1->nodes, zone2->nodes, changeset, ignore_dnssec);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = load_trees(zone1->nsec3_nodes, zone2->nsec3_nodes, changeset, ignore_dnssec);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (ret_soa == KNOT_ENODIFF && !changeset_empty(changeset)) {
		return KNOT_ESEMCHECK;
	}

	return ret_soa;
}

int zone_tree_add_diff(zone_tree_t *t1, zone_tree_t *t2, changeset_t *changeset)
{
	if (changeset == NULL) {
		return KNOT_EINVAL;
	}

	return load_trees(t1, t2, changeset, false);
}
