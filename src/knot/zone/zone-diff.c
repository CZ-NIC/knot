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
#include <stdlib.h>
#include <inttypes.h>

#include "common/debug.h"
#include "libknot/errcode.h"
#include "knot/zone/zone-diff.h"
#include "libknot/descriptor.h"
#include "libknot/util/utils.h"
#include "libknot/rrtype/soa.h"

struct zone_diff_param {
	zone_tree_t *nodes;
	changeset_t *changeset;
};

// forward declaration
static int knot_zone_diff_rdata(const knot_rrset_t *rrset1,
                                const knot_rrset_t *rrset2,
                                changeset_t *changeset);

static int knot_zone_diff_load_soas(const zone_contents_t *zone1,
                                    const zone_contents_t *zone2,
                                    changeset_t *changeset)
{
	if (zone1 == NULL || zone2 == NULL || changeset == NULL) {
		return KNOT_EINVAL;
	}

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

	if (soa_rrset1.rrs.rr_count == 0 ||
	    soa_rrset2.rrs.rr_count == 0) {
		return KNOT_EINVAL;
	}

	int64_t soa_serial1 = knot_soa_serial(&soa_rrset1.rrs);
	int64_t soa_serial2 = knot_soa_serial(&soa_rrset2.rrs);

	if (knot_serial_compare(soa_serial1, soa_serial2) == 0) {
		return KNOT_ENODIFF;
	}

	if (knot_serial_compare(soa_serial1, soa_serial2) > 0) {
		return KNOT_ERANGE;
	}

	assert(changeset);

	changeset->soa_from = knot_rrset_copy(&soa_rrset1, NULL);
	if (changeset->soa_from == NULL) {
		return KNOT_ENOMEM;
	}
	changeset->soa_to = knot_rrset_copy(&soa_rrset2, NULL);
	if (changeset->soa_to == NULL) {
		knot_rrset_free(&changeset->soa_from, NULL);
		return KNOT_ENOMEM;
	}

	dbg_zonediff_verb("zone_diff: load_soas: SOAs diffed. "
	                  "(%"PRId64" -> %"PRId64")\n",
	                  soa_serial1, soa_serial2);

	return KNOT_EOK;
}

static int knot_zone_diff_add_node(const zone_node_t *node,
                                   changeset_t *changeset)
{
	/* Add all rrsets from node. */
	for (uint i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		int ret = changeset_add_rrset(changeset, &rrset);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: add_node: Cannot add RRSet (%s).\n",
			             knot_strerror(ret));
			return ret;
		}
	}

	return KNOT_EOK;
}

static int knot_zone_diff_remove_node(changeset_t *changeset,
                                      const zone_node_t *node)
{
	/* Remove all the RRSets of the node. */
	for (uint i = 0; i < node->rrset_count; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		int ret = changeset_rem_rrset(changeset, &rrset);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: remove_node: Failed to "
			             "remove rrset. Error: %s\n",
			             knot_strerror(ret));
			return ret;
		}
	}

	return KNOT_EOK;
}

static bool rr_exists(const knot_rrset_t *in, const knot_rrset_t *ref,
                      size_t ref_pos)
{
	knot_rdata_t *to_check = knot_rdataset_at(&ref->rrs, ref_pos);
	const bool compare_ttls = true;
	return knot_rdataset_member(&in->rrs, to_check, compare_ttls);
}

static int knot_zone_diff_rdata_return_changes(const knot_rrset_t *rrset1,
                                               const knot_rrset_t *rrset2,
                                               knot_rrset_t *changes)
{
	if (rrset1 == NULL || rrset2 == NULL) {
		dbg_zonediff("zone_diff: diff_rdata: NULL arguments. (%p) (%p).\n",
		             rrset1, rrset2);
		return KNOT_EINVAL;
	}

	/*
	* Take one rdata from first list and search through the second list
	* looking for an exact match. If no match occurs, it means that this
	* particular RR has changed.
	* After the list has been traversed, we have a list of
	* changed/removed rdatas. This has awful computation time.
	*/

	/* Create fake RRSet, it will be easier to handle. */
	knot_rrset_init(changes, rrset1->owner, rrset1->type, rrset1->rclass);

	const rdata_descriptor_t *desc = knot_get_rdata_descriptor(rrset1->type);
	assert(desc);

	uint16_t rr1_count = rrset1->rrs.rr_count;
	for (uint16_t i = 0; i < rr1_count; ++i) {
		if (!rr_exists(rrset2, rrset1, i)) {
			/*
			 * No such RR is present in 'rrset2'. We'll copy
			 * index 'i' into 'changes' RRSet.
			 */
			knot_rdata_t *add_rr = knot_rdataset_at(&rrset1->rrs, i);
			int ret = knot_rdataset_add(&changes->rrs, add_rr, NULL);
			if (ret != KNOT_EOK) {
				knot_rdataset_clear(&changes->rrs, NULL);
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int knot_zone_diff_rdata(const knot_rrset_t *rrset1,
                                const knot_rrset_t *rrset2,
                                changeset_t *changeset)
{
	if ((changeset == NULL) || (rrset1 == NULL && rrset2 == NULL)) {
		return KNOT_EINVAL;
	}
	/*
	 * The easiest solution is to remove all the RRs that had no match and
	 * to add all RRs that had no match, but those from second RRSet. */

	/* Get RRs to add to zone and to remove from zone. */
	knot_rrset_t to_remove;
	knot_rrset_t to_add;
	if (rrset1 != NULL && rrset2 != NULL) {
		int ret = knot_zone_diff_rdata_return_changes(rrset1, rrset2,
		                                              &to_remove);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = knot_zone_diff_rdata_return_changes(rrset2, rrset1,
		                                          &to_add);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (!knot_rrset_empty(&to_remove)) {
		int ret = changeset_rem_rrset(changeset, &to_remove);
		knot_rdataset_clear(&to_remove.rrs, NULL);
		if (ret != KNOT_EOK) {
			knot_rdataset_clear(&to_add.rrs, NULL);
			return ret;
		}
	}

	if (!knot_rrset_empty(&to_add)) {
		int ret = changeset_add_rrset(changeset, &to_add);
		knot_rdataset_clear(&to_add.rrs, NULL);
		return ret;
	}

	return KNOT_EOK;
}

static int knot_zone_diff_rrsets(const knot_rrset_t *rrset1,
                                 const knot_rrset_t *rrset2,
                                 changeset_t *changeset)
{
	/* RRs (=rdata) have to be cross-compared, unfortunalely. */
	return knot_zone_diff_rdata(rrset1, rrset2, changeset);
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
	const zone_node_t *node_in_second_tree = NULL;
	const knot_dname_t *node_owner = node->owner;
	assert(node_owner);

	zone_tree_find(param->nodes, node_owner, &node_in_second_tree);

	if (node_in_second_tree == NULL) {
		return knot_zone_diff_remove_node(param->changeset, node);
	}

	assert(node_in_second_tree != node);

	/* The nodes are in both trees, we have to diff each RRSet. */
	if (node->rrset_count == 0) {
		/*
		 * If there are no RRs in the first tree, all of the RRs
		 * in the second tree will have to be inserted to ADD section.
		 */
		return knot_zone_diff_add_node(node_in_second_tree,
		                               param->changeset);
	}

	for (uint i = 0; i < node->rrset_count; i++) {
		/* Search for the RRSet in the node from the second tree. */
		knot_rrset_t rrset = node_rrset_at(node, i);

		/* SOAs are handled explicitely. */
		if (rrset.type == KNOT_RRTYPE_SOA) {
			continue;
		}

		knot_rrset_t rrset_from_second_node =
			node_rrset(node_in_second_tree, rrset.type);
		if (knot_rrset_empty(&rrset_from_second_node)) {
			/* RRSet has been removed. Make a copy and remove. */
			int ret = changeset_rem_rrset(
				param->changeset, &rrset);
			if (ret != KNOT_EOK) {
				return ret;
			}
		} else {
			/* Diff RRSets. */
			int ret = knot_zone_diff_rrsets(&rrset,
			                                &rrset_from_second_node,
			                                param->changeset);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	for (uint i = 0; i < node_in_second_tree->rrset_count; i++) {
		/* Search for the RRSet in the node from the second tree. */
		knot_rrset_t rrset = node_rrset_at(node_in_second_tree, i);

		/* SOAs are handled explicitely. */
		if (rrset.type == KNOT_RRTYPE_SOA) {
			continue;
		}

		knot_rrset_t rrset_from_first_node = node_rrset(node, rrset.type);
		if (knot_rrset_empty(&rrset_from_first_node)) {
			/* RRSet has been added. Make a copy and add. */
			int ret = changeset_add_rrset(
				param->changeset, &rrset);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

/*!< \todo possibly not needed! */
static int knot_zone_diff_add_new_nodes(zone_node_t **node_ptr, void *data)
{
	if (node_ptr == NULL || *node_ptr == NULL || data == NULL) {
		dbg_zonediff("zone_diff: add_new_nodes: NULL arguments.\n");
		return KNOT_EINVAL;
	}

	zone_node_t *node = *node_ptr;

	struct zone_diff_param *param = (struct zone_diff_param *)data;
	if (param->changeset == NULL) {
		dbg_zonediff("zone_diff: add_new_nodes: NULL arguments.\n");
		return KNOT_EINVAL;
	}

	/*
	* If a node is not present in the second zone, it is a new node
	* and has to be added to changeset. Differencies on the RRSet level are
	* already handled.
	*/

	const knot_dname_t *node_owner = node->owner;
	/*
	 * Node should definitely have an owner, otherwise it would not be in
	 * the tree.
	 */
	assert(node_owner);

	zone_node_t *new_node = NULL;
    //printf("zone_diff_add_new_nodes: prin to get\n");
    zone_tree_get(param->nodes, node_owner, &new_node);
    //printf("zone_diff_add_new_nodes: meta to get\n");

	int ret = KNOT_EOK;

	if (!new_node) {
        //printf("Den ypirxe o komvos, valton sto changeset. Trexw to knot_zone_diff_add_node\n");
		assert(node);
		ret = knot_zone_diff_add_node(node, param->changeset);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: add_new_nodes: Cannot add "
			             "node: %p to changeset. Reason: %s.\n",
			             node->owner,
			             knot_strerror(ret));
		}
	}

	return ret;
}

static int knot_zone_diff_load_trees(zone_tree_t *nodes1,
                                     zone_tree_t *nodes2,
                                     changeset_t *changeset)
{
	assert(changeset);

	struct zone_diff_param param = { 0 };
	param.changeset = changeset;

	// Traverse one tree, compare every node, each RRSet with its rdata.
	param.nodes = nodes2;
    //printf("PRIN TO prwto zone tree apply, TO WEIGHT TOU NSEC5 NODES: %d\n", zone_tree_weight(nodes2));
    //printf("PRIN TO prwto zone tree apply, TO WEIGHT TOU zone->nsec3nodes NODES: %d\n", zone_tree_weight(nodes1));

	int result = zone_tree_apply(nodes1, knot_zone_diff_node, &param);
	if (result != KNOT_EOK) {
        printf("kati pige strava mesa sto prwto zone tree apply\n");
		return result;
	}
    //printf("META TO prwto zone tree apply, TO WEIGHT TOU NSEC5 NODES: %d\n", zone_tree_weight(nodes2));
    //printf("META TO prwto zone tree apply, TO WEIGHT TOU zone->nsec3nodes NODES: %d\n", zone_tree_weight(nodes1));

    //printf ("zone-diff: Ekana prwto zone tree apply\n");
	// Some nodes may have been added. Add missing nodes to changeset.
	param.nodes = nodes1;
	result = zone_tree_apply(nodes2, knot_zone_diff_add_new_nodes, &param);
    //printf ("zone-diff: Ekana deytero zone tree apply\n");

	return result;
}

static int knot_zone_diff_load_content(const zone_contents_t *zone1,
                                       const zone_contents_t *zone2,
                                       changeset_t *changeset)
{
	int ret = knot_zone_diff_load_trees(zone1->nodes, zone2->nodes, changeset);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return knot_zone_diff_load_trees(zone1->nsec3_nodes, zone2->nsec3_nodes,
	                                 changeset);
}

static int zone_contents_diff(const zone_contents_t *zone1,
                              const zone_contents_t *zone2,
                              changeset_t *changeset)
{
	if (zone1 == NULL || zone2 == NULL) {
		return KNOT_EINVAL;
	}

	int result = knot_zone_diff_load_soas(zone1, zone2, changeset);
	if (result != KNOT_EOK) {
		return result;
	}

	return knot_zone_diff_load_content(zone1, zone2, changeset);
}

int zone_contents_create_diff(const zone_contents_t *z1,
                              const zone_contents_t *z2,
                              changeset_t *changeset)
{
	int ret = zone_contents_diff(z1, z2, changeset);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: create_changesets: "
		             "Could not diff zones. "
		             "Reason: %s.\n", knot_strerror(ret));
		return ret;
	}

	dbg_zonediff("Changesets created successfully!\n");
	return KNOT_EOK;
}

int zone_tree_add_diff(zone_tree_t *t1, zone_tree_t *t2, changeset_t *changeset)
{
	if (!changeset) {
        printf("zone_tree_add_diff: no changesest\n");
		return KNOT_EINVAL;
	}

	return knot_zone_diff_load_trees(t1, t2, changeset);
}
