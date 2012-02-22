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

#include "libknot/util/error.h"
#include "libknot/util/debug.h"
#include "libknot/rdata.h"
#include "zone-diff.h"

struct zone_diff_param {
	knot_zone_contents_t *contents;
	char nsec3;
	knot_changeset_t *changeset;
	int ret;
};

static int knot_zone_diff_load_soas(const knot_zone_contents_t *zone1,
                                    const knot_zone_contents_t *zone2,
                                    knot_changeset_t *changeset)
{
	if (zone1 == NULL || zone2 == NULL || changeset == NULL) {
		return KNOT_EBADARG;
	}

	const knot_node_t *apex1 = knot_zone_contents_apex(zone1);
	const knot_node_t *apex2 = knot_zone_contents_apex(zone2);
	if (apex1 == NULL || apex2 == NULL) {
		dbg_zonediff("zone_diff: "
		             "both zones must have apex nodes.\n");
		return KNOT_EBADARG;
	}

	const knot_rrset_t soa_rrset1 = knot_node_rrset(apex1, KNOT_RRTYPE_SOA);
	const knot_rrset_t soa_rrset2 = knot_node_rrset(apex2, KNOT_RRTYPE_SOA);
	if (soa_rrset1 == NULL || soa_rrset2 == NULL) {
		dbg_zonediff("zone_diff: "
		             "both zones must have apex nodes.\n");
		return KNOT_EBADARG;
	}

	if (knot_rrset_rdata(soa_rrset1) == NULL ||
	    knot_rrset_rdata(soa_rrset2) == NULL) {
		dbg_zonediff("zone_diff: "
		             "both zones must have apex nodes with SOA "
		             "RRs.\n");
		return KNOT_EBADARG;
	}

	int64_t soa_serial1 =
		knot_rdata_soa_serial(knot_rrset_rdata(soa_rrset1));

	int64_t soa_serial2 =
		knot_rdata_soa_serial(knot_rrset_rdata(soa_rrset2));

	if (soa_serial1 >= soa_serial2) {
		dbg_zonediff("zone_diff: "
		             "second zone must have higher serial than the "
		             "first one.\n");
		return KNOT_EBADARG;
	}

	assert(changeset);

	changeset->soa_from = soa_rrset1;
	changeset->soa_to = soa_rrset2;

	return KNOT_EOK;
}

static int knot_zone_diff_compare_rdata(const knot_rdata_t *rdata1,
                                        const knot_rdata_t *rdata2)

static int knot_zone_diff_rdata...

static int knot_zone_diff_rrset...

static int knot_zone_diff_changeset_remove_rrset(knot_changeset_t *changeset,
                                                 const knot_rrset_t *rrset)
{
	/* Remove all RRs of the RRSet. */
}

static int knot_zone_diff_changeset_remove_node(knot_changeset_t *changeset,
                                                const knot_node_t *node)
{
	/* Remove all the RRSets of the node. */
}

static void knot_zone_diff_node(knot_node_t *node, void *data)
{
	if (node == NULL || data == NULL) {
		dbg_zonediff("zone_diff: diff_node: NULL arguments.\n");
		return;
	}

	struct zone_diff_param *param = (zone_diff_param *)data;
	if (param->changeset == NULL || param->contents == NULL) {
		dbg_zonediff("zone_diff: diff_node: NULL arguments.\n");
		param->ret = KNOT_EBADARG;
		return;
	}

	/*
	 * First, we have to search the second tree to see if there's according
	 * node, if not, the whole node has been removed.
	 */
	const knot_node_t *node_in_second_tree = NULL;
	const knot_dname_t *node_owner = knot_node_owner(node);
	assert(node_owner);
	if (!param->nsec3) {
		node_in_second_tree =
			knot_zone_contents_find_node(param->contents,
			                             node_owner);
	} else {
		node_in_second_tree =
			knot_zone_contents_find_nsec3_node(param->contents,
			                                   node_owner);
	}

	if (node_in_second_tree == NULL) {
		ret = knot_zone_diff_changeset_remove_node(param->changeset,
		                                           node);
		if (ret != KNOT_EOK) {
			dbg_zonediff("zone_diff: failed to remove node.\n");
			param->ret = ret;
			return;
		}
	}

	/* The nodes are in both trees, we have to diff each RRSet. */
	const knot_rrset_t **rrsets = knot_node_rrsets(node);
	if (rrsets == NULL) {
		dbg_zonediff("zone_diff: Node has no RRSets\n");
		param->ret = KNOT_EBADARG;
		return;
	}

	for(uint i = 0; i < knot_node_rrset_count(node), i++) {
		/* Search for the RRSet in the node from the second tree. */
		const knot_rrset_t *rrset = rrsets[i];
		assert(rrset);
		const knot_rrset_t *rrset_from_second_node =
			knot_node_rrset(node_in_second_tree,
			                knot_rrset_type(rrset));
		if (rrset_from_second_node == NULL) {
			/* RRSet has been removed. */
			ret = knot_zone_diff_changeset_remove_rrset(
				param->changeset,
				rrset);
			if (ret != KNOT_EOK) {
				dbg_zonediff("zone_diff: "
				             "Failed to remove RRSet\n");
			}
		}
	}
}

static void knot_zone_diff_add_new_nodes(knot_node_t *node, void *data)
{

}

knot_changeset_t *knot_zone_diff(knot_zone_contents_t *zone1,
                                 knot_zone_contents_t *zone2)
{
	if (zone1 == NULL || zone2 == NULL) {
		dbg_zonediff("zone_diff: NULL argument(s).\n");
		return KNOT_EBADARG;
	}

	/* Create changeset structure. */
	knot_changeset_t *changeset = malloc(sizeof(knot_changeset_t));
	if (changeset == NULL) {
		ERR_ALLOC_FAILED;
		return KNOT_ENOMEM;
	}

	/* Settle SOAs first. */
	int ret = knot_zone_diff_load_soas(zone1, zone2, changeset);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: loas_SOAs failed with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	/* Traverse one tree, compare every node, each RRSet with its rdata. */
	struct zone_diff_param param;
	param.contents = zone2;
	param.nsec3 = 0;
	param.changeset = changeset;
	parar.ret = 0;
	ret = knot_zone_contents_tree_apply_inorder(zone1, knot_zone_diff_node,
	                                            &param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s. Error from inner function: %s\n",
		             knot_strerror(ret),
		             knot_strerror(param.ret));
		return ret;
	}

	/* Do the same for NSEC3 nodes. */
	param.nsec3 = 1;
	ret = knot_zone_contents_nsec3_apply_inorder(zone1, knot_zone_diff_node,
	                                             &param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	/*
	 * Some nodes may have been added. The code above will not notice,
	 * we have to go through the second tree and add missing nodes to
	 * changeset.
	 */
	param.nsec3 = 0;
	ret = knot_zone_contents_tree_apply_inorder(zone2,
		knot_zone_diff_add_new_nodes,
		&param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s. Error from inner function: %s\n",
		             knot_strerror(ret),
		             knot_strerror(param.ret));
		return ret;
	}

	/* NSEC3 nodes. */
	param.nsec3 = 1;
	ret = knot_zone_contents_nsec3_apply_inorder(zone2,
		knot_zone_diff_add_new_nodes,
		&param);
	if (ret != KNOT_EOK) {
		dbg_zonediff("zone_diff: Tree traversal failed "
		             "with error: %s\n",
		             knot_strerror(ret));
		return ret;
	}

	return KNOT_EOK;
}

