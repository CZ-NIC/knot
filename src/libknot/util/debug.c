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
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

#include "libknot/util/utils.h"
#include "libknot/util/debug.h"
#include "libknot/rrset.h"
#include "common/descriptor.h"
#include "common/print.h"

#if defined(KNOT_ZONE_DEBUG)
static int knot_node_dump_from_tree(knot_node_t *node, void *data)
{
	UNUSED(data);
	knot_node_dump(node);

	return KNOT_EOK;
}
#endif

void knot_node_dump(knot_node_t *node)
{
#if defined(KNOT_ZONE_DEBUG) || defined(KNOT_NODE_DEBUG)
	//char loaded_zone = *((char*) data);
	char *name;

	dbg_node_detail("------- NODE --------\n");
	name = knot_dname_to_str(node->owner);
	dbg_node_detail("owner: %s\n", name);
	free(name);
	dbg_node_detail("node: %p\n", node);

	if (knot_node_is_deleg_point(node)) {
		dbg_node_detail("delegation point\n");
	}

	if (knot_node_is_non_auth(node)) {
		dbg_node_detail("non-authoritative node\n");
	}

	if (node->parent != NULL) {
		/*! \todo This causes segfault when parent was free'd,
		 *        e.g. when applying changesets.
		 */
		name = knot_dname_to_str(node->parent->owner);
		dbg_node_detail("parent: %s\n", name);
		free(name);
	} else {
		dbg_node_detail("no parent\n");
	}

	if (node->prev != NULL) {
		dbg_node_detail("previous node: %p\n", node->prev);
		/*! \todo This causes segfault when prev was free'd,
		 *        e.g. when applying changesets.
		 */
		name = knot_dname_to_str(node->prev->owner);
		dbg_node_detail("previous node: %s\n", name);
		free(name);
	} else {
		dbg_node_detail("previous node: none\n");
	}

	knot_rrset_t **rrsets = knot_node_get_rrsets(node);

	dbg_node_detail("Wildcard child: ");

	if (node->wildcard_child != NULL) {
		/*! \todo This causes segfault when wildcard child was free'd,
		 *        e.g. when applying changesets.
		 */
		name = knot_dname_to_str(node->wildcard_child->owner);
		dbg_node_detail("%s\n", name);
		free(name);
	} else {
		dbg_node_detail("none\n");
	}

	dbg_node_detail("NSEC3 node: ");

	if (node->nsec3_node != NULL) {
		/*! \todo This causes segfault when n	sec3_node was free'd,
		 *        e.g. when applying changesets.
		 */
		name = knot_dname_to_str(node->nsec3_node->owner);
		dbg_node_detail("%s\n", name);
		free(name);
	} else {
		dbg_node_detail("none\n");
	}

	dbg_node_detail("Zone: %p\n", node->zone);

	dbg_node_detail("RRSet count: %d\n", node->rrset_count);

	for (int i = 0; i < node->rrset_count; i++) {
		knot_rrset_dump(rrsets[i]);
	}
	free(rrsets);
	//assert(node->owner->node == node);
	dbg_node_detail("------- NODE --------\n");
#else
	UNUSED(node);
#endif
}

void knot_zone_contents_dump(knot_zone_contents_t *zone)
{
#if defined(KNOT_ZONE_DEBUG)
	if (!zone) {
		dbg_zone_detail("------- STUB ZONE --------\n");
		return;
	}

	dbg_zone_detail("------- ZONE --------\n");

	knot_zone_contents_tree_apply_inorder(zone, knot_node_dump_from_tree,
					      NULL);

	dbg_zone_detail("------- ZONE --------\n");

	dbg_zone_detail("------- NSEC 3 tree -\n");

	knot_zone_contents_nsec3_apply_inorder(zone, knot_node_dump_from_tree,
					       NULL);

	dbg_zone_detail("------- NSEC 3 tree -\n");
#else
	UNUSED(zone);
#endif
}
