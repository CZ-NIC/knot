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

#include "knot/updates/zone-update.h"
#include "common/lists.h"
#include "common/mempool.h"

static int add_to_node(zone_node_t *node, const zone_node_t *add_node,
                       mm_ctx_t *mm)
{
	for (uint16_t i = 0; i < add_node->rrset_count; ++i) {
		knot_rrset_t rr = node_rrset_at(add_node, i);
		if (!knot_rrset_empty(&rr)) {
			int ret = node_add_rrset(node, &rr, mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int rem_from_node(zone_node_t *node, const zone_node_t *rem_node,
                         mm_ctx_t *mm)
{
	for (uint16_t i = 0; i < rem_node->rrset_count; ++i) {
		// Remove each found RR from 'node'.
		knot_rrset_t rem_rrset = node_rrset_at(rem_node, i);
		knot_rdataset_t *to_change = node_rdataset(node, rem_rrset.type);
		if (to_change) {
			// Remove data from synthesized node
			int ret = knot_rdataset_subtract(to_change,
			                                 &rem_rrset.rrs,
			                                 mm);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static int apply_changes_to_node(zone_node_t *synth_node, const zone_node_t *add_node,
                                 const zone_node_t *rem_node, mm_ctx_t *mm)
{
	// Add changes to node
	if (!node_empty(add_node)) {
		int ret = add_to_node(synth_node, add_node, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Remove changes from node
	if (!node_empty(rem_node)) {
		int ret = rem_from_node(synth_node, rem_node, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int deep_copy_node_data(zone_node_t *node_copy, const zone_node_t *node,
                               mm_ctx_t *mm)
{
	// Clear space for RRs
	node_copy->rrs = NULL;
	node_copy->rrset_count = 0;
	
	for (uint16_t i = 0; i < node->rrset_count; ++i) {
		knot_rrset_t rr = node_rrset_at(node, i);
		int ret = node_add_rrset(node_copy, &rr, mm);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static zone_node_t *node_deep_copy(const zone_node_t *node, mm_ctx_t *mm)
{
	// Shallow copy old node
	zone_node_t *synth_node = node_shallow_copy(node, mm);
	if (synth_node == NULL) {
		return NULL;
	}

	// Deep copy data inside node copy.
	int ret = deep_copy_node_data(synth_node, node, mm);
	if (ret != KNOT_EOK) {
		node_free(&synth_node, mm);
		return NULL;
	}

	return synth_node;
}

/* ------------------------------- API -------------------------------------- */

void zone_update_init(zone_update_t *update, const zone_contents_t *zone, changeset_t *change)
{
	update->zone = zone;
	update->change = change;
	mm_ctx_mempool(&update->mm, 4096);
}

const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname)
{
	if (update == NULL || dname == NULL) {
		return NULL;
	}

	const zone_node_t *old_node =
		zone_contents_find_node(update->zone, dname);
	const zone_node_t *add_node =
		zone_contents_find_node(update->change->add, dname);
	const zone_node_t *rem_node =
		zone_contents_find_node(update->change->remove, dname);

	const bool have_change = !node_empty(add_node) || !node_empty(rem_node);
	if (!have_change) {
		// Nothing to apply
		return old_node;
	}

	if (!old_node) {
		if (add_node && node_empty(rem_node)) {
			// Just addition
			return add_node;
		} else {
			// Addition and deletion
			old_node = add_node;
			add_node = NULL;
		}
	}

	// We have to apply changes to node.
	zone_node_t *synth_node = node_deep_copy(old_node, &update->mm);
	if (synth_node == NULL) {
		return NULL;
	}

	// Apply changes to node.
	int ret = apply_changes_to_node(synth_node, add_node, rem_node,
	                                &update->mm);
	if (ret != KNOT_EOK) {
		node_free_rrsets(synth_node, &update->mm);
		node_free(&synth_node, &update->mm);
		return NULL;
	}

	return synth_node;
}

void zone_update_clear(zone_update_t *update)
{
	if (update) {
		mp_delete(update->mm.ctx);
		memset(update, 0, sizeof(*update));
	}
}
