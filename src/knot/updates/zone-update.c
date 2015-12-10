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

#include "knot/common/log.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/apply.h"
#include "knot/zone/serial.h"

#include "libknot/internal/lists.h"
#include "contrib/ucw/mempool.h"

static int add_to_node(zone_node_t *node, const zone_node_t *add_node,
                       knot_mm_t *mm)
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
                         knot_mm_t *mm)
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
                                 const zone_node_t *rem_node, knot_mm_t *mm)
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
                               knot_mm_t *mm)
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

static zone_node_t *node_deep_copy(const zone_node_t *node, knot_mm_t *mm)
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

static int init_incremental(zone_update_t *update, zone_t *zone)
{
	int ret = changeset_init(&update->change, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(zone->contents);

	// Copy base SOA RR.
	update->change.soa_from =
		node_create_rrset(update->zone->contents->apex, KNOT_RRTYPE_SOA);
	if (update->change.soa_from == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int init_full(zone_update_t *update, zone_t *zone)
{
	update->new_cont = zone_contents_new(zone->name);
	if (update->new_cont == NULL) {
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

/* ------------------------------- API -------------------------------------- */

int zone_update_init(zone_update_t *update, zone_t *zone, zone_update_flags_t flags)
{
	if (update == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	memset(update, 0, sizeof(*update));
	update->zone = zone;

	mm_ctx_mempool(&update->mm, MM_DEFAULT_BLKSIZE);
	update->flags = flags;

	if (flags & UPDATE_INCREMENTAL) {
		return init_incremental(update, zone);
	} else if (flags & UPDATE_FULL) {
		return init_full(update, zone);
	} else {
		return KNOT_EINVAL;
	}
}

const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname)
{
	if (update == NULL || dname == NULL) {
		return NULL;
	}

	const zone_node_t *old_node =
		zone_contents_find_node(update->zone->contents, dname);
	const zone_node_t *add_node =
		zone_contents_find_node(update->change.add, dname);
	const zone_node_t *rem_node =
		zone_contents_find_node(update->change.remove, dname);

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

const zone_node_t *zone_update_get_apex(zone_update_t *update)
{
	return zone_update_get_node(update, update->zone->name);
}

uint32_t zone_update_current_serial(zone_update_t *update)
{
	const zone_node_t *apex = zone_update_get_apex(update);
	if (apex) {
		return knot_soa_serial(node_rdataset(apex, KNOT_RRTYPE_SOA));
	} else {
		return 0;
	}
}

const knot_rdataset_t *zone_update_from(zone_update_t *update)
{
	const zone_node_t *apex = update->zone->contents->apex;
	return node_rdataset(apex, KNOT_RRTYPE_SOA);
}

const knot_rdataset_t *zone_update_to(zone_update_t *update)
{
	assert(update);

	if (update->change.soa_to == NULL) {
		return NULL;
	}

	return &update->change.soa_to->rrs;
}

void zone_update_clear(zone_update_t *update)
{
	if (update) {
		update_cleanup(&update->change);
		changeset_clear(&update->change);
		mp_delete(update->mm.ctx);
		memset(update, 0, sizeof(*update));
	}
}

int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_add_rrset(&update->change, rrset);
	} else if (update->flags & UPDATE_FULL) {
		zone_node_t *n = NULL;
		return zone_contents_add_rr(update->new_cont, rrset, &n);
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_rem_rrset(&update->change, rrset);
	} else {
		return KNOT_ENOTSUP;
	}
}

static bool apex_rr_changed(const zone_node_t *old_apex,
                            const zone_node_t *new_apex,
                            uint16_t type)
{
	knot_rrset_t old_rr = node_rrset(old_apex, type);
	knot_rrset_t new_rr = node_rrset(new_apex, type);

	return !knot_rrset_equal(&old_rr, &new_rr, KNOT_RRSET_COMPARE_WHOLE);
}

static bool apex_dnssec_changed(zone_update_t *update)
{
	assert(update->zone->contents);
	const zone_node_t *new_apex = zone_update_get_apex(update);
	const zone_node_t *old_apex = update->zone->contents->apex;
	return !changeset_empty(&update->change) &&
	       (apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_DNSKEY) ||
	        apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_NSEC3PARAM));
}

static int sign_update(zone_update_t *update,
                       zone_contents_t *new_contents)
{
	assert(update != NULL);

	/*
	 * Check if the UPDATE changed DNSKEYs or NSEC3PARAM.
	 * If so, we have to sign the whole zone.
	 */
	int ret = KNOT_EOK;
	uint32_t refresh_at = 0;
	changeset_t sec_ch;
	ret = changeset_init(&sec_ch, update->zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	const bool full_sign = changeset_empty(&update->change) ||
	                       apex_dnssec_changed(update);
	if (full_sign) {
		ret = knot_dnssec_zone_sign(new_contents, &sec_ch,
		                            ZONE_SIGN_KEEP_SOA_SERIAL,
		                            &refresh_at);
	} else {
		// Sign the created changeset
		ret = knot_dnssec_sign_changeset(new_contents, &update->change,
		                                 &sec_ch, &refresh_at);
	}
	if (ret != KNOT_EOK) {
		changeset_clear(&sec_ch);
		return ret;
	}

	// Apply DNSSEC changeset
	ret = apply_changeset_directly(new_contents, &sec_ch);
	if (ret != KNOT_EOK) {
		changeset_clear(&sec_ch);
		return ret;
	}

	// Merge changesets
	ret = changeset_merge(&update->change, &sec_ch);
	if (ret != KNOT_EOK) {
		update_rollback(&sec_ch);
		changeset_clear(&sec_ch);
		return ret;
	}

	// Plan next zone resign.
	const time_t resign_time = zone_events_get_time(update->zone, ZONE_EVENT_DNSSEC);
	if (refresh_at < resign_time) {
		zone_events_schedule_at(update->zone, ZONE_EVENT_DNSSEC, refresh_at);
	}

	/*
	 * We are not calling update_cleanup, as the rollback data are merged
	 * into the main changeset and will get cleaned up with that.
	 */
	changeset_clear(&sec_ch);

	return KNOT_EOK;
}

static int set_new_soa(zone_update_t *update)
{
	assert(update);

	knot_rrset_t *soa_cpy = node_create_rrset(zone_update_get_apex(update), KNOT_RRTYPE_SOA);
	if (soa_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	conf_val_t val = conf_zone_get(conf(), C_SERIAL_POLICY, update->zone->name);
	uint32_t old_serial = knot_soa_serial(&soa_cpy->rrs);
	uint32_t new_serial = serial_next(old_serial, conf_opt(&val));
	if (serial_compare(old_serial, new_serial) >= 0) {
		log_zone_warning(update->zone->name, "updated serial is lower "
		                 "than current, serial %u -> %u",
		                  old_serial, new_serial);
	}

	knot_soa_serial_set(&soa_cpy->rrs, new_serial);
	update->change.soa_to = soa_cpy;

	return KNOT_EOK;
}

static int commit_incremental(zone_update_t *update, zone_contents_t **contents_out)
{
	assert(update);

	if (changeset_empty(&update->change)) {
		changeset_clear(&update->change);
		return KNOT_EOK;
	}

	int ret = KNOT_EOK;
	if (zone_update_to(update) == NULL) {
		// No SOA in the update, create one according to the current policy
		ret = set_new_soa(update);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	// Apply changes.
	zone_contents_t *new_contents = NULL;
	ret = apply_changeset(update->zone, &update->change, &new_contents);
	if (ret != KNOT_EOK) {
		changeset_clear(&update->change);
		return ret;
	}

	assert(new_contents);

	conf_val_t val = conf_zone_get(conf(), C_DNSSEC_SIGNING, update->zone->name);
	bool dnssec_enable = update->flags & UPDATE_SIGN && conf_bool(&val);

	// Sign the update.
	if (dnssec_enable) {
		ret = sign_update(update, new_contents);
		if (ret != KNOT_EOK) {
			update_rollback(&update->change);
			update_free_zone(&new_contents);
			changeset_clear(&update->change);
			return ret;
		}
	}

	// Write changes to journal if all went well. (DNSSEC merged)
	ret = zone_change_store(update->zone, &update->change);
	if (ret != KNOT_EOK) {
		update_rollback(&update->change);
		update_free_zone(&new_contents);
		return ret;
	}

	*contents_out = new_contents;

	return KNOT_EOK;
}

int zone_update_commit(zone_update_t *update, zone_contents_t **contents_out)
{
	if (update->flags & UPDATE_INCREMENTAL) {
		return commit_incremental(update, contents_out);
	}

	return KNOT_ENOTSUP;
}

bool zone_update_no_change(zone_update_t *up)
{
	return changeset_empty(&up->change);
}
