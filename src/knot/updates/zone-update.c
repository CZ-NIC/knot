/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/common/log.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/serial.h"
#include "contrib/mempattern.h"
#include "contrib/ucw/lists.h"
#include "contrib/ucw/mempool.h"

#include <urcu.h>

static int init_incremental(zone_update_t *update, zone_t *zone)
{
	if (zone->contents == NULL) {
		return KNOT_EINVAL;
	}

	int ret = changeset_init(&update->change, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = apply_prepare_zone_copy(zone->contents, &update->new_cont);
	if (ret != KNOT_EOK) {
		changeset_clear(&update->change);
		return ret;
	}

	apply_init_ctx(&update->a_ctx, update->new_cont, 0);

	/* Copy base SOA RR. */
	update->change.soa_from =
		node_create_rrset(update->zone->contents->apex, KNOT_RRTYPE_SOA);
	if (update->change.soa_from == NULL) {
		changeset_clear(&update->change);
		zone_contents_free(&update->new_cont);
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

	apply_init_ctx(&update->a_ctx, update->new_cont, 0);

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

	return zone_contents_find_node(update->new_cont, dname);
}

const zone_node_t *zone_update_get_apex(zone_update_t *update)
{
	if (update == NULL) {
		return NULL;
	}

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
	if (update == NULL) {
		return NULL;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		const zone_node_t *apex = update->zone->contents->apex;
		return node_rdataset(apex, KNOT_RRTYPE_SOA);
	}

	return NULL;
}

const knot_rdataset_t *zone_update_to(zone_update_t *update)
{
	if (update == NULL) {
		return NULL;
	}

	if (update->flags & UPDATE_FULL) {
		const zone_node_t *apex = update->new_cont->apex;
		return node_rdataset(apex, KNOT_RRTYPE_SOA);
	} else if (update->flags & UPDATE_INCREMENTAL) {
		if (update->change.soa_to == NULL) {
			return NULL;
		}
		return &update->change.soa_to->rrs;
	}

	return NULL;
}

void zone_update_clear(zone_update_t *update)
{
	if (update == NULL) {
		return;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		/* Revert any changes on error, do nothing on success. */
		update_rollback(&update->a_ctx);
		update_free_zone(&update->new_cont);
		changeset_clear(&update->change);
	} else if (update->flags & UPDATE_FULL) {
		zone_contents_deep_free(&update->new_cont);
	}
	mp_delete(update->mm.ctx);
	memset(update, 0, sizeof(*update));
}

int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update == NULL) {
		return KNOT_EINVAL;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		int ret = changeset_add_addition(&update->change, rrset, CHANGESET_CHECK);
		if (ret != KNOT_EOK) {
			return ret;
		}

		if (rrset->type == KNOT_RRTYPE_SOA) {
			/* replace previous SOA */
			ret = apply_replace_soa(&update->a_ctx, &update->change);
			if (ret != KNOT_EOK) {
				changeset_remove_addition(&update->change, rrset);
			}
			return ret;
		}

		ret = apply_add_rr(&update->a_ctx, rrset);
		if (ret != KNOT_EOK) {
			changeset_remove_addition(&update->change, rrset);
			return ret;
		}

		return KNOT_EOK;
	} else if (update->flags & UPDATE_FULL) {
		zone_node_t *n = NULL;
		return zone_contents_add_rr(update->new_cont, rrset, &n);
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update == NULL) {
		return KNOT_EINVAL;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		int ret = changeset_add_removal(&update->change, rrset, CHANGESET_CHECK);
		if (ret != KNOT_EOK) {
			return ret;
		}

		if (rrset->type == KNOT_RRTYPE_SOA) {
			/* SOA is replaced with addition */
			return KNOT_EOK;
		}

		ret = apply_remove_rr(&update->a_ctx, rrset);
		if (ret != KNOT_EOK) {
			changeset_remove_removal(&update->change, rrset);
			return ret;
		}

		return KNOT_EOK;
	} else if (update->flags & UPDATE_FULL) {
		zone_node_t *n = NULL;
		knot_rrset_t *rrs_copy = knot_rrset_copy(rrset, &update->mm);
		int ret = zone_contents_remove_rr(update->new_cont, rrs_copy, &n);
		knot_rrset_free(&rrs_copy, &update->mm);
		return ret;
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove_rrset(zone_update_t *update, knot_dname_t *owner, uint16_t type)
{
	if (update == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		/* Remove the RRSet from the original node */
		const zone_node_t *node = zone_contents_find_node(update->new_cont, owner);
		if (node != NULL) {
			knot_rrset_t rrset = node_rrset(node, type);
			if (rrset.owner == NULL) {
				return KNOT_ENOENT;
			}
			int ret = changeset_add_removal(&update->change, &rrset,
			                                CHANGESET_CHECK);
			if (ret != KNOT_EOK) {
				return ret;
			}

			if (type == KNOT_RRTYPE_SOA) {
				/* SOA is replaced with addition */
				return KNOT_EOK;
			}

			ret = apply_remove_rr(&update->a_ctx, &rrset);
			if (ret != KNOT_EOK) {
				return ret;
			}
		} else {
			return KNOT_ENONODE;
		}
	} else if (update->flags & UPDATE_FULL) {
		/* Remove the RRSet from the non-synthesized new node */
		const zone_node_t *node = zone_contents_find_node(update->new_cont, owner);
		if (node == NULL) {
			return KNOT_ENONODE;
		}

		knot_rrset_t rrset = node_rrset(node, type);
		int ret = zone_update_remove(update, &rrset);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

int zone_update_remove_node(zone_update_t *update, const knot_dname_t *owner)
{
	if (update == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		/* Remove all RRSets from the new node */
		const zone_node_t *node = zone_contents_find_node(update->new_cont, owner);
		if (node != NULL) {
			size_t rrset_count = node->rrset_count;
			for (int i = 0; i < rrset_count; ++i) {
				knot_rrset_t rrset = node_rrset_at(node, rrset_count - 1 - i);
				int ret = changeset_add_removal(&update->change, &rrset,
				                                CHANGESET_CHECK);
				if (ret != KNOT_EOK) {
					return ret;
				}

				if (rrset.type == KNOT_RRTYPE_SOA) {
					/* SOA is replaced with addition */
					return KNOT_EOK;
				}

				ret = apply_remove_rr(&update->a_ctx, &rrset);
				if (ret != KNOT_EOK) {
					return ret;
				}
			}
		} else {
			return KNOT_ENONODE;
		}
	} else if (update->flags & UPDATE_FULL) {
		/* Remove all RRSets from the non-synthesized new node */
		const zone_node_t *node = zone_contents_find_node(update->new_cont, owner);
		if (node == NULL) {
			return KNOT_ENONODE;
		}

		size_t rrset_count = node->rrset_count;
		for (int i = 0; i < rrset_count; ++i) {
			knot_rrset_t rrset = node_rrset_at(node, rrset_count - 1 - i);
			int ret = zone_update_remove(update, &rrset);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

static bool apex_rr_changed(const zone_node_t *old_apex,
                            const zone_node_t *new_apex,
                            uint16_t type)
{
	assert(old_apex);
	assert(new_apex);
	knot_rrset_t old_rr = node_rrset(old_apex, type);
	knot_rrset_t new_rr = node_rrset(new_apex, type);

	return !knot_rrset_equal(&old_rr, &new_rr, KNOT_RRSET_COMPARE_WHOLE);
}

static bool apex_dnssec_changed(zone_update_t *update)
{
	const zone_node_t *new_apex = zone_update_get_apex(update);
	if (update->zone->contents != NULL) {
		const zone_node_t *old_apex = update->zone->contents->apex;
		return !changeset_empty(&update->change) &&
		       (apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_DNSKEY) ||
		        apex_rr_changed(new_apex, old_apex, KNOT_RRTYPE_NSEC3PARAM));
	} else if (new_apex != NULL) {
		return true;
	}

	return false;
}

static int sign_update(zone_update_t *update,
                       zone_contents_t *new_contents)
{
	assert(update);
	assert(new_contents);

	/* Check if the UPDATE changed DNSKEYs or NSEC3PARAM.
	 * If so, we have to sign the whole zone. */
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
		/* Sign the created changeset */
		ret = knot_dnssec_sign_changeset(new_contents, &update->change,
		                                 &sec_ch, &refresh_at);
	}
	if (ret != KNOT_EOK) {
		changeset_clear(&sec_ch);
		return ret;
	}

	/* Apply DNSSEC changeset */
	ret = apply_changeset_directly(&update->a_ctx, &sec_ch);
	if (ret != KNOT_EOK) {
		changeset_clear(&sec_ch);
		return ret;
	}

	if (!full_sign) {
		/* Merge changesets */
		ret = changeset_merge(&update->change, &sec_ch);
		if (ret != KNOT_EOK) {
			update_rollback(&update->a_ctx);
			changeset_clear(&sec_ch);
			return ret;
		}
	}

	/* Plan next zone resign. */
	const time_t resign_time = zone_events_get_time(update->zone, ZONE_EVENT_DNSSEC);
	if (refresh_at < resign_time) {
		zone_events_schedule_at(update->zone, ZONE_EVENT_DNSSEC, refresh_at);
	}

	/* We are not calling update_cleanup, as the rollback data are merged
	 * into the main changeset and will get cleaned up with that. */
	changeset_clear(&sec_ch);

	return KNOT_EOK;
}

static int set_new_soa(zone_update_t *update, unsigned serial_policy)
{
	assert(update);

	knot_rrset_t *soa_cpy = node_create_rrset(zone_update_get_apex(update),
	                                          KNOT_RRTYPE_SOA);
	if (soa_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	uint32_t old_serial = knot_soa_serial(&soa_cpy->rrs);
	uint32_t new_serial = serial_next(old_serial, serial_policy);
	if (serial_compare(old_serial, new_serial) >= 0) {
		log_zone_warning(update->zone->name, "updated serial is lower "
		                 "than current, serial %u -> %u",
		                  old_serial, new_serial);
	}

	knot_soa_serial_set(&soa_cpy->rrs, new_serial);
	update->change.soa_to = soa_cpy;

	return KNOT_EOK;
}

static int commit_incremental(conf_t *conf, zone_update_t *update,
                              zone_contents_t **contents_out)
{
	assert(update);
	assert(contents_out);

	if (changeset_empty(&update->change)) {
		changeset_clear(&update->change);
		return KNOT_EOK;
	}

	zone_contents_t *new_contents = update->new_cont;
	int ret = KNOT_EOK;
	if (zone_update_to(update) == NULL) {
		/* No SOA in the update, create one according to the current policy */
		conf_val_t val = conf_zone_get(conf, C_SERIAL_POLICY, update->zone->name);
		ret = set_new_soa(update, conf_opt(&val));
		if (ret != KNOT_EOK) {
			update_rollback(&update->a_ctx);
			update_free_zone(&new_contents);
			changeset_clear(&update->change);
			return ret;
		}

		ret = apply_replace_soa(&update->a_ctx, &update->change);
		if (ret != KNOT_EOK) {
			update_rollback(&update->a_ctx);
			update_free_zone(&new_contents);
			changeset_clear(&update->change);
			return ret;
		}
	}

	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, update->zone->name);
	bool dnssec_enable = (update->flags & UPDATE_SIGN) && conf_bool(&val);

	/* Sign the update. */
	if (dnssec_enable) {
		ret = apply_prepare_to_sign(&update->a_ctx);
		if (ret != KNOT_EOK) {
			update_rollback(&update->a_ctx);
			update_free_zone(&new_contents);
			changeset_clear(&update->change);
			return ret;
		}

		ret = sign_update(update, new_contents);
		if (ret != KNOT_EOK) {
			update_rollback(&update->a_ctx);
			update_free_zone(&new_contents);
			changeset_clear(&update->change);
			return ret;
		}
	} else {
		ret = apply_finalize(&update->a_ctx);
		if (ret != KNOT_EOK) {
			update_rollback(&update->a_ctx);
			update_free_zone(&new_contents);
			changeset_clear(&update->change);
			return ret;
		}
	}

	/* Write changes to journal if all went well. (DNSSEC merged) */
	ret = zone_change_store(conf, update->zone, &update->change);
	if (ret != KNOT_EOK) {
		update_rollback(&update->a_ctx);
		update_free_zone(&new_contents);
		return ret;
	}

	*contents_out = new_contents;

	return KNOT_EOK;
}

static int commit_full(conf_t *conf, zone_update_t *update, zone_contents_t **contents_out)
{
	assert(update);
	assert(contents_out);

	/* Check if we have SOA. We might consider adding full semantic check here.
	 * But if we wanted full sem-check I'd consider being it controlled by a flag
	 * - to enable/disable it on demand. */
	if (!node_rrtype_exists(update->new_cont->apex, KNOT_RRTYPE_SOA)) {
		return KNOT_ESEMCHECK;
	}

	zone_contents_adjust_full(update->new_cont);

	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, update->zone->name);
	bool dnssec_enable = (update->flags & UPDATE_SIGN) && conf_bool(&val);

	/* Sign the update. */
	if (dnssec_enable) {
		int ret = sign_update(update, update->new_cont);
		if (ret != KNOT_EOK) {
			update_rollback(&update->a_ctx);
			return ret;
		}
	}

	update_cleanup(&update->a_ctx);
	*contents_out = update->new_cont;
	return KNOT_EOK;
}

int zone_update_commit(conf_t *conf, zone_update_t *update)
{
	if (conf == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;
	zone_contents_t *new_contents = NULL;
	if (update->flags & UPDATE_INCREMENTAL) {
		ret = commit_incremental(conf, update, &new_contents);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		ret = commit_full(conf, update, &new_contents);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	conf_val_t val = conf_zone_get(conf, C_MAX_ZONE_SIZE, update->zone->name);
	int64_t size_limit = conf_int(&val);

	if (new_contents != NULL && new_contents->size > size_limit) {
		return KNOT_EZONESIZE;
	}

	/* If there is anything to change */
	if (new_contents != NULL) {
		/* Switch zone contents. */
		zone_contents_t *old_contents = zone_switch_contents(update->zone,
		                                                     new_contents);

		/* Sync RCU. */
		synchronize_rcu();
		if (update->flags & UPDATE_FULL) {
			zone_contents_deep_free(&old_contents);
			update->new_cont = NULL;
		} else if (update->flags & UPDATE_INCREMENTAL) {
			update_cleanup(&update->a_ctx);
			update_free_zone(&old_contents);
			update->new_cont = NULL;
			changeset_clear(&update->change);
		}
	}

	return KNOT_EOK;
}

static int iter_init_tree_iters(zone_update_iter_t *it, zone_update_t *update,
                                bool nsec3)
{
	zone_tree_t *tree;

	/* Set zone iterator. */
	zone_contents_t *_contents = update->new_cont;

	/* Begin iteration. We can safely assume _contents is a valid pointer. */
	tree = nsec3 ? _contents->nsec3_nodes : _contents->nodes;
	hattrie_build_index(tree);
	it->tree_it = hattrie_iter_begin(nsec3 ? _contents->nsec3_nodes : _contents->nodes, true);
	if (it->tree_it == NULL) {
		return KNOT_ENOMEM;
	}

	it->cur_node = (zone_node_t *)(*hattrie_iter_val(it->tree_it));

	return KNOT_EOK;
}

static int iter_get_next_node(zone_update_iter_t *it)
{
	hattrie_iter_next(it->tree_it);
	if (hattrie_iter_finished(it->tree_it)) {
		hattrie_iter_free(it->tree_it);
		it->tree_it = NULL;
		it->cur_node = NULL;
		return KNOT_ENOENT;
	}

	it->cur_node = (zone_node_t *)(*hattrie_iter_val(it->tree_it));

	return KNOT_EOK;
}

static int iter_init(zone_update_iter_t *it, zone_update_t *update, const bool nsec3)
{
	memset(it, 0, sizeof(*it));

	it->update = update;
	it->nsec3 = nsec3;
	int ret = iter_init_tree_iters(it, update, nsec3);
	if (ret != KNOT_EOK) {
		return ret;
	}

	it->cur_node = (zone_node_t *)(*hattrie_iter_val(it->tree_it));

	return KNOT_EOK;
}

int zone_update_iter(zone_update_iter_t *it, zone_update_t *update)
{
	if (it == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	return iter_init(it, update, false);
}

int zone_update_iter_nsec3(zone_update_iter_t *it, zone_update_t *update)
{
	if (it == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	if (update->flags & UPDATE_FULL) {
		if (update->new_cont->nsec3_nodes == NULL) {
			/* No NSEC3 tree. */
			return KNOT_ENOENT;
		}
	} else {
		if (update->change.add->nsec3_nodes == NULL &&
		    update->change.remove->nsec3_nodes == NULL) {
			/* No NSEC3 changes. */
			return KNOT_ENOENT;
		}
	}

	return iter_init(it, update, true);
}

int zone_update_iter_next(zone_update_iter_t *it)
{
	if (it == NULL) {
		return KNOT_EINVAL;
	}

	if (it->tree_it != NULL) {
		int ret = iter_get_next_node(it);
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			return ret;
		}
	}

	return KNOT_EOK;
}

const zone_node_t *zone_update_iter_val(zone_update_iter_t *it)
{
	if (it != NULL) {
		return it->cur_node;
	} else {
		return NULL;
	}
}

void zone_update_iter_finish(zone_update_iter_t *it)
{
	if (it == NULL) {
		return;
	}

	hattrie_iter_free(it->tree_it);
}

bool zone_update_no_change(zone_update_t *update)
{
	if (update == NULL) {
		return true;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		return changeset_empty(&update->change);
	} else {
		/* This branch does not make much sense and FULL update will most likely
		 * be a change every time anyway, just return false. */
		return false;
	}
}
