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

#include "knot/common/log.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/serial.h"
#include "knot/zone/zone-diff.h"
#include "contrib/mempattern.h"
#include "contrib/trim.h"
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

	update->new_cont_deep_copy = false;

	ret = apply_prepare_zone_copy(zone->contents, &update->new_cont);
	if (ret != KNOT_EOK) {
		changeset_clear(&update->change);
		return ret;
	}

	uint32_t apply_flags = update->flags & UPDATE_STRICT ? APPLY_STRICT : 0;
	apply_init_ctx(update->a_ctx, update->new_cont, apply_flags);

	/* Copy base SOA RR. */
	update->change.soa_from =
		node_create_rrset(zone->contents->apex, KNOT_RRTYPE_SOA);
	if (update->change.soa_from == NULL) {
		zone_contents_free(&update->new_cont);
		changeset_clear(&update->change);
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

	update->new_cont_deep_copy = true;

	apply_init_ctx(update->a_ctx, update->new_cont, 0);

	return KNOT_EOK;
}

static int replace_soa(zone_contents_t *contents, const knot_rrset_t *rr)
{
	/* SOA possible only within apex. */
	if (!knot_dname_is_equal(rr->owner, contents->apex->owner)) {
		return KNOT_EDENIED;
	}

	knot_rrset_t old_soa = node_rrset(contents->apex, KNOT_RRTYPE_SOA);
	zone_node_t *n = contents->apex;
	int ret = zone_contents_remove_rr(contents, &old_soa, &n);
	if (ret != KNOT_EOK && ret != KNOT_EINVAL) {
		return ret;
	}

	return zone_contents_add_rr(contents, rr, &n);
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

	update->a_ctx = calloc(1, sizeof(*update->a_ctx));
	if (update->a_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = KNOT_EINVAL;
	if (flags & UPDATE_INCREMENTAL) {
		ret = init_incremental(update, zone);
	} else if (flags & UPDATE_FULL) {
		ret = init_full(update, zone);
	}
	if (ret != KNOT_EOK) {
		free(update->a_ctx);
	}

	return ret;
}

int zone_update_from_differences(zone_update_t *update, zone_t *zone, zone_contents_t *old_cont,
                                 zone_contents_t *new_cont, zone_update_flags_t flags)
{
	if (update == NULL || zone == NULL || new_cont == NULL ||
	    !(flags & UPDATE_INCREMENTAL) || (flags & UPDATE_FULL)) {
		return KNOT_EINVAL;
	}

	memset(update, 0, sizeof(*update));
	update->zone = zone;

	mm_ctx_mempool(&update->mm, MM_DEFAULT_BLKSIZE);
	update->flags = flags;

	update->new_cont = new_cont;
	update->new_cont_deep_copy = true;

	update->a_ctx = calloc(1, sizeof(*update->a_ctx));
	if (update->a_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = changeset_init(&update->change, zone->name);
	if (ret != KNOT_EOK) {
		free(update->a_ctx);
		return ret;
	}

	ret = zone_contents_diff(old_cont, new_cont, &update->change);
	if (ret != KNOT_EOK && ret != KNOT_ENODIFF) {
		free(update->a_ctx);
		changeset_clear(&update->change);
		return ret;
	}

	uint32_t apply_flags = update->flags & UPDATE_STRICT ? APPLY_STRICT : 0;
	apply_init_ctx(update->a_ctx, update->new_cont, apply_flags);

	return KNOT_EOK;
}

int zone_update_from_contents(zone_update_t *update, zone_t *zone_without_contents,
                              zone_contents_t *new_cont, zone_update_flags_t flags)
{
	if (update == NULL || zone_without_contents == NULL || new_cont == NULL) {
		return KNOT_EINVAL;
	}

	memset(update, 0, sizeof(*update));
	update->zone = zone_without_contents;

	mm_ctx_mempool(&update->mm, MM_DEFAULT_BLKSIZE);
	update->flags = flags;

	update->new_cont = new_cont;
	update->new_cont_deep_copy = true;

	update->a_ctx = calloc(1, sizeof(*update->a_ctx));
	if (update->a_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	if (flags & UPDATE_INCREMENTAL) {
		int ret = changeset_init(&update->change, zone_without_contents->name);
		if (ret != KNOT_EOK) {
			free(update->a_ctx);
			return ret;
		}

		update->change.soa_from = node_create_rrset(new_cont->apex, KNOT_RRTYPE_SOA);
		if (update->change.soa_from == NULL) {
			changeset_clear(&update->change);
			free(update->a_ctx);
			return KNOT_ENOMEM;
		}
	}

	uint32_t apply_flags = update->flags & UPDATE_STRICT ? APPLY_STRICT : 0;
	apply_init_ctx(update->a_ctx, update->new_cont, apply_flags);

	return KNOT_EOK;
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
	if (apex != NULL) {
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
		if (update->new_cont_deep_copy) {
			update_cleanup(update->a_ctx);
			zone_contents_deep_free(&update->new_cont);
		} else {
			update_rollback(update->a_ctx);
			update_free_zone(&update->new_cont);
		}
		changeset_clear(&update->change);
	} else if (update->flags & UPDATE_FULL) {
		assert(update->new_cont_deep_copy);
		zone_contents_deep_free(&update->new_cont);
	}
	free(update->a_ctx);
	mp_delete(update->mm.ctx);
	memset(update, 0, sizeof(*update));
}

int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		int ret = changeset_add_addition(&update->change, rrset, CHANGESET_CHECK);
		if (ret != KNOT_EOK) {
			return ret;
		}

		if (rrset->type == KNOT_RRTYPE_SOA) {
			/* replace previous SOA */
			ret = apply_replace_soa(update->a_ctx, &update->change);
			if (ret != KNOT_EOK) {
				changeset_remove_addition(&update->change, rrset);
			}
			return ret;
		}

		ret = apply_add_rr(update->a_ctx, rrset);
		if (ret != KNOT_EOK) {
			changeset_remove_addition(&update->change, rrset);
			return ret;
		}

		return KNOT_EOK;
	} else if (update->flags & UPDATE_FULL) {
		if (rrset->type == KNOT_RRTYPE_SOA) {
			/* replace previous SOA */
			return replace_soa(update->new_cont, rrset);
		}

		zone_node_t *n = NULL;
		return zone_contents_add_rr(update->new_cont, rrset, &n);
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update == NULL || rrset == NULL) {
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

		ret = apply_remove_rr(update->a_ctx, rrset);
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

			ret = apply_remove_rr(update->a_ctx, &rrset);
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
					continue;
				}

				ret = apply_remove_rr(update->a_ctx, &rrset);
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

int zone_update_apply_changeset(zone_update_t *update, const changeset_t *changes)
{
	int ret = KNOT_EOK;
	if (update->flags & UPDATE_INCREMENTAL) {
		ret = changeset_merge(&update->change, changes, CHANGESET_CHECK_CANCELOUT);
	}
	if (ret == KNOT_EOK) {
		ret = apply_changeset_directly(update->a_ctx, changes);
	}
	return ret;
}

int zone_update_apply_changeset_fix(zone_update_t *update, changeset_t *changes)
{
	int ret = changeset_cancelout(changes);
	if (ret == KNOT_EOK) {
		ret = changeset_preapply_fix(update->new_cont, changes);
	}
	if (ret == KNOT_EOK) {
		ret = zone_update_apply_changeset(update, changes);
	}
	return ret;
}

static int set_new_soa(zone_update_t *update, unsigned serial_policy)
{
	assert(update);

	knot_rrset_t *soa_cpy = node_create_rrset(zone_update_get_apex(update),
	                                          KNOT_RRTYPE_SOA);
	if (soa_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = zone_update_remove(update, soa_cpy);
	if (ret != KNOT_EOK) {
		knot_rrset_free(&soa_cpy, NULL);
	}

	uint32_t old_serial = knot_soa_serial(&soa_cpy->rrs);
	uint32_t new_serial = serial_next(old_serial, serial_policy);
	if (serial_compare(old_serial, new_serial) != SERIAL_LOWER) {
		log_zone_warning(update->zone->name, "updated serial is lower "
		                 "than current, serial %u -> %u",
		                 old_serial, new_serial);
		ret = KNOT_ESOAINVAL;
	} else {
		knot_soa_serial_set(&soa_cpy->rrs, new_serial);

		ret = zone_update_add(update, soa_cpy);
	}
	knot_rrset_free(&soa_cpy, NULL);

	return ret;
}

int zone_update_increment_soa(zone_update_t *update, conf_t *conf)
{
	if (update == NULL || conf == NULL) {
		return KNOT_EINVAL;
	}

	conf_val_t val = conf_zone_get(conf, C_SERIAL_POLICY, update->zone->name);
	return set_new_soa(update, conf_opt(&val));
}

static int commit_incremental(conf_t *conf, zone_update_t *update,
                              zone_contents_t **contents_out)
{
	assert(update);
	assert(contents_out);

	if (changeset_empty(&update->change)) {
		changeset_clear(&update->change);
		if (update->zone->contents == NULL || update->new_cont_deep_copy) {
			*contents_out = update->new_cont;
		}
		return KNOT_EOK;
	}

	zone_contents_t *new_contents = update->new_cont;
	int ret = KNOT_EOK;
	if (zone_update_to(update) == NULL) {
		/* No SOA in the update, create one according to the current policy */
		ret = zone_update_increment_soa(update, conf);
		if (ret != KNOT_EOK) {
			zone_update_clear(update);
			return ret;
		}
	}

	ret = apply_finalize(update->a_ctx);
	if (ret != KNOT_EOK) {
		zone_update_clear(update);
		return ret;
	}

	/* Write changes to journal if all went well. */
	conf_val_t val = conf_zone_get(conf, C_JOURNAL_CONTENT, update->zone->name);
	if (conf_opt(&val) != JOURNAL_CONTENT_NONE) {
		ret = zone_change_store(conf, update->zone, &update->change);
		if (ret != KNOT_EOK) {
			return ret;
		}
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

	int ret = zone_contents_adjust_full(update->new_cont);
	if (ret != KNOT_EOK) {
		zone_update_clear(update);
		return ret;
	}

	/* Store new zone contents in journal. */
	conf_val_t val = conf_zone_get(conf, C_JOURNAL_CONTENT, update->zone->name);
	if (conf_opt(&val) == JOURNAL_CONTENT_ALL) {
		ret = zone_in_journal_store(conf, update->zone, update->new_cont);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	*contents_out = update->new_cont;

	return KNOT_EOK;
}

/*! \brief Routine for calling call_rcu() easier way.
 *
 * Consider moving elsewhere, as it has no direct relation to zone-update.
 */
typedef struct {
	struct rcu_head rcuhead;
	void (*callback)(void *);
	void *ctx;
	bool call_ctx_addr;
} callrcu_wrapper_t;

static void callrcu_wrapper_cb(struct rcu_head *param)
{
	callrcu_wrapper_t *wrap = (callrcu_wrapper_t *)param;
	if (wrap->call_ctx_addr) {
		// Paradigm free_fun(type_t **t) freeing the pointer completely.
		wrap->callback(&wrap->ctx);
	} else {
		// Paradigm clear_fun(type_t *t) just clearing the contents of type_t.
		wrap->callback(wrap->ctx);
		free(wrap->ctx);
	}
	free(wrap);

	// Trim extra heap.
	mem_trim();
}

/* NOTE: Does nothing if not enough memory. */
static void callrcu_wrapper(void *ctx, void (*callback)(void *), bool call_ctx_addr)
{
	callrcu_wrapper_t *wrap = calloc(1, sizeof(callrcu_wrapper_t));
	if (wrap != NULL) {
		wrap->callback = callback;
		wrap->ctx = ctx;
		wrap->call_ctx_addr = call_ctx_addr;
		call_rcu((struct rcu_head *)wrap, callrcu_wrapper_cb);
	}
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
	} else {
		ret = commit_full(conf, update, &new_contents);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	/* If there is anything to change. */
	if (new_contents == NULL) {
		return KNOT_EOK;
	}

	/* Check the zone size. */
	conf_val_t val = conf_zone_get(conf, C_MAX_ZONE_SIZE, update->zone->name);
	size_t size_limit = conf_int(&val);

	if (new_contents->size > size_limit) {
		/* Recoverable error. */
		return KNOT_EZONESIZE;
	}

	/* Check if the zone has changed and possible flush makes sense. */
	if (!changeset_empty(&update->change)) {
		update->zone->zonefile.changed = true;
	}

	/* Switch zone contents. */
	zone_contents_t *old_contents;
	old_contents = zone_switch_contents(update->zone, new_contents);

	/* Sync RCU. */
	if (update->flags & UPDATE_FULL) {
		assert(update->new_cont_deep_copy);
		callrcu_wrapper(old_contents, (void (*)(void *))zone_contents_deep_free, true);
	} else if (update->flags & UPDATE_INCREMENTAL) {
		if (update->new_cont_deep_copy) {
			callrcu_wrapper(old_contents, (void (*)(void *))zone_contents_deep_free, true);
		} else {
			callrcu_wrapper(old_contents, (void (*)(void *))update_free_zone, true);
		}
		changeset_clear(&update->change);
	}
	callrcu_wrapper(update->a_ctx, (void (*)(void *))update_cleanup, false);
	update->a_ctx = NULL;
	update->new_cont = NULL;

	/* Sync zonefile immediately if configured. */
	val = conf_zone_get(conf, C_ZONEFILE_SYNC, update->zone->name);
	if (conf_int(&val) == 0) {
		zone_events_schedule_now(update->zone, ZONE_EVENT_FLUSH);
	}

	return KNOT_EOK;
}

static int iter_init_tree_iters(zone_update_iter_t *it, zone_update_t *update,
                                bool nsec3)
{
	/* Set zone iterator. */
	zone_contents_t *_contents = update->new_cont;

	/* Begin iteration. We can safely assume _contents is a valid pointer. */
	zone_tree_t *tree = nsec3 ? _contents->nsec3_nodes : _contents->nodes;
	it->tree_it = trie_it_begin(tree);
	if (it->tree_it == NULL) {
		return KNOT_ENOMEM;
	}

	it->cur_node = (zone_node_t *)(*trie_it_val(it->tree_it));

	return KNOT_EOK;
}

static int iter_get_next_node(zone_update_iter_t *it)
{
	trie_it_next(it->tree_it);
	if (trie_it_finished(it->tree_it)) {
		trie_it_free(it->tree_it);
		it->tree_it = NULL;
		it->cur_node = NULL;
		return KNOT_ENOENT;
	}

	it->cur_node = (zone_node_t *)(*trie_it_val(it->tree_it));

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

	it->cur_node = (zone_node_t *)(*trie_it_val(it->tree_it));

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

	trie_it_free(it->tree_it);
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
