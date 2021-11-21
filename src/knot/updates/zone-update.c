/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/catalog/interpret.h"
#include "knot/common/log.h"
#include "knot/dnssec/zone-events.h"
#include "knot/updates/zone-update.h"
#include "knot/zone/adds_tree.h"
#include "knot/zone/adjust.h"
#include "knot/zone/digest.h"
#include "knot/zone/serial.h"
#include "knot/zone/zone-diff.h"
#include "knot/zone/zonefile.h"
#include "contrib/trim.h"
#include "contrib/ucw/lists.h"

#include <signal.h>
#include <unistd.h>
#include <urcu.h>

// Call mem_trim() whenever accumulated size of updated zones reaches this size.
#define UPDATE_MEMTRIM_AT (10 * 1024 * 1024)

static int init_incremental(zone_update_t *update, zone_t *zone, zone_contents_t *old_contents)
{
	if (old_contents == NULL) {
		return KNOT_EINVAL;
	}

	int ret = changeset_init(&update->change, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (update->flags & UPDATE_HYBRID) {
		update->new_cont = old_contents;
	} else {
		ret = zone_contents_cow(old_contents, &update->new_cont);
		if (ret != KNOT_EOK) {
			changeset_clear(&update->change);
			return ret;
		}
	}

	uint32_t apply_flags = (update->flags & UPDATE_STRICT) ? APPLY_STRICT : 0;
	apply_flags |= (update->flags & UPDATE_HYBRID) ? APPLY_UNIFY_FULL : 0;
	ret = apply_init_ctx(update->a_ctx, update->new_cont, apply_flags);
	if (ret != KNOT_EOK) {
		changeset_clear(&update->change);
		return ret;
	}

	/* Copy base SOA RR. */
	update->change.soa_from =
		node_create_rrset(old_contents->apex, KNOT_RRTYPE_SOA);
	if (update->change.soa_from == NULL) {
		zone_contents_free(update->new_cont);
		changeset_clear(&update->change);
		return KNOT_ENOMEM;
	}

	return KNOT_EOK;
}

static int init_full(zone_update_t *update, zone_t *zone)
{
	update->new_cont = zone_contents_new(zone->name, true);
	if (update->new_cont == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = apply_init_ctx(update->a_ctx, update->new_cont, APPLY_UNIFY_FULL);
	if (ret != KNOT_EOK) {
		zone_contents_free(update->new_cont);
		return ret;
	}

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

	ret = zone_contents_add_rr(contents, rr, &n);
	if (ret == KNOT_ETTL) {
		return KNOT_EOK;
	}

	return ret;
}

static int init_base(zone_update_t *update, zone_t *zone, zone_contents_t *old_contents,
                     zone_update_flags_t flags)
{
	if (update == NULL || zone == NULL) {
		return KNOT_EINVAL;
	}

	memset(update, 0, sizeof(*update));
	update->zone = zone;
	update->flags = flags;

	update->a_ctx = calloc(1, sizeof(*update->a_ctx));
	if (update->a_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	if (zone->control_update != NULL && zone->control_update != update) {
		log_zone_warning(zone->name, "blocked zone update due to open control transaction");
	}

	knot_sem_wait(&zone->cow_lock);
	update->a_ctx->cow_mutex = &zone->cow_lock;

	if (old_contents == NULL) {
		old_contents = zone->contents; // don't obtain this pointer before any other zone_update ceased to exist!
	}

	int ret = KNOT_EINVAL;
	if (flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
		ret = init_incremental(update, zone, old_contents);
	} else if (flags & UPDATE_FULL) {
		ret = init_full(update, zone);
	}
	if (ret != KNOT_EOK) {
		knot_sem_post(&zone->cow_lock);
		free(update->a_ctx);
	}

	return ret;
}

/* ------------------------------- API -------------------------------------- */

int zone_update_init(zone_update_t *update, zone_t *zone, zone_update_flags_t flags)
{
	return init_base(update, zone, NULL, flags);
}

int zone_update_from_differences(zone_update_t *update, zone_t *zone, zone_contents_t *old_cont,
				 zone_contents_t *new_cont, zone_update_flags_t flags, bool ignore_dnssec)
{
	if (update == NULL || zone == NULL || new_cont == NULL ||
	    !(flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) || (flags & UPDATE_FULL)) {
		return KNOT_EINVAL;
	}

	changeset_t diff;
	int ret = changeset_init(&diff, zone->name);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = init_base(update, zone, old_cont, flags);
	if (ret != KNOT_EOK) {
		changeset_clear(&diff);
		return ret;
	}

	if (old_cont == NULL) {
		old_cont = zone->contents;
	}

	ret = zone_contents_diff(old_cont, new_cont, &diff, ignore_dnssec);
	switch (ret) {
	case KNOT_ENODIFF:
	case KNOT_ESEMCHECK:
	case KNOT_EOK:
		break;
	case KNOT_ERANGE:
		additionals_tree_free(update->new_cont->adds_tree);
		update->new_cont->adds_tree = NULL;
		update->new_cont = NULL; // Prevent deep_free as old_cont will be used later.
		update->a_ctx->flags &= ~APPLY_UNIFY_FULL; // Prevent Unify of old_cont that will be used later.
		// FALLTHROUGH
	default:
		changeset_clear(&diff);
		zone_update_clear(update);
		return ret;
	}

	ret = zone_update_apply_changeset(update, &diff);
	changeset_clear(&diff);
	if (ret != KNOT_EOK) {
		zone_update_clear(update);
		return ret;
	}

	update->init_cont = new_cont;
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
	update->flags = flags;
	update->new_cont = new_cont;

	update->a_ctx = calloc(1, sizeof(*update->a_ctx));
	if (update->a_ctx == NULL) {
		return KNOT_ENOMEM;
	}

	if (zone_without_contents->control_update != NULL) {
		log_zone_warning(zone_without_contents->name,
		                 "blocked zone update due to open control transaction");
	}

	knot_sem_wait(&update->zone->cow_lock);
	update->a_ctx->cow_mutex = &update->zone->cow_lock;

	if (flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
		int ret = changeset_init(&update->change, zone_without_contents->name);
		if (ret != KNOT_EOK) {
			free(update->a_ctx);
			update->a_ctx = NULL;
			knot_sem_post(&update->zone->cow_lock);
			return ret;
		}

		update->change.soa_from = node_create_rrset(new_cont->apex, KNOT_RRTYPE_SOA);
		if (update->change.soa_from == NULL) {
			changeset_clear(&update->change);
			free(update->a_ctx);
			update->a_ctx = NULL;
			knot_sem_post(&update->zone->cow_lock);
			return KNOT_ENOMEM;
		}
	}

	uint32_t apply_flags = (update->flags & UPDATE_STRICT) ? APPLY_STRICT : 0;
	int ret = apply_init_ctx(update->a_ctx, update->new_cont, apply_flags | APPLY_UNIFY_FULL);
	if (ret != KNOT_EOK) {
		changeset_clear(&update->change);
		free(update->a_ctx);
		update->a_ctx = NULL;
		knot_sem_post(&update->zone->cow_lock);
		return ret;
	}

	return KNOT_EOK;
}

int zone_update_start_extra(zone_update_t *update, conf_t *conf)
{
	assert((update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)));

	int ret = changeset_init(&update->extra_ch, update->new_cont->apex->owner);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (update->init_cont != NULL) {
		ret = zone_update_increment_soa(update, conf);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = zone_contents_diff(update->init_cont, update->new_cont, &update->extra_ch, false);
		if (ret != KNOT_EOK) {
			return ret;
		}
	} else {
		update->extra_ch.soa_from = node_create_rrset(update->new_cont->apex, KNOT_RRTYPE_SOA);
		if (update->extra_ch.soa_from == NULL) {
			return KNOT_ENOMEM;
		}

		ret = zone_update_increment_soa(update, conf);
		if (ret != KNOT_EOK) {
			return ret;
		}

		update->extra_ch.soa_to = node_create_rrset(update->new_cont->apex, KNOT_RRTYPE_SOA);
		if (update->extra_ch.soa_to == NULL) {
			return KNOT_ENOMEM;
		}
	}

	update->flags |= UPDATE_EXTRA_CHSET;
	return KNOT_EOK;
}

const zone_node_t *zone_update_get_node(zone_update_t *update, const knot_dname_t *dname)
{
	if (update == NULL || dname == NULL) {
		return NULL;
	}

	return zone_contents_node_or_nsec3(update->new_cont, dname);
}

uint32_t zone_update_current_serial(zone_update_t *update)
{
	const zone_node_t *apex = update->new_cont->apex;
	if (apex != NULL) {
		return knot_soa_serial(node_rdataset(apex, KNOT_RRTYPE_SOA)->rdata);
	} else {
		return 0;
	}
}

bool zone_update_changed_nsec3param(const zone_update_t *update)
{
	if (update->zone->contents == NULL) {
		return true;
	}

	dnssec_nsec3_params_t *orig = &update->zone->contents->nsec3_params;
	dnssec_nsec3_params_t *upd = &update->new_cont->nsec3_params;
	return !dnssec_nsec3_params_match(orig, upd);
}

const knot_rdataset_t *zone_update_from(zone_update_t *update)
{
	if (update == NULL) {
		return NULL;
	}

	if (update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
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
	} else {
		if (update->change.soa_to == NULL) {
			return NULL;
		}
		return &update->change.soa_to->rrs;
	}

	return NULL;
}

void zone_update_clear(zone_update_t *update)
{
	if (update == NULL || update->zone == NULL) {
		return;
	}

	if (update->new_cont != NULL) {
		additionals_tree_free(update->new_cont->adds_tree);
		update->new_cont->adds_tree = NULL;
	}

	if (update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
		changeset_clear(&update->change);
		changeset_clear(&update->extra_ch);
	}

	zone_contents_deep_free(update->init_cont);

	if (update->flags & (UPDATE_FULL | UPDATE_HYBRID)) {
		apply_cleanup(update->a_ctx);
		zone_contents_deep_free(update->new_cont);
	} else {
		apply_rollback(update->a_ctx);
	}

	free(update->a_ctx);
	memset(update, 0, sizeof(*update));
}

inline static void update_affected_rrtype(zone_update_t *update, uint16_t rrtype)
{
	switch (rrtype) {
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		update->flags |= UPDATE_CHANGED_NSEC;
		break;
	}
}

static int solve_add_different_ttl(zone_update_t *update, const knot_rrset_t *add)
{
	if (add->type == KNOT_RRTYPE_RRSIG || add->type == KNOT_RRTYPE_SOA) {
		return KNOT_EOK;
	}

	const zone_node_t *exist_node = zone_contents_find_node(update->new_cont, add->owner);
	const knot_rrset_t exist_rr = node_rrset(exist_node, add->type);
	if (knot_rrset_empty(&exist_rr) || exist_rr.ttl == add->ttl) {
		return KNOT_EOK;
	}

	knot_dname_txt_storage_t buff;
	char *owner = knot_dname_to_str(buff, add->owner, sizeof(buff));
	if (owner == NULL) {
		owner = "";
	}
	char type[16] = "";
	knot_rrtype_to_string(add->type, type, sizeof(type));
	log_zone_notice(update->zone->name, "TTL mismatch, owner %s, type %s, "
	                "TTL set to %u", owner, type, add->ttl);

	knot_rrset_t *exist_copy = knot_rrset_copy(&exist_rr, NULL);
	if (exist_copy == NULL) {
		return KNOT_ENOMEM;
	}
	int ret = zone_update_remove(update, exist_copy);
	if (ret == KNOT_EOK) {
		exist_copy->ttl = add->ttl;
		ret = zone_update_add(update, exist_copy);
	}
	knot_rrset_free(exist_copy, NULL);
	return ret;
}

int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}
	if (knot_rrset_empty(rrset)) {
		return KNOT_EOK;
	}

	if (update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
		int ret = solve_add_different_ttl(update, rrset);
		if (ret == KNOT_EOK) {
			ret = changeset_add_addition(&update->change, rrset, CHANGESET_CHECK);
		}
		if (ret == KNOT_EOK && (update->flags & UPDATE_EXTRA_CHSET)) {
			ret = changeset_add_addition(&update->extra_ch, rrset, CHANGESET_CHECK);
		}
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		if (rrset->type == KNOT_RRTYPE_SOA) {
			// replace previous SOA
			int ret = apply_replace_soa(update->a_ctx, rrset);
			if (ret != KNOT_EOK) {
				changeset_remove_addition(&update->change, rrset);
			}
			return ret;
		}

		int ret = apply_add_rr(update->a_ctx, rrset);
		if (ret != KNOT_EOK) {
			changeset_remove_addition(&update->change, rrset);
			return ret;
		}

		update_affected_rrtype(update, rrset->type);
		return KNOT_EOK;
	} else if (update->flags & (UPDATE_FULL | UPDATE_HYBRID)) {
		if (rrset->type == KNOT_RRTYPE_SOA) {
			/* replace previous SOA */
			return replace_soa(update->new_cont, rrset);
		}

		zone_node_t *n = NULL;
		int ret = zone_contents_add_rr(update->new_cont, rrset, &n);
		if (ret == KNOT_ETTL) {
			knot_dname_txt_storage_t buff;
			char *owner = knot_dname_to_str(buff, rrset->owner, sizeof(buff));
			if (owner == NULL) {
				owner = "";
			}
			char type[16] = "";
			knot_rrtype_to_string(rrset->type, type, sizeof(type));
			log_zone_notice(update->new_cont->apex->owner,
			                "TTL mismatch, owner %s, type %s, "
			                "TTL set to %u", owner, type, rrset->ttl);
			return KNOT_EOK;
		}

		return ret;
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset)
{
	if (update == NULL || rrset == NULL) {
		return KNOT_EINVAL;
	}
	if (knot_rrset_empty(rrset)) {
		return KNOT_EOK;
	}

	if ((update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) && rrset->type != KNOT_RRTYPE_SOA) {
		int ret = changeset_add_removal(&update->change, rrset, CHANGESET_CHECK);
		if (ret == KNOT_EOK && (update->flags & UPDATE_EXTRA_CHSET)) {
			ret = changeset_add_removal(&update->extra_ch, rrset, CHANGESET_CHECK);
		}
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	if (update->flags & UPDATE_INCREMENTAL) {
		if (rrset->type == KNOT_RRTYPE_SOA) {
			/* SOA is replaced with addition */
			return KNOT_EOK;
		}

		int ret = apply_remove_rr(update->a_ctx, rrset);
		if (ret != KNOT_EOK) {
			changeset_remove_removal(&update->change, rrset);
			return ret;
		}

		update_affected_rrtype(update, rrset->type);
		return KNOT_EOK;
	} else if (update->flags & (UPDATE_FULL | UPDATE_HYBRID)) {
		zone_node_t *n = NULL;
		return zone_contents_remove_rr(update->new_cont, rrset, &n);
	} else {
		return KNOT_EINVAL;
	}
}

int zone_update_remove_rrset(zone_update_t *update, knot_dname_t *owner, uint16_t type)
{
	if (update == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	const zone_node_t *node = zone_contents_node_or_nsec3(update->new_cont, owner);
	if (node == NULL) {
		return KNOT_ENONODE;
	}

	knot_rrset_t rrset = node_rrset(node, type);
	if (rrset.owner == NULL) {
		return KNOT_ENOENT;
	}

	return zone_update_remove(update, &rrset);
}

int zone_update_remove_node(zone_update_t *update, const knot_dname_t *owner)
{
	if (update == NULL || owner == NULL) {
		return KNOT_EINVAL;
	}

	const zone_node_t *node = zone_contents_node_or_nsec3(update->new_cont, owner);
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

	return KNOT_EOK;
}

static int update_chset_step(const knot_rrset_t *rrset, bool addition, void *ctx)
{
	zone_update_t *update = ctx;
	if (addition) {
		return zone_update_add(update, rrset);
	} else {
		return zone_update_remove(update, rrset);
	}
}

int zone_update_apply_changeset(zone_update_t *update, const changeset_t *changes)
{
	return changeset_walk(changes, update_chset_step, update);
}

int zone_update_apply_changeset_reverse(zone_update_t *update, const changeset_t *changes)
{
	changeset_t reverse;
	reverse.remove = changes->add;
	reverse.add = changes->remove;
	reverse.soa_from = changes->soa_to;
	reverse.soa_to = changes->soa_from;
	return zone_update_apply_changeset(update, &reverse);
}

static int set_new_soa(zone_update_t *update, unsigned serial_policy)
{
	assert(update);

	knot_rrset_t *soa_cpy = node_create_rrset(update->new_cont->apex,
	                                          KNOT_RRTYPE_SOA);
	if (soa_cpy == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = zone_update_remove(update, soa_cpy);
	if (ret != KNOT_EOK) {
		knot_rrset_free(soa_cpy, NULL);
		return ret;
	}

	uint32_t old_serial = knot_soa_serial(soa_cpy->rrs.rdata);
	uint32_t new_serial = serial_next(old_serial, serial_policy, 1);
	if (serial_compare(old_serial, new_serial) != SERIAL_LOWER) {
		log_zone_warning(update->zone->name, "updated SOA serial is lower "
		                 "than current, serial %u -> %u",
		                 old_serial, new_serial);
		ret = KNOT_ESOAINVAL;
	} else {
		knot_soa_serial_set(soa_cpy->rrs.rdata, new_serial);

		ret = zone_update_add(update, soa_cpy);
	}
	knot_rrset_free(soa_cpy, NULL);

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

static int commit_journal(conf_t *conf, zone_update_t *update)
{
	conf_val_t val = conf_zone_get(conf, C_JOURNAL_CONTENT, update->zone->name);
	unsigned content = conf_opt(&val);
	int ret = KNOT_EOK;
	if ((update->flags & UPDATE_INCREMENTAL) ||
	    (update->flags & UPDATE_HYBRID)) {
		changeset_t *extra = (update->flags & UPDATE_EXTRA_CHSET) ? &update->extra_ch : NULL;
		if (content != JOURNAL_CONTENT_NONE && !changeset_empty(&update->change)) {
			ret = zone_change_store(conf, update->zone, &update->change, extra);
		}
	} else {
		if (content == JOURNAL_CONTENT_ALL) {
			return zone_in_journal_store(conf, update->zone, update->new_cont);
		} else if (content != JOURNAL_CONTENT_NONE) { // zone_in_journal_store does this automatically
			return zone_changes_clear(conf, update->zone);
		}
	}
	return ret;
}

static int commit_incremental(conf_t *conf, zone_update_t *update)
{
	assert(update);

	if (zone_update_to(update) == NULL && !changeset_empty(&update->change)) {
		/* No SOA in the update, create one according to the current policy */
		int ret = zone_update_increment_soa(update, conf);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}

	return KNOT_EOK;
}

static int commit_full(conf_t *conf, zone_update_t *update)
{
	assert(update);

	/* Check if we have SOA. We might consider adding full semantic check here.
	 * But if we wanted full sem-check I'd consider being it controlled by a flag
	 * - to enable/disable it on demand. */
	if (!node_rrtype_exists(update->new_cont->apex, KNOT_RRTYPE_SOA)) {
		return KNOT_ESEMCHECK;
	}

	return KNOT_EOK;
}

static int update_catalog(conf_t *conf, zone_update_t *update)
{
	conf_val_t val = conf_zone_get(conf, C_CATALOG_TPL, update->zone->name);
	if (val.code != KNOT_EOK) {
		return (val.code == KNOT_ENOENT || val.code == KNOT_YP_EINVAL_ID) ? KNOT_EOK : val.code;
	}

	zone_set_flag(update->zone, ZONE_IS_CATALOG);

	int ret = catalog_zone_verify(update->new_cont);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ssize_t upd_count = 0;
	if ((update->flags & UPDATE_INCREMENTAL)) {
		ret = catalog_update_from_zone(zone_catalog_upd(update->zone),
		                               update->change.remove, update->new_cont,
		                               true, zone_catalog(update->zone), &upd_count);
		if (ret == KNOT_EOK) {
			ret = catalog_update_from_zone(zone_catalog_upd(update->zone),
			                               update->change.add, update->new_cont,
			                               false, NULL, &upd_count);
		}
	} else {
		ret = catalog_update_del_all(zone_catalog_upd(update->zone),
		                             zone_catalog(update->zone),
		                             update->zone->name, &upd_count);
		if (ret == KNOT_EOK) {
			ret = catalog_update_from_zone(zone_catalog_upd(update->zone),
			                               update->new_cont, update->new_cont,
			                               false, NULL, &upd_count);
		}
	}

	if (ret == KNOT_EOK) {
		log_zone_info(update->zone->name, "catalog reloaded, %zd updates", upd_count);
		if (kill(getpid(), SIGUSR1) != 0) {
			ret = knot_map_errno();
		}
	} else {
		// this cant normally happen, just some ENOMEM or so
		(void)catalog_update_del_all(zone_catalog_upd(update->zone),
		                             zone_catalog(update->zone),
		                             update->zone->name, &upd_count);
	}

	return ret;
}

typedef struct {
	pthread_mutex_t lock;
	size_t counter;
} counter_reach_t;

static bool counter_reach(counter_reach_t *counter, size_t increment, size_t limit)
{
	bool reach = false;
	pthread_mutex_lock(&counter->lock);
	counter->counter += increment;
	if (counter->counter >= limit) {
		counter->counter = 0;
		reach = true;
	}
	pthread_mutex_unlock(&counter->lock);
	return reach;
}

/*! \brief Struct for what needs to be cleared after RCU.
 *
 * This can't be zone_update_t structure as this might be already freed at that time.
 */
typedef struct {
	struct rcu_head rcuhead;

	zone_contents_t *free_contents;
	void (*free_method)(zone_contents_t *);

	apply_ctx_t *cleanup_apply;

	size_t new_cont_size;
} update_clear_ctx_t;

static void update_clear(struct rcu_head *param)
{
	static counter_reach_t counter = { PTHREAD_MUTEX_INITIALIZER, 0 };

	update_clear_ctx_t *ctx = (update_clear_ctx_t *)param;

	ctx->free_method(ctx->free_contents);
	apply_cleanup(ctx->cleanup_apply);
	free(ctx->cleanup_apply);

	if (counter_reach(&counter, ctx->new_cont_size, UPDATE_MEMTRIM_AT)) {
		mem_trim();
	}

	free(ctx);
}

static void discard_adds_tree(zone_update_t *update)
{
	additionals_tree_free(update->new_cont->adds_tree);
	update->new_cont->adds_tree = NULL;
}

int zone_update_semcheck(zone_update_t *update)
{
	if (update == NULL) {
		return KNOT_EINVAL;
	}

	zone_tree_t *node_ptrs = (update->flags & UPDATE_INCREMENTAL) ?
	                         update->a_ctx->node_ptrs : NULL;

	// adjust_cb_nsec3_pointer not needed as we don't check DNSSEC here
	int ret = zone_adjust_contents(update->new_cont, adjust_cb_flags, NULL,
	                               false, false, 1, node_ptrs);
	if (ret != KNOT_EOK) {
		return ret;
	}

	sem_handler_t handler = {
		.cb = err_handler_logger
	};

	ret = sem_checks_process(update->new_cont, SEMCHECK_MANDATORY_ONLY,
	                         &handler, time(NULL));
	if (ret != KNOT_EOK) {
		// error is logged by the error handler
		return ret;
	}

	return KNOT_EOK;
}

int zone_update_verify_digest(conf_t *conf, zone_update_t *update)
{
	conf_val_t val = conf_zone_get(conf, C_ZONEMD_VERIFY, update->zone->name);
	if (!conf_bool(&val)) {
		return KNOT_EOK;
	}

	int ret = zone_contents_digest_verify(update->new_cont);
	if (ret != KNOT_EOK) {
		log_zone_error(update->zone->name, "ZONEMD, verification failed (%s)",
		               knot_strerror(ret));
	} else {
		log_zone_info(update->zone->name, "ZONEMD, verification successful");
	}

	return ret;
}

int zone_update_commit(conf_t *conf, zone_update_t *update)
{
	if (conf == NULL || update == NULL) {
		return KNOT_EINVAL;
	}

	int ret = KNOT_EOK;

	if ((update->flags & UPDATE_INCREMENTAL) && changeset_empty(&update->change)) {
		zone_update_clear(update);
		return KNOT_EOK;
	}

	if (update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
		ret = commit_incremental(conf, update);
	} else {
		ret = commit_full(conf, update);
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	conf_val_t val = conf_zone_get(conf, C_DNSSEC_SIGNING, update->zone->name);
	bool dnssec = conf_bool(&val);

	conf_val_t thr = conf_zone_get(conf, C_ADJUST_THR, update->zone->name);
	if ((update->flags & (UPDATE_HYBRID | UPDATE_FULL))) {
		ret = zone_adjust_full(update->new_cont, conf_int(&thr));
	} else {
		ret = zone_adjust_incremental_update(update, conf_int(&thr));
	}
	if (ret != KNOT_EOK) {
		discard_adds_tree(update);
		return ret;
	}

	/* Check the zone size. */
	val = conf_zone_get(conf, C_ZONE_MAX_SIZE, update->zone->name);
	size_t size_limit = conf_int(&val);

	if (update->new_cont->size > size_limit) {
		discard_adds_tree(update);
		return KNOT_EZONESIZE;
	}

	val = conf_zone_get(conf, C_DNSSEC_VALIDATION, update->zone->name);
	if (conf_bool(&val)) {
		bool incr_valid = update->flags & UPDATE_INCREMENTAL;
		const char *msg_valid = incr_valid ? "incremental " : "";

		ret = knot_dnssec_validate_zone(update, conf, incr_valid);
		if (ret != KNOT_EOK) {
			log_zone_error(update->zone->name, "DNSSEC, %svalidation failed (%s)",
			               msg_valid, knot_strerror(ret));
			char name_str[KNOT_DNAME_TXT_MAXLEN], type_str[16];
			if (knot_dname_to_str(name_str, update->validation_hint.node, sizeof(name_str)) != NULL &&
			    knot_rrtype_to_string(update->validation_hint.rrtype, type_str, sizeof(type_str)) >= 0) {
				log_zone_error(update->zone->name, "DNSSEC, validation hint: %s %s",
				               name_str, type_str);
			}
			discard_adds_tree(update);
			return ret;
		} else {
			log_zone_info(update->zone->name, "DNSSEC, %svalidation successful", msg_valid);
		}
	}

	ret = update_catalog(conf, update);
	if (ret != KNOT_EOK) {
		log_zone_error(update->zone->name, "failed to process catalog zone (%s)", knot_strerror(ret));
		discard_adds_tree(update);
		return ret;
	}

	ret = commit_journal(conf, update);
	if (ret != KNOT_EOK) {
		discard_adds_tree(update);
		return ret;
	}

	if (dnssec && zone_is_slave(conf, update->zone)) {
		ret = zone_set_lastsigned_serial(update->zone,
		                                 zone_contents_serial(update->new_cont));
		if (ret != KNOT_EOK) {
			log_zone_warning(update->zone->name,
			                 "unable to save lastsigned serial, "
			                 "future transfers might be broken");
		}
	}

	/* Switch zone contents. */
	zone_contents_t *old_contents;
	old_contents = zone_switch_contents(update->zone, update->new_cont);

	if (update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
		changeset_clear(&update->change);
		changeset_clear(&update->extra_ch);
	}
	zone_contents_deep_free(update->init_cont);

	update_clear_ctx_t *clear_ctx = calloc(1, sizeof(*clear_ctx));
	if (clear_ctx != NULL) {
		clear_ctx->free_contents = old_contents;
		clear_ctx->free_method = (
			(update->flags & (UPDATE_FULL | UPDATE_HYBRID)) ?
			zone_contents_deep_free : update_free_zone
		);
		clear_ctx->cleanup_apply = update->a_ctx;
		clear_ctx->new_cont_size = update->new_cont->size;

		call_rcu((struct rcu_head *)clear_ctx, update_clear);
	} else {
		log_zone_error(update->zone->name, "failed to deallocate unused memory");
	}

	/* Sync zonefile immediately if configured. */
	val = conf_zone_get(conf, C_ZONEFILE_SYNC, update->zone->name);
	if (conf_int(&val) == 0) {
		zone_events_schedule_now(update->zone, ZONE_EVENT_FLUSH);
	}

	memset(update, 0, sizeof(*update));

	return KNOT_EOK;
}

bool zone_update_no_change(zone_update_t *update)
{
	if (update == NULL) {
		return true;
	}

	if (update->flags & (UPDATE_INCREMENTAL | UPDATE_HYBRID)) {
		return changeset_empty(&update->change);
	} else {
		/* This branch does not make much sense and FULL update will most likely
		 * be a change every time anyway, just return false. */
		return false;
	}
}

static bool contents_have_dnskey(const zone_contents_t *contents)
{
	if (contents == NULL) {
		return false;
	}
	assert(contents->apex != NULL);
	return (node_rrtype_exists(contents->apex, KNOT_RRTYPE_DNSKEY) ||
	        node_rrtype_exists(contents->apex, KNOT_RRTYPE_CDNSKEY) ||
		node_rrtype_exists(contents->apex, KNOT_RRTYPE_CDS));
}

bool zone_update_changes_dnskey(zone_update_t *update)
{
	if (update->flags & UPDATE_FULL) {
		return contents_have_dnskey(update->new_cont);
	} else {
		return (contents_have_dnskey(update->change.remove) ||
		        contents_have_dnskey(update->change.add));
	}
}
