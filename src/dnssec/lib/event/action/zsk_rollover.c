/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/error.h"
#include "dnssec/event.h"
#include "dnssec/keyusage.h"
#include "event/action.h"
#include "event/keystate.h"
#include "event/utils.h"
#include "key/internal.h"
#include "shared.h"

/*
 * Three stage ZSK key pre-publish rollover:
 *
 * 1. The new key is introduced in the key set.
 * 2. All signatures are replaced with new ones.
 * 3. The old key is removed from the key set.
 *
 * RFC 6781 (Section 4.1.1.1)
 */

typedef bool (*key_match_cb)(const dnssec_kasp_key_t *key, void *data);

static bool newer_key(const dnssec_kasp_key_t *prev, const dnssec_kasp_key_t *cur)
{
	return cur->timing.created == 0 ||
	       cur->timing.created >= prev->timing.created;
}

static bool zsk_match(const dnssec_kasp_key_t *key, time_t now, key_state_t state)
{
	return dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
	       get_key_state(key, now) == state;
}

static dnssec_kasp_key_t *last_key(dnssec_event_ctx_t *ctx, key_state_t state)
{
	assert(ctx);
	assert(ctx->zone);

	dnssec_kasp_key_t *match = NULL;

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(ctx->zone);
	dnssec_list_foreach(i, keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(i);
		if ((match == NULL || newer_key(match, key)) &&
		    zsk_match(key, ctx->now, state)
		) {
			match = key;
		}
	}

	return match;
}

static bool responds_to(dnssec_event_type_t event)
{
	switch (event) {
	case DNSSEC_EVENT_ZSK_ROLL_PUBLISH_NEW_KEY:
	case DNSSEC_EVENT_ZSK_ROLL_REPLACE_SIGNATURES:
	case DNSSEC_EVENT_ZSK_ROLL_REMOVE_OLD_KEY:
		return true;
	default:
		return false;
	}
}

#define subzero(a, b) ((a) > (b) ? (a) - (b) : 0)

static int plan(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	assert(ctx);
	assert(event);

	/*
	 * We should not start another rollover, if there is a rollover
	 * in progress. Therefore we will check the keys in reverse order
	 * to make sure all stages are finished.
	 */

	dnssec_kasp_key_t *retired = last_key(ctx, DNSSEC_KEY_STATE_RETIRED);
	if (retired) {
		if (ctx->now < retired->timing.retire) {
			return DNSSEC_EINVAL;
		}

		uint32_t retired_time = ctx->now - retired->timing.retire;
		uint32_t retired_need = ctx->policy->propagation_delay +
					ctx->policy->zone_maximal_ttl;

		event->type = DNSSEC_EVENT_ZSK_ROLL_REMOVE_OLD_KEY;
		event->time = ctx->now + subzero(retired_need, retired_time);

		return DNSSEC_EOK;
	}

	dnssec_kasp_key_t *rolling = last_key(ctx, DNSSEC_KEY_STATE_PUBLISHED);
	if (rolling) {
		if (ctx->now < rolling->timing.publish) {
			return DNSSEC_EINVAL;
		}

		uint32_t rolling_time = ctx->now - rolling->timing.publish;
		uint32_t rolling_need = ctx->policy->propagation_delay +
					ctx->policy->dnskey_ttl;

		event->type = DNSSEC_EVENT_ZSK_ROLL_REPLACE_SIGNATURES;
		event->time = ctx->now + subzero(rolling_need, rolling_time);

		return DNSSEC_EOK;
	}

	dnssec_kasp_key_t *active = last_key(ctx, DNSSEC_KEY_STATE_ACTIVE);
	if (active) {
		if (ctx->now < active->timing.publish) {
			return DNSSEC_EINVAL;
		}

		uint32_t active_age = ctx->now - active->timing.publish;
		uint32_t active_max = ctx->policy->zsk_lifetime;

		event->type = DNSSEC_EVENT_ZSK_ROLL_PUBLISH_NEW_KEY;
		event->time = ctx->now + subzero(active_max, active_age);

		return DNSSEC_EOK;
	}

	return DNSSEC_EINVAL;
}

static int exec_new_key(dnssec_event_ctx_t *ctx)
{
	dnssec_kasp_key_t *new_key = NULL;
	int r = generate_key(ctx, false, &new_key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	//! \todo Cannot set "active" to zero, using upper bound instead.
	new_key->timing.publish = ctx->now;
	new_key->timing.active = UINT32_MAX;

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

static int exec_new_signatures(dnssec_event_ctx_t *ctx)
{
	dnssec_kasp_key_t *active  = last_key(ctx, DNSSEC_KEY_STATE_ACTIVE);
	dnssec_kasp_key_t *rolling = last_key(ctx, DNSSEC_KEY_STATE_PUBLISHED);
	if (!active || !rolling) {
		return DNSSEC_EINVAL;
	}

	active->timing.retire = ctx->now;
	rolling->timing.active = ctx->now;

	char *path;
	if (asprintf(&path, "%s/keyusage", ctx->kasp->functions->base_path(ctx->kasp->ctx)) == -1){
		return DNSSEC_ENOMEM;
	}
	dnssec_keyusage_t *keyusage = dnssec_keyusage_new();
	dnssec_keyusage_load(keyusage, path);
	dnssec_keyusage_add(keyusage, rolling->id, ctx->zone->name);
	dnssec_keyusage_save(keyusage, path);
	dnssec_keyusage_free(keyusage);
	free(path);

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

static int exec_remove_old_key(dnssec_event_ctx_t *ctx)
{
	dnssec_kasp_key_t *retired = last_key(ctx, DNSSEC_KEY_STATE_RETIRED);
	if (!retired) {
		return DNSSEC_EINVAL;
	}

	char *path;
	if (asprintf(&path, "%s/keyusage", ctx->kasp->functions->base_path(ctx->kasp->ctx)) == -1){
		return DNSSEC_ENOMEM;
	}

	dnssec_keyusage_t *keyusage = dnssec_keyusage_new();
	dnssec_keyusage_load(keyusage, path);
	dnssec_keyusage_remove(keyusage, retired->id, ctx->zone->name);
	dnssec_keyusage_save(keyusage, path);

	retired->timing.remove = ctx->now;
	dnssec_list_foreach(item, ctx->zone->keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(item);
		if (key->id == retired->id) {
			dnssec_list_remove(item);
		}
	}

	if (dnssec_keyusage_is_used(keyusage, retired->id)) {
		dnssec_keyusage_free(keyusage);
		free(path);
		return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
	}
	dnssec_keyusage_free(keyusage);
	free(path);

	dnssec_keystore_remove_key(ctx->keystore, retired->id);

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

static int exec(dnssec_event_ctx_t *ctx, const dnssec_event_t *event)
{
	assert(ctx);
	assert(event);

	switch (event->type) {
	case DNSSEC_EVENT_ZSK_ROLL_PUBLISH_NEW_KEY:
		return exec_new_key(ctx);
	case DNSSEC_EVENT_ZSK_ROLL_REPLACE_SIGNATURES:
		return exec_new_signatures(ctx);
	case DNSSEC_EVENT_ZSK_ROLL_REMOVE_OLD_KEY:
		return exec_remove_old_key(ctx);
	default:
		assert_unreachable();
		return DNSSEC_EINVAL;
	};
}

/*! Event API. */
const event_action_functions_t event_action_zsk_rollover = {
	.responds_to = responds_to,
	.plan        = plan,
	.exec        = exec
};
