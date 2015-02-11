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
#include "event/action.h"
#include "event/keystate.h"
#include "event/utils.h"
#include "key/internal.h"
#include "shared.h"

typedef bool (*key_match_cb)(const dnssec_kasp_key_t *key, void *data);

static bool newer_key(const dnssec_kasp_key_t *prev, const dnssec_kasp_key_t *cur)
{
	return cur->timing.created == 0 ||
	       cur->timing.created >= prev->timing.created;
}

static dnssec_kasp_key_t *last_key(dnssec_kasp_zone_t *zone,
				   key_match_cb match_cb, void *data)
{
	assert(zone);

	dnssec_kasp_key_t *match = NULL;

	dnssec_list_t *keys = dnssec_kasp_zone_get_keys(zone);
	dnssec_list_foreach(i, keys) {
		dnssec_kasp_key_t *key = dnssec_item_get(i);
		if ((match == NULL || newer_key(match, key)) && match_cb(key, data)) {
			match = key;
		}
	}

	return match;
}

static bool is_active_zsk(const dnssec_kasp_key_t *key, void *data)
{
	time_t now = (time_t)data;

	return dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
	       get_key_state(key, now) == DNSSEC_KEY_STATE_ACTIVE;
}

static bool is_rolling_zsk(const dnssec_kasp_key_t *key, void *data)
{
	time_t now = (time_t)data;

	return dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
	       get_key_state(key, now) == DNSSEC_KEY_STATE_PUBLISHED;
}

static bool responds_to(dnssec_event_type_t event)
{
	return event == DNSSEC_EVENT_ZSK_ROTATION_INIT ||
	       event == DNSSEC_EVENT_ZSK_ROTATION_FINISH;
}

static int plan(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	assert(ctx);
	assert(event);

	dnssec_kasp_key_t *active = last_key(ctx->zone, is_active_zsk, (void *)ctx->now);
	if (!active) {
		return DNSSEC_EINVAL;
	}

	if (ctx->now < active->timing.publish) {
		return DNSSEC_EINVAL;
	}

	uint32_t active_age = ctx->now - active->timing.publish;
	if (active_age < ctx->policy->zsk_lifetime) {
		event->type = DNSSEC_EVENT_ZSK_ROTATION_INIT;
		event->time = ctx->now + (ctx->policy->zsk_lifetime - active_age);
		return DNSSEC_EOK;
	}

	dnssec_kasp_key_t *rolling = last_key(ctx->zone, is_rolling_zsk, (void *)ctx->now);
	if (!rolling) {
		event->type = DNSSEC_EVENT_ZSK_ROTATION_INIT;
		event->time = ctx->now;
		return DNSSEC_EOK;
	}

	if (ctx->now < rolling->timing.publish) {
		return DNSSEC_EINVAL;
	}

	uint32_t rolling_age = ctx->now - rolling->timing.publish;
	uint32_t rolling_known = ctx->policy->dnskey_ttl + ctx->policy->propagation_delay;
	if (rolling_age < rolling_known) {
		event->type = DNSSEC_EVENT_ZSK_ROTATION_FINISH;
		event->time = ctx->now + (rolling_known - rolling_age);
		return DNSSEC_EOK;
	} else {
		event->type = DNSSEC_EVENT_ZSK_ROTATION_FINISH;
		event->time = ctx->now;
		return DNSSEC_EOK;
	}
}

static int exec_init(dnssec_event_ctx_t *ctx)
{
	dnssec_kasp_key_t *new_key = NULL;
	int r = generate_key(ctx, false, &new_key);
	if (r != DNSSEC_EOK) {
		return r;
	}

	#warning TODO: Cannot set "active" to zero, using upper bound instead.
	new_key->timing.publish = ctx->now;
	new_key->timing.active = UINT32_MAX;

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

static int exec_finish(dnssec_event_ctx_t *ctx)
{
	dnssec_kasp_key_t *active = last_key(ctx->zone, is_active_zsk, (void *)ctx->now);
	dnssec_kasp_key_t *rolling = last_key(ctx->zone, is_rolling_zsk, (void *)ctx->now);
	if (!active || !rolling) {
		return DNSSEC_EINVAL;
	}

	rolling->timing.active = ctx->now;

	active->timing.retire = ctx->now;
	active->timing.remove = ctx->now;

	return dnssec_kasp_zone_save(ctx->kasp, ctx->zone);
}

static int exec(dnssec_event_ctx_t *ctx, const dnssec_event_t *event)
{
	assert(ctx);
	assert(event);

	switch (event->type) {
	case DNSSEC_EVENT_ZSK_ROTATION_INIT:   return exec_init(ctx);
	case DNSSEC_EVENT_ZSK_ROTATION_FINISH: return exec_finish(ctx);
	default:
		assert_unreachable();
		return DNSSEC_EINVAL;
	};
}

const event_action_functions_t event_action_zsk_rollover = {
	.responds_to = responds_to,
	.plan        = plan,
	.exec        = exec
};
