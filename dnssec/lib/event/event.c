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
#include <stdbool.h>

#include "dnssec/error.h"
#include "dnssec/event.h"
#include "dnssec/kasp.h"
#include "event/keysearch.h"
#include "event/keystate.h"
#include "key/internal.h"
#include "shared.h"

static bool missing_ksk_or_zsk(dnssec_kasp_zone_t *zone)
{
	bool has_ksk, has_zsk;
	zone_check_ksk_and_zsk(zone, &has_ksk, &has_zsk);

	return !has_ksk || !has_zsk;
}

static bool active_zsk_key(const dnssec_kasp_key_t *key, void *data)
{
	dnssec_event_ctx_t *ctx = data;

	return dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
	       get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_ACTIVE;
}

static bool rolling_zsk_key(const dnssec_kasp_key_t *key, void *data)
{
	dnssec_event_ctx_t *ctx = data;

	return dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
	       get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED;
}

_public_
int dnssec_event_get_next(dnssec_event_ctx_t *ctx, dnssec_event_t *event)
{
	if (!ctx || !event) {
		return DNSSEC_EINVAL;
	}

	// TODO: additional checks on ctx content

	// initial keys

	if (missing_ksk_or_zsk(ctx->zone)) {
		event->time = ctx->now;
		event->type = DNSSEC_EVENT_GENERATE_INITIAL_KEY;
		return DNSSEC_EOK;
	}

	// ZSK rotation

#warning Concept code, needs cleanup.

	dnssec_kasp_key_t *active = last_matching_key(ctx->zone, active_zsk_key, ctx);
	if (!active) {
		return DNSSEC_EINVAL;
	}

	assert(ctx->now >= active->timing.publish);
	uint32_t key_age = ctx->now - active->timing.publish;
	if (key_age < ctx->policy->zsk_lifetime) {
		event->time = ctx->now + (ctx->policy->zsk_lifetime - key_age);
		event->type = DNSSEC_EVENT_ZSK_ROTATION_INIT;
		return DNSSEC_EOK;
	} else {
		dnssec_kasp_key_t *rolling = last_matching_key(ctx->zone, rolling_zsk_key, ctx);
		if (!rolling) {
			event->type = DNSSEC_EVENT_ZSK_ROTATION_INIT;
			event->time = ctx->now;
			return DNSSEC_EOK;
		}

		assert(ctx->now >= rolling->timing.publish);
		uint32_t pub_age = ctx->now - rolling->timing.publish;
		uint32_t need_age = ctx->policy->dnskey_ttl + ctx->policy->propagation_delay;
		printf("[debug] need_age %u pub_age %u\n", need_age, pub_age);
		if (pub_age < need_age) {
			event->type = DNSSEC_EVENT_ZSK_ROTATION_FINISH;
			event->time = ctx->now + (need_age - pub_age);
			return DNSSEC_EOK;
		} else {
			event->type = DNSSEC_EVENT_ZSK_ROTATION_FINISH;
			event->time = ctx->now;
			return DNSSEC_EOK;
		}
	}

	clear_struct(event);
	return DNSSEC_EOK;
}
