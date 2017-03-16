/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/random.h"
#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/common/log.h"
#include "knot/dnssec/kasp/keystate.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/policy.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/serial.h"

#define TIME_INFINITY ((time_t)0x00ffffffffffff00LLU)

static knot_kasp_key_t *last_key(kdnssec_ctx_t *ctx, key_state_t state)
{
	assert(ctx);
	assert(ctx->zone);

	knot_kasp_key_t *match = NULL;

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (match == NULL || key->timing.created == 0 ||
		    key->timing.created >= match->timing.created) {
			if (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK &&
			    get_key_state(key, ctx->now) == state) {
				match = key;
			}
		}
	}
	assert(match == NULL || dnssec_key_get_flags(match->key) == DNSKEY_FLAGS_ZSK);
	return match;
}

static bool key_present(kdnssec_ctx_t *ctx, uint16_t flag)
{
	assert(ctx);
	assert(ctx->zone);
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(key->key) == flag) {
			return true;
		}
	}
	return false;
}

static int generate_initial_key(kdnssec_ctx_t *ctx, bool ksk)
{
	knot_kasp_key_t *key = NULL;
	int r = kdnssec_generate_key(ctx, ksk, &key);
	if (r != KNOT_EOK) {
		return r;
	}

	key->timing.active  = ctx->now;
	key->timing.publish = ctx->now;

	return KNOT_EOK;
}

typedef enum {
	INVALID = 0,
	PUBLISH = 1,
	REPLACE,
	REMOVE,
} roll_action;

inline static time_t time_max(time_t a, time_t b)
{
	return ((a > b) ? a : b);
}

static roll_action next_action(kdnssec_ctx_t *ctx, time_t *next_action_time)
{
	assert(next_action_time);
	knot_kasp_key_t *kk = last_key(ctx, DNSSEC_KEY_STATE_RETIRED);
	if (kk != NULL) {
		if (ctx->now < kk->timing.retire) {
			return KNOT_EINVAL;
		}
		*next_action_time = time_max(ctx->now, kk->timing.retire +
					     ctx->policy->propagation_delay +
					     ctx->policy->zone_maximal_ttl);
		return REMOVE;
	}

	kk = last_key(ctx, DNSSEC_KEY_STATE_PUBLISHED);
	if (kk != NULL) {
		if (ctx->now < kk->timing.publish) {
			return KNOT_EINVAL;
		}
		*next_action_time = time_max(ctx->now, kk->timing.publish +
					     ctx->policy->propagation_delay +
		                             ctx->policy->dnskey_ttl);
		return REPLACE;
	}

	kk = last_key(ctx, DNSSEC_KEY_STATE_ACTIVE);
	if (kk != NULL) {
		if (ctx->now < kk->timing.active) {
			return KNOT_EINVAL;
		}
		*next_action_time = time_max(ctx->now, kk->timing.active +
					     ctx->policy->zsk_lifetime);
		return PUBLISH;
	}

	return INVALID;
}

static int exec_new_key(kdnssec_ctx_t *ctx)
{
	knot_kasp_key_t *new_key = NULL;
	int r = kdnssec_generate_key(ctx, false, &new_key);
	if (r != KNOT_EOK) {
		return r;
	}

	//! \todo Cannot set "active" to zero, using upper bound instead.
	new_key->timing.publish = ctx->now;
	new_key->timing.active = TIME_INFINITY;

	return KNOT_EOK;
}

static int exec_new_signatures(kdnssec_ctx_t *ctx)
{
	knot_kasp_key_t *active  = last_key(ctx, DNSSEC_KEY_STATE_ACTIVE);
	knot_kasp_key_t *rolling = last_key(ctx, DNSSEC_KEY_STATE_PUBLISHED);
	if (!active || !rolling) {
		return KNOT_EINVAL;
	}

	assert(dnssec_key_get_flags(active->key) == DNSKEY_FLAGS_ZSK);
	assert(dnssec_key_get_flags(rolling->key) == DNSKEY_FLAGS_ZSK);

	active->timing.retire = ctx->now;
	rolling->timing.active = ctx->now;

	return KNOT_EOK;
}

static int exec_remove_old_key(kdnssec_ctx_t *ctx)
{
	knot_kasp_key_t *retired = last_key(ctx, DNSSEC_KEY_STATE_RETIRED);
	if (!retired) {
		return KNOT_EINVAL;
	}

	retired->timing.remove = ctx->now;

	return kdnssec_delete_key(ctx, retired);
}

// TODO refactor next event calculation to be straightforward based on the previous event,
// and store the timing in timers-db
// problem: we need to rollover each key independently (?) but in timers we just store event time

int knot_dnssec_zsk_rollover(kdnssec_ctx_t *ctx, bool *keys_changed, time_t *next_rollover)
{
	if (ctx->policy->manual) {
		return KNOT_EOK;
	}
	int ret = KNOT_ESEMCHECK; // just an independent rcode not appearing normally

	// generate initial keys if missing
	if (!ctx->policy->singe_type_signing && !key_present(ctx, DNSKEY_FLAGS_KSK)) {
		ret = generate_initial_key(ctx, true);
	}
	if ((ret == KNOT_EOK || ret == KNOT_ESEMCHECK) && !key_present(ctx, DNSKEY_FLAGS_ZSK)) {
		ret = generate_initial_key(ctx, false);
	}
	if (ret == KNOT_EOK) {
		*keys_changed = true;
	}

	if (ret != KNOT_EOK && ret != KNOT_ESEMCHECK) {
		return ret;
	}

	roll_action next = next_action(ctx, next_rollover);

	if (!ctx->policy->singe_type_signing && *next_rollover <= ctx->now) {
		switch (next) {
		case PUBLISH:
			ret = exec_new_key(ctx);
			break;
		case REPLACE:
			ret = exec_new_signatures(ctx);
			break;
		case REMOVE:
			ret = exec_remove_old_key(ctx);
			break;
		default:
			ret = KNOT_EINVAL;
		}

		if (ret == KNOT_EOK) {
			*keys_changed = true;
			(void)next_action(ctx, next_rollover);
		} else {
			*next_rollover = time(NULL) + 10; // fail => try in 10seconds #TODO better?
		}
	}

	if (*keys_changed) {
		ret = kdnssec_ctx_commit(ctx);
	}
	return (ret == KNOT_ESEMCHECK ? KNOT_EOK : ret);
}
