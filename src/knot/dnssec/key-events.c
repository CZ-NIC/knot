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
#include <time.h>
#include <stdarg.h>

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
	key->timing.ready   = ctx->now;
	key->timing.publish = ctx->now;

	return KNOT_EOK;
}

typedef enum {
	INVALID = 0,
	PUBLISH = 1,
	SUBMIT,
	REPLACE,
	REMOVE,
} roll_action_type;

typedef struct {
	roll_action_type type;
	bool ksk;
	time_t time;
	knot_kasp_key_t *key;
} roll_action;

__attribute__((unused))
inline static time_t time_max(time_t a, time_t b)
{
	return ((a > b) ? a : b);
}

inline static time_t time_min(time_t a, time_t b)
{
	return ((a < b) ? a : b);
}

__attribute__((unused))
static time_t time_min_multi(time_t first, ...)
{
	va_list args;
	va_start(args, first);
	time_t res = TIME_INFINITY;
	for (time_t cur = first; cur != 0; cur = va_arg(args, time_t)) {
		res = time_min(res, cur);
	}
	va_end(args);
	return res;
}

static time_t zsk_publish_time(time_t active_time, const kdnssec_ctx_t *ctx)
{
	if (active_time <= 0 || active_time >= TIME_INFINITY) {
		return TIME_INFINITY;
	}
	return active_time + ctx->policy->zsk_lifetime; // TODO better minus something ?
}

static time_t zsk_active_time(time_t publish_time, const kdnssec_ctx_t *ctx)
{
	if (publish_time <= 0 || publish_time >= TIME_INFINITY) {
		return TIME_INFINITY;
	}
	return publish_time + ctx->policy->propagation_delay + ctx->policy->dnskey_ttl;
}

static time_t zsk_remove_time(time_t retire_time, const kdnssec_ctx_t *ctx)
{
	if (retire_time <= 0 || retire_time >= TIME_INFINITY) {
		return TIME_INFINITY;
	}
	return retire_time + ctx->policy->propagation_delay + ctx->policy->zone_maximal_ttl;
}

static time_t ksk_publish_time(time_t active_time, const kdnssec_ctx_t *ctx)
{
	if (active_time <= 0 || active_time >= TIME_INFINITY) {
		return TIME_INFINITY;
	}
	return active_time + ctx->policy->ksk_lifetime; // TODO better minus something ?
}

static time_t ksk_ready_time(time_t publish_time, const kdnssec_ctx_t *ctx)
{
	if (publish_time <= 0 || publish_time >= TIME_INFINITY) {
		return TIME_INFINITY;
	}
	return publish_time + ctx->policy->propagation_delay + ctx->policy->dnskey_ttl;
}

static time_t ksk_remove_time(time_t retire_time, const kdnssec_ctx_t *ctx)
{
	if (retire_time <= 0 || retire_time >= TIME_INFINITY) {
		return TIME_INFINITY;
	}
	return retire_time + ctx->policy->propagation_delay + ctx->policy->dnskey_ttl; // DS TTL == DNSKEY TTL (?) TODO
}

static roll_action next_action(kdnssec_ctx_t *ctx)
{
	roll_action res = { 0 };
	res.time = TIME_INFINITY;

	bool is_zsk_published = false;
	bool is_ksk_published = false;
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		key_state_t keystate = get_key_state(key, ctx->now);
		if (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_ZSK && (
		    keystate == DNSSEC_KEY_STATE_PUBLISHED)) {
			is_zsk_published = true;
		}
		if (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK && (
		    keystate == DNSSEC_KEY_STATE_PUBLISHED || keystate == DNSSEC_KEY_STATE_READY)) {
			is_ksk_published = true;
		}
	}

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		time_t keytime = TIME_INFINITY;
		roll_action_type restype = INVALID;
		bool isksk = (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK);
		if (isksk) {
			switch (get_key_state(key, ctx->now)) {
			case DNSSEC_KEY_STATE_PUBLISHED:
				keytime = ksk_ready_time(key->timing.publish, ctx);
				restype = SUBMIT;
				break;
			case DNSSEC_KEY_STATE_READY:
				break;
			case DNSSEC_KEY_STATE_ACTIVE:
				if (!is_ksk_published) {
					keytime = ksk_publish_time(key->timing.active, ctx);
					restype = PUBLISH;
				}
				break;
			case DNSSEC_KEY_STATE_RETIRED:
				keytime = ksk_remove_time(key->timing.retire, ctx);
				restype = REMOVE;
				break;

			default:
				assert(0);
			}
		} else {
			switch (get_key_state(key, ctx->now)) {
			case DNSSEC_KEY_STATE_PUBLISHED:
				keytime = zsk_active_time(key->timing.publish, ctx);
				restype = REPLACE;
				break;
			case DNSSEC_KEY_STATE_ACTIVE:
				if (!is_zsk_published) {
					keytime = zsk_publish_time(key->timing.active, ctx);
					restype = PUBLISH;
				}
				break;
			case DNSSEC_KEY_STATE_RETIRED:
				keytime = zsk_remove_time(key->timing.retire, ctx);
				restype = REMOVE;
				break;
			case DNSSEC_KEY_STATE_READY:
			default:
				assert(0);
			}
		}
		if (keytime < res.time) {
			res.key = key;
			res.ksk = isksk;
			res.time = keytime;
			res.type = restype;
		}
	}

	return res;
}

static int exec_new_key(kdnssec_ctx_t *ctx, bool ksk)
{
	knot_kasp_key_t *new_key = NULL;
	int r = kdnssec_generate_key(ctx, ksk, &new_key);
	if (r != KNOT_EOK) {
		return r;
	}

	//! \todo Cannot set "active" to zero, using upper bound instead.
	new_key->timing.publish = ctx->now;
	new_key->timing.ready = TIME_INFINITY;
	new_key->timing.active = TIME_INFINITY;

	return KNOT_EOK;
}

static int submit_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *newkey) {
	assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED);
	newkey->timing.ready = ctx->now;
	return KNOT_EOK;
}

static int exec_new_signatures(kdnssec_ctx_t *ctx, knot_kasp_key_t *newkey)
{
	uint16_t kskflag = dnssec_key_get_flags(newkey->key);

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(key->key) == kskflag &&
		    get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_ACTIVE) {
			key->timing.retire = ctx->now;
		}
	}

	if (kskflag == DNSKEY_FLAGS_KSK) {
		assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_READY);
	} else {
		assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED);
		newkey->timing.ready = ctx->now;
	}
	newkey->timing.active = ctx->now;

	return KNOT_EOK;
}

static int exec_remove_old_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *key)
{
	assert(get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_RETIRED);
	key->timing.remove = ctx->now;

	return kdnssec_delete_key(ctx, key);
}

int knot_dnssec_key_rollover(kdnssec_ctx_t *ctx, zone_t *zone, bool *keys_changed, time_t *next_rollover)
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

	roll_action next = next_action(ctx);

	*next_rollover = next.time;

	if (!ctx->policy->singe_type_signing && *next_rollover <= ctx->now) {
		switch (next.type) {
		case PUBLISH:
			ret = exec_new_key(ctx, next.ksk);
			break;
		case SUBMIT:
			ret = submit_key(ctx, next.key);
			if (zone == NULL) {
				return KNOT_EINVAL;
			}
			zone_events_schedule_now(zone, ZONE_EVENT_PARENT_DS_Q);
			// "now" it won't probably succeed, but it replans itself for proper interval

			log_zone_notice(zone->name, "DNSSEC, published CDS, CDNSKEY for submittion");
			break;
		case REPLACE:
			ret = exec_new_signatures(ctx, next.key);
			break;
		case REMOVE:
			ret = exec_remove_old_key(ctx, next.key);
			break;
		default:
			ret = KNOT_EINVAL;
		}

		if (ret == KNOT_EOK) {
			*keys_changed = true;
			next = next_action(ctx);
			*next_rollover = next.time;
		} else {
			*next_rollover = time(NULL) + 10; // fail => try in 10seconds #TODO better?
		}
	}

	if (*keys_changed) {
		ret = kdnssec_ctx_commit(ctx);
	}
	return (ret == KNOT_ESEMCHECK ? KNOT_EOK : ret);
}

int knot_dnssec_ksk_submittion_confirm(kdnssec_ctx_t *ctx, uint16_t for_key)
{
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK &&
		    dnssec_key_get_keytag(key->key) == for_key &&
		    get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_READY) {
			int ret = exec_new_signatures(ctx, key);
			if (ret == KNOT_EOK) {
				ret = kdnssec_ctx_commit(ctx);
			}
			return ret;
		}
	}
	return KNOT_ENOENT;
}

bool zone_has_key_submittion(const kdnssec_ctx_t *ctx)
{
	assert(ctx->zone);

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK &&
		    get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_READY) {
			return true;
		}
	}
	return false;
}
