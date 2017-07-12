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

#include "knot/common/log.h"
#include "knot/dnssec/kasp/keystate.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/policy.h"
#include "knot/dnssec/zone-keys.h"

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

static bool key_id_present(kdnssec_ctx_t *ctx, const char *keyid, uint16_t flag)
{
	assert(ctx);
	assert(ctx->zone);
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (strcmp(keyid, key->id) == 0 &&
		    dnssec_key_get_flags(key->key) == flag) {
			return true;
		}
	}
	return false;
}

static knot_kasp_key_t *key_get_by_id(kdnssec_ctx_t *ctx, const char *keyid)
{
	assert(ctx);
	assert(ctx->zone);
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (strcmp(keyid, key->id) == 0) {
			return key;
		}
	}
	return NULL;
}

static int generate_key(kdnssec_ctx_t *ctx, bool ksk, knot_time_t when_active)
{
	knot_kasp_key_t *key = NULL;
	int ret = kdnssec_generate_key(ctx, ksk, &key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	key->timing.remove = 0;
	key->timing.retire = 0;
	key->timing.active  = (ksk ? 0 : when_active);
	key->timing.ready   = when_active;
	key->timing.publish = ctx->now;

	return KNOT_EOK;
}

static int share_or_generate_key(kdnssec_ctx_t *ctx, bool ksk, knot_time_t when_active)
{
	knot_dname_t *borrow_zone = NULL;
	char *borrow_key = NULL;

	if (!ksk) {
		return KNOT_EINVAL;
	} // for now not designed for rotating shared ZSK

	int ret = kasp_db_get_policy_last(*ctx->kasp_db, ctx->policy->string,
	                                  &borrow_zone, &borrow_key);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return ret;
	}

	// if we already have the policy-last key, we have to generate new one
	if (ret == KNOT_ENOENT || key_id_present(ctx, borrow_key, DNSKEY_FLAGS_KSK)) {
		knot_kasp_key_t *key = NULL;
		ret = kdnssec_generate_key(ctx, ksk, &key);
		if (ret != KNOT_EOK) {
			return ret;
		}
		key->timing.remove = 0;
		key->timing.retire = 0;
		key->timing.active  = (ksk ? 0 : when_active);
		key->timing.ready   = when_active;
		key->timing.publish = ctx->now;

		ret = kdnssec_ctx_commit(ctx);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = kasp_db_set_policy_last(*ctx->kasp_db, ctx->policy->string,
		                              borrow_key, ctx->zone->dname, key->id);
		free(borrow_zone);
		free(borrow_key);
		borrow_zone = NULL;
		borrow_key = NULL;
		if (ret != KNOT_ESEMCHECK) {
			// all ok, we generated new kay and updated policy-last
			return ret;
		} else {
			// another zone updated policy-last key in the meantime
			ret = kdnssec_delete_key(ctx, key);
			if (ret == KNOT_EOK) {
				ret = kdnssec_ctx_commit(ctx);
			}
			if (ret != KNOT_EOK) {
				return ret;
			}

			ret = kasp_db_get_policy_last(*ctx->kasp_db, ctx->policy->string,
			                              &borrow_zone, &borrow_key);
		}
	}

	if (ret == KNOT_EOK) {
		ret = kdnssec_share_key(ctx, borrow_zone, borrow_key);
		if (ret == KNOT_EOK) {
			knot_kasp_key_t *newkey = key_get_by_id(ctx, borrow_key);
			assert(newkey != NULL);
			newkey->timing.publish = ctx->now;
			newkey->timing.ready = when_active;
			newkey->timing.active = (ksk ? 0 : when_active);
		}
	}
	free(borrow_zone);
	free(borrow_key);
	return ret;
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
	knot_time_t time;
	knot_kasp_key_t *key;
} roll_action;

static knot_time_t zsk_publish_time(knot_time_t active_time, const kdnssec_ctx_t *ctx)
{
	if (active_time <= 0) {
		return 0;
	}
	return knot_time_add(active_time, ctx->policy->zsk_lifetime);
}

static knot_time_t zsk_active_time(knot_time_t publish_time, const kdnssec_ctx_t *ctx)
{
	if (publish_time <= 0) {
		return 0;
	}
	return knot_time_add(publish_time, ctx->policy->propagation_delay + ctx->policy->dnskey_ttl);
}

static knot_time_t zsk_remove_time(knot_time_t retire_time, const kdnssec_ctx_t *ctx)
{
	if (retire_time <= 0) {
		return 0;
	}
	return knot_time_add(retire_time, ctx->policy->propagation_delay + ctx->policy->zone_maximal_ttl);
}

static knot_time_t ksk_publish_time(knot_time_t created_time, const kdnssec_ctx_t *ctx)
{
	if (created_time <= 0 || ctx->policy->ksk_lifetime == 0) {
		return 0;
	}
	return knot_time_add(created_time, ctx->policy->ksk_lifetime);
}

static knot_time_t ksk_ready_time(knot_time_t publish_time, const kdnssec_ctx_t *ctx)
{
	if (publish_time <= 0) {
		return 0;
	}
	return knot_time_add(publish_time, ctx->policy->propagation_delay + ctx->policy->dnskey_ttl);
}

static knot_time_t ksk_sbm_max_time(knot_time_t ready_time, const kdnssec_ctx_t *ctx)
{
	if (ready_time <= 0 || ctx->policy->ksk_sbm_timeout == 0) {
		return 0;
	}
	return knot_time_add(ready_time, ctx->policy->ksk_sbm_timeout);
}

static knot_time_t ksk_remove_time(knot_time_t retire_time, const kdnssec_ctx_t *ctx)
{
	if (retire_time <= 0) {
		return 0;
	}
	return knot_time_add(retire_time, ctx->policy->propagation_delay + ctx->policy->dnskey_ttl);
}

static roll_action next_action(kdnssec_ctx_t *ctx)
{
	roll_action res = { 0 };
	res.time = 0;

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
		knot_time_t keytime = 0;
		roll_action_type restype = INVALID;
		bool isksk = (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK);
		if (isksk) {
			switch (get_key_state(key, ctx->now)) {
			case DNSSEC_KEY_STATE_PUBLISHED:
				keytime = ksk_ready_time(key->timing.publish, ctx);
				restype = SUBMIT;
				break;
			case DNSSEC_KEY_STATE_READY:
				keytime = ksk_sbm_max_time(key->timing.ready, ctx);
				restype = REPLACE;
				break;
			case DNSSEC_KEY_STATE_ACTIVE:
				if (!is_ksk_published) {
					keytime = ksk_publish_time(key->timing.created, ctx);
					restype = PUBLISH;
				}
				break;
			case DNSSEC_KEY_STATE_RETIRED:
			case DNSSEC_KEY_STATE_REMOVED:
				// ad REMOVED state: normally this wouldn't happen (key in removed state is instantly deleted)
				// but if imported keys, they can be in this state
				keytime = ksk_remove_time(key->timing.retire, ctx);
				restype = REMOVE;
				break;
			default:
				continue;
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
			case DNSSEC_KEY_STATE_REMOVED:
				// ad REMOVED state: normally this wouldn't happen (key in removed state is instantly deleted)
				// but if imported keys, they can be in this state
				keytime = zsk_remove_time(key->timing.retire, ctx);
				restype = REMOVE;
				break;
			case DNSSEC_KEY_STATE_READY:
			default:
				continue;
			}
		}
		if (knot_time_cmp(keytime, res.time) < 0) {
			res.key = key;
			res.ksk = isksk;
			res.time = keytime;
			res.type = restype;
		}
	}

	return res;
}

static int submit_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *newkey) {
	assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED);
	newkey->timing.ready = ctx->now;
	return KNOT_EOK;
}

static int exec_new_signatures(kdnssec_ctx_t *ctx, knot_kasp_key_t *newkey)
{
	uint16_t kskflag = dnssec_key_get_flags(newkey->key);

	// A delay to avoid left-behind of behind-a-loadbalancer parent NSs
	// for now we use (incorrectly) ksk_sbm_check_interval, to avoid too many conf options
	knot_timediff_t delay = 0;
	if (kskflag == DNSKEY_FLAGS_KSK && ctx->policy->ksk_sbm_check_interval != 0) {
		delay = ctx->policy->ksk_sbm_check_interval;
	}

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(key->key) == kskflag &&
		    get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_ACTIVE) {
			key->timing.retire = knot_time_min(knot_time_add(ctx->now, delay), key->timing.retire);
		}
	}

	if (kskflag == DNSKEY_FLAGS_KSK) {
		assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_READY);
	} else {
		assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED);
		assert(delay == 0);
		newkey->timing.ready = knot_time_min(knot_time_add(ctx->now, delay), newkey->timing.ready);
	}
	newkey->timing.active = knot_time_min(knot_time_add(ctx->now, delay), newkey->timing.active);

	return KNOT_EOK;
}

static int exec_remove_old_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *key)
{
	assert(get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_RETIRED ||
	       get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_REMOVED);
	key->timing.remove = ctx->now;

	return kdnssec_delete_key(ctx, key);
}

int knot_dnssec_key_rollover(kdnssec_ctx_t *ctx, zone_sign_reschedule_t *reschedule)
{
	if (ctx == NULL || reschedule == NULL) {
		return KNOT_EINVAL;
	}
	if (ctx->policy->manual) {
		return KNOT_EOK;
	}
	int ret = KNOT_ESEMCHECK; // just an independent rcode not appearing normally

	// generate initial keys if missing
	if (!ctx->policy->singe_type_signing && !key_present(ctx, DNSKEY_FLAGS_KSK)) {
		if (ctx->policy->ksk_shared) {
			ret = share_or_generate_key(ctx, true, ctx->now);
		} else {
			ret = generate_key(ctx, true, ctx->now);
		}
		reschedule->plan_ds_query = true;
	}
	if ((ret == KNOT_EOK || ret == KNOT_ESEMCHECK) && !key_present(ctx, DNSKEY_FLAGS_ZSK)) {
		ret = generate_key(ctx, false, ctx->now);
	}
	if (ret == KNOT_EOK) {
		reschedule->keys_changed = true;
	}

	if (ret != KNOT_EOK && ret != KNOT_ESEMCHECK) {
		return ret;
	}

	roll_action next = next_action(ctx);

	reschedule->next_rollover = next.time;

	if (!ctx->policy->singe_type_signing && knot_time_cmp(reschedule->next_rollover, ctx->now) <= 0) {
		switch (next.type) {
		case PUBLISH:
			if (next.ksk && ctx->policy->ksk_shared) {
				ret = share_or_generate_key(ctx, next.ksk, 0);
			} else {
				ret = generate_key(ctx, next.ksk, 0);
			}
			if (ret == KNOT_EOK) {
				log_zone_info(ctx->zone->dname, "DNSSEC, %cSK rollover started", (next.ksk ? 'K' : 'Z'));
			}
			break;
		case SUBMIT:
			ret = submit_key(ctx, next.key);
			reschedule->plan_ds_query = true;
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
			reschedule->keys_changed = true;
			next = next_action(ctx);
			reschedule->next_rollover = next.time;
		} else {
			reschedule->next_rollover = knot_time_add(knot_time(), 10); // fail => try in 10seconds #TODO better?
		}
	}

	if (reschedule->keys_changed) {
		ret = kdnssec_ctx_commit(ctx);
	}
	return (ret == KNOT_ESEMCHECK ? KNOT_EOK : ret);
}

int knot_dnssec_ksk_sbm_confirm(kdnssec_ctx_t *ctx)
{
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (dnssec_key_get_flags(key->key) == DNSKEY_FLAGS_KSK &&
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

bool zone_has_key_sbm(const kdnssec_ctx_t *ctx)
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
