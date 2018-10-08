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
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>

#include "contrib/macros.h"
#include "knot/common/log.h"
#include "knot/dnssec/kasp/keystate.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/policy.h"
#include "knot/dnssec/zone-keys.h"

static bool key_present(const kdnssec_ctx_t *ctx, bool ksk, bool zsk)
{
	assert(ctx);
	assert(ctx->zone);
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		const knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (key->is_ksk == ksk && key->is_zsk == zsk) {
			return true;
		}
	}
	return false;
}

static bool key_id_present(const kdnssec_ctx_t *ctx, const char *keyid, bool want_ksk)
{
	assert(ctx);
	assert(ctx->zone);
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		const knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (strcmp(keyid, key->id) == 0 &&
		    key->is_ksk == want_ksk) {
			return true;
		}
	}
	return false;
}

static unsigned algorithm_present(const kdnssec_ctx_t *ctx, uint8_t alg)
{
	assert(ctx);
	assert(ctx->zone);
	unsigned ret = 0;
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		const knot_kasp_key_t *key = &ctx->zone->keys[i];
		knot_time_t activated = knot_time_min(key->timing.pre_active, key->timing.ready);
		if (knot_time_cmp(knot_time_min(activated, key->timing.active), ctx->now) <= 0 &&
		    dnssec_key_get_algorithm(key->key) == alg) {
			ret++;
		}
	}
	return ret;
}

static bool signing_scheme_present(const kdnssec_ctx_t *ctx)
{
	if (ctx->policy->singe_type_signing) {
		return (!key_present(ctx, true, false) || !key_present(ctx, false, true) || key_present(ctx, true, true));
	} else {
		return (key_present(ctx, true, false) && key_present(ctx, false, true));
	}
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

static int generate_key(kdnssec_ctx_t *ctx, kdnssec_generate_flags_t flags,
			knot_time_t when_active, bool pre_active)
{
	assert(!pre_active || when_active == 0);

	knot_kasp_key_t *key = NULL;
	int ret = kdnssec_generate_key(ctx, flags, &key);
	if (ret != KNOT_EOK) {
		return ret;
	}

	key->timing.remove = 0;
	key->timing.retire = 0;
	key->timing.active = ((flags & DNSKEY_GENERATE_KSK) ? 0 : when_active);
	key->timing.ready  = ((flags & DNSKEY_GENERATE_KSK) ? when_active : 0);
	key->timing.publish    = (pre_active ? 0 : ctx->now);
	key->timing.pre_active = (pre_active ? ctx->now : 0);

	return KNOT_EOK;
}

static int share_or_generate_key(kdnssec_ctx_t *ctx, kdnssec_generate_flags_t flags,
				 knot_time_t when_active, bool pre_active)
{
	assert(!pre_active || when_active == 0);

	knot_dname_t *borrow_zone = NULL;
	char *borrow_key = NULL;

	if (!(flags & DNSKEY_GENERATE_KSK)) {
		return KNOT_EINVAL;
	} // for now not designed for rotating shared ZSK

	int ret = kasp_db_get_policy_last(*ctx->kasp_db, ctx->policy->string,
	                                  &borrow_zone, &borrow_key);
	if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
		return ret;
	}

	// if we already have the policy-last key, we have to generate new one
	if (ret == KNOT_ENOENT || key_id_present(ctx, borrow_key, true)) {
		knot_kasp_key_t *key = NULL;
		ret = kdnssec_generate_key(ctx, flags, &key);
		if (ret != KNOT_EOK) {
			return ret;
		}
		key->timing.remove = 0;
		key->timing.retire = 0;
		key->timing.active = ((flags & DNSKEY_GENERATE_KSK) ? 0 : when_active);
		key->timing.ready  = ((flags & DNSKEY_GENERATE_KSK) ? when_active : 0);
		key->timing.publish    = (pre_active ? 0 : ctx->now);
		key->timing.pre_active = (pre_active ? ctx->now : 0);

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
			newkey->timing.remove = 0;
			newkey->timing.retire = 0;
			newkey->timing.active = ((flags & DNSKEY_GENERATE_KSK) ? 0 : when_active);
			newkey->timing.ready  = ((flags & DNSKEY_GENERATE_KSK) ? when_active : 0);
			newkey->timing.publish    = (pre_active ? 0 : ctx->now);
			newkey->timing.pre_active = (pre_active ? ctx->now : 0);
			newkey->is_ksk = (flags & DNSKEY_GENERATE_KSK);
			newkey->is_zsk = (flags & DNSKEY_GENERATE_ZSK);
		}
	}
	free(borrow_zone);
	free(borrow_key);
	return ret;
}

#define GEN_KSK_FLAGS (DNSKEY_GENERATE_KSK | (ctx->policy->singe_type_signing ? DNSKEY_GENERATE_ZSK : 0))

static int generate_ksk(kdnssec_ctx_t *ctx, knot_time_t when_active, bool pre_active)
{
	if (ctx->policy->ksk_shared) {
		return share_or_generate_key(ctx, GEN_KSK_FLAGS, when_active, pre_active);
	} else {
		return generate_key(ctx, GEN_KSK_FLAGS, when_active, pre_active);
	}
}

static bool running_rollover(const kdnssec_ctx_t *ctx)
{
	bool res = false;
	bool ready_ksk = false, active_ksk = false;

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		switch (get_key_state(key, ctx->now)) {
		case DNSSEC_KEY_STATE_PRE_ACTIVE:
			res = true;
			break;
		case DNSSEC_KEY_STATE_PUBLISHED:
			res = (res || !key->is_pub_only);
			break;
		case DNSSEC_KEY_STATE_READY:
			ready_ksk = (ready_ksk || key->is_ksk);
			break;
		case DNSSEC_KEY_STATE_ACTIVE:
			active_ksk = (active_ksk || key->is_ksk);
			break;
		case DNSSEC_KEY_STATE_RETIRE_ACTIVE:
		case DNSSEC_KEY_STATE_POST_ACTIVE:
			res = true;
			break;
		case DNSSEC_KEY_STATE_RETIRED:
		case DNSSEC_KEY_STATE_REMOVED:
		default:
			break;
		}
	}
	if (ready_ksk && active_ksk) {
		res = true;
	}
	return res;
}

typedef enum {
	INVALID = 0,
	GENERATE = 1,
	PUBLISH,
	SUBMIT,
	REPLACE,
	RETIRE,
	REMOVE,
} roll_action_type_t;

typedef struct {
	roll_action_type_t type;
	bool ksk;
	knot_time_t time;
	knot_kasp_key_t *key;
} roll_action_t;

static const char *roll_action_name(roll_action_type_t type)
{
	switch (type) {
	case GENERATE: return "generate";
	case PUBLISH:  return "publish";
	case SUBMIT:   return "submit";
	case REPLACE:  return "replace";
	case RETIRE:   return "retire";
	case REMOVE:   return "remove";
	case INVALID:
		// FALLTHROUGH
	default:       return "invalid";
	}
}

static knot_time_t zsk_rollover_time(knot_time_t active_time, const kdnssec_ctx_t *ctx)
{
	if (active_time <= 0 || ctx->policy->zsk_lifetime == 0) {
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

static knot_time_t ksk_rollover_time(knot_time_t created_time, const kdnssec_ctx_t *ctx)
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

static knot_time_t ksk_retire_time(knot_time_t retire_active_time, const kdnssec_ctx_t *ctx)
{
	if (retire_active_time <= 0) {
		return 0;
	}
	return knot_time_add(retire_active_time, ctx->policy->propagation_delay + ctx->policy->dnskey_ttl);
}

static knot_time_t ksk_remove_time(knot_time_t retire_time, const kdnssec_ctx_t *ctx)
{
	if (retire_time <= 0) {
		return 0;
	}
	knot_timediff_t use_ttl = ctx->policy->dnskey_ttl;
	if (ctx->policy->singe_type_signing && ctx->policy->zone_maximal_ttl > use_ttl) {
		use_ttl = ctx->policy->zone_maximal_ttl;
	}
	return knot_time_add(retire_time, ctx->policy->propagation_delay + use_ttl);
}

// algorithm rollover related timers must be the same for KSK and ZSK

static knot_time_t alg_publish_time(knot_time_t pre_active_time, const kdnssec_ctx_t *ctx)
{
	if (pre_active_time <= 0) {
		return 0;
	}
	return knot_time_add(pre_active_time, ctx->policy->propagation_delay + ctx->policy->zone_maximal_ttl);
}

static knot_time_t alg_remove_time(knot_time_t post_active_time, const kdnssec_ctx_t *ctx)
{
	return MAX(ksk_remove_time(post_active_time, ctx), zsk_remove_time(post_active_time, ctx));
}

static roll_action_t next_action(kdnssec_ctx_t *ctx, zone_sign_roll_flags_t flags)
{
	roll_action_t res = { 0 };
	res.time = 0;

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		knot_time_t keytime = 0;
		roll_action_type_t restype = INVALID;
		if (key->is_pub_only ||
		    (key->is_ksk && !(flags & KEY_ROLL_ALLOW_KSK_ROLL)) ||
		    (key->is_zsk && !(flags & KEY_ROLL_ALLOW_ZSK_ROLL))) {
			continue;
		}
		if (key->is_ksk) {
			switch (get_key_state(key, ctx->now)) {
			case DNSSEC_KEY_STATE_PRE_ACTIVE:
				keytime = alg_publish_time(key->timing.pre_active, ctx);
				restype = PUBLISH;
				break;
			case DNSSEC_KEY_STATE_PUBLISHED:
				keytime = ksk_ready_time(key->timing.publish, ctx);
				restype = SUBMIT;
				break;
			case DNSSEC_KEY_STATE_READY:
				keytime = ksk_sbm_max_time(key->timing.ready, ctx);
				restype = REPLACE;
				break;
			case DNSSEC_KEY_STATE_ACTIVE:
				if (!running_rollover(ctx) &&
				    dnssec_key_get_algorithm(key->key) == ctx->policy->algorithm) {
					keytime = ksk_rollover_time(key->timing.created, ctx);
					restype = GENERATE;
				}
				break;
			case DNSSEC_KEY_STATE_RETIRE_ACTIVE:
				keytime = ksk_retire_time(key->timing.retire_active, ctx);
				restype = RETIRE;
				break;
			case DNSSEC_KEY_STATE_POST_ACTIVE:
				keytime = alg_remove_time(key->timing.post_active, ctx);
				restype = REMOVE;
				break;
			case DNSSEC_KEY_STATE_RETIRED:
			case DNSSEC_KEY_STATE_REMOVED:
				// ad REMOVED state: normally this wouldn't happen
				// (key in removed state is instantly deleted)
				// but if imported keys, they can be in this state
				keytime = knot_time_min(key->timing.retire, key->timing.remove);
				keytime = ksk_remove_time(keytime, ctx);
				restype = REMOVE;
				break;
			default:
				continue;
			}
		} else {
			switch (get_key_state(key, ctx->now)) {
			case DNSSEC_KEY_STATE_PRE_ACTIVE:
				keytime = alg_publish_time(key->timing.pre_active, ctx);
				restype = PUBLISH;
				break;
			case DNSSEC_KEY_STATE_PUBLISHED:
				keytime = zsk_active_time(key->timing.publish, ctx);
				restype = REPLACE;
				break;
			case DNSSEC_KEY_STATE_ACTIVE:
				if (!running_rollover(ctx) &&
				    dnssec_key_get_algorithm(key->key) == ctx->policy->algorithm) {
					keytime = zsk_rollover_time(key->timing.active, ctx);
					restype = GENERATE;
				}
				break;
			case DNSSEC_KEY_STATE_RETIRE_ACTIVE:
				// simply waiting for submitted KSK to retire me.
				break;
			case DNSSEC_KEY_STATE_POST_ACTIVE:
				keytime = alg_remove_time(key->timing.post_active, ctx);
				restype = REMOVE;
				break;
			case DNSSEC_KEY_STATE_REMOVED:
				// ad REMOVED state: normally this wouldn't happen
				// (key in removed state is instantly deleted)
				// but if imported keys, they can be in this state
				if (ctx->keep_deleted_keys) {
					break;
				} // else FALLBACK
			case DNSSEC_KEY_STATE_RETIRED:
				keytime = knot_time_min(key->timing.retire, key->timing.remove);
				keytime = ksk_remove_time(keytime, ctx);;
				restype = REMOVE;
				break;
			case DNSSEC_KEY_STATE_READY:
			default:
				continue;
			}
		}
		if (knot_time_cmp(keytime, res.time) < 0) {
			res.key = key;
			res.ksk = key->is_ksk;
			res.time = keytime;
			res.type = restype;
		}
	}

	return res;
}

static int submit_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *newkey)
{
	assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED);
	assert(newkey->is_ksk);

	// pushing from READY into ACTIVE decreases the other key's cds_priority
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (key->is_ksk && get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_READY) {
			key->timing.active = ctx->now;
		}
	}

	newkey->timing.ready = ctx->now;
	return KNOT_EOK;
}

static int exec_new_signatures(kdnssec_ctx_t *ctx, knot_kasp_key_t *newkey)
{
	if (newkey->is_ksk) {
		log_zone_notice(ctx->zone->dname, "DNSSEC, KSK submission, confirmed");
	}

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		key_state_t keystate = get_key_state(key, ctx->now);
		uint8_t keyalg = dnssec_key_get_algorithm(key->key);
		if (((newkey->is_ksk && key->is_ksk) || (newkey->is_zsk && key->is_zsk && !key->is_ksk))
		    && keystate == DNSSEC_KEY_STATE_ACTIVE) {
			if (key->is_ksk || keyalg != dnssec_key_get_algorithm(newkey->key)) {
				key->timing.retire_active = ctx->now;
			} else {
				key->timing.retire = ctx->now;
			}
		}
	}

	if (newkey->is_ksk) {
		assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_READY);
	} else {
		assert(get_key_state(newkey, ctx->now) == DNSSEC_KEY_STATE_PUBLISHED);
	}
	newkey->timing.active = knot_time_min(ctx->now, newkey->timing.active);

	return KNOT_EOK;
}

static int exec_publish(kdnssec_ctx_t *ctx, knot_kasp_key_t *key)
{
	assert(get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_PRE_ACTIVE);
	key->timing.publish = ctx->now;

	return KNOT_EOK;
}

static int exec_ksk_retire(kdnssec_ctx_t *ctx, knot_kasp_key_t *key)
{
	bool alg_rollover = false;
	knot_kasp_key_t *alg_rollover_friend = NULL;

	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *k = &ctx->zone->keys[i];
		int magic = (k->is_ksk && k->is_zsk ? 2 : 3); // :(
		if (k->is_zsk && get_key_state(k, ctx->now) == DNSSEC_KEY_STATE_RETIRE_ACTIVE &&
		    algorithm_present(ctx, dnssec_key_get_algorithm(k->key)) < magic) {
			alg_rollover = true;
			alg_rollover_friend = k;
		}
	}

	assert(get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_RETIRE_ACTIVE);

	if (alg_rollover) {
		key->timing.post_active = ctx->now;
		alg_rollover_friend->timing.post_active = ctx->now;
	} else {
		key->timing.retire = ctx->now;
	}

	return KNOT_EOK;
}

static int exec_remove_old_key(kdnssec_ctx_t *ctx, knot_kasp_key_t *key)
{
	assert(get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_RETIRED ||
	       get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_POST_ACTIVE ||
	       get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_REMOVED);
	key->timing.remove = ctx->now;

	if (ctx->keep_deleted_keys) {
		return KNOT_EOK;
	} else {
		return kdnssec_delete_key(ctx, key);
	}
}

int knot_dnssec_key_rollover(kdnssec_ctx_t *ctx, zone_sign_roll_flags_t flags,
                             zone_sign_reschedule_t *reschedule)
{
	if (ctx == NULL || reschedule == NULL) {
		return KNOT_EINVAL;
	}
	if (ctx->policy->manual) {
		return KNOT_EOK;
	}
	int ret = KNOT_EOK;
	bool allowed_general_roll = ((flags & KEY_ROLL_ALLOW_KSK_ROLL) && (flags & KEY_ROLL_ALLOW_ZSK_ROLL));
	// generate initial keys if missing
	if (!key_present(ctx, true, false) && !key_present(ctx, true, true)) {
		if ((flags & KEY_ROLL_ALLOW_KSK_ROLL)) {
			if (ctx->policy->ksk_shared) {
				ret = share_or_generate_key(ctx, GEN_KSK_FLAGS, ctx->now, false);
			} else {
				ret = generate_key(ctx, GEN_KSK_FLAGS, ctx->now, false);
			}
			reschedule->plan_ds_query = true;
		}
		if (ret == KNOT_EOK && (flags & KEY_ROLL_ALLOW_ZSK_ROLL)) {
			reschedule->keys_changed = true;
			if (!ctx->policy->singe_type_signing &&
			    !key_present(ctx, false, true)) {
				ret = generate_key(ctx, DNSKEY_GENERATE_ZSK, ctx->now, false);
			}
		}
	}
	// forced KSK rollover
	if ((flags & KEY_ROLL_FORCE_KSK_ROLL) && ret == KNOT_EOK && (flags & KEY_ROLL_ALLOW_KSK_ROLL)) {
		flags &= ~KEY_ROLL_FORCE_KSK_ROLL;
		if (running_rollover(ctx)) {
			log_zone_warning(ctx->zone->dname, "DNSSEC, ignoring forced KSK rollover "
			                                   "due to running rollover");
		} else {
			ret = generate_ksk(ctx, 0, false);
			if (ret == KNOT_EOK) {
				reschedule->keys_changed = true;
				log_zone_info(ctx->zone->dname, "DNSSEC, KSK rollover started");
			}
		}
	}
	// forced ZSK rollover
	if ((flags & KEY_ROLL_FORCE_ZSK_ROLL) && ret == KNOT_EOK && (flags & KEY_ROLL_ALLOW_ZSK_ROLL)) {
		flags &= ~KEY_ROLL_FORCE_ZSK_ROLL;
		if (running_rollover(ctx)) {
			log_zone_warning(ctx->zone->dname, "DNSSEC, ignoring forced ZSK rollover "
			                                   "due to running rollover");
		} else {
			ret = generate_key(ctx, DNSKEY_GENERATE_ZSK, 0, false);
			if (ret == KNOT_EOK) {
				reschedule->keys_changed = true;
				log_zone_info(ctx->zone->dname, "DNSSEC, ZSK rollover started");
			}
		}
	}
	// algorithm rollover
	if (algorithm_present(ctx, ctx->policy->algorithm) == 0 &&
	    !running_rollover(ctx) && allowed_general_roll && ret == KNOT_EOK) {
		ret = generate_ksk(ctx, 0, true);
		if (!ctx->policy->singe_type_signing && ret == KNOT_EOK) {
			ret = generate_key(ctx, DNSKEY_GENERATE_ZSK, 0, true);
		}
		log_zone_info(ctx->zone->dname, "DNSSEC, algorithm rollover started");
		if (ret == KNOT_EOK) {
			reschedule->keys_changed = true;
		}
	}
	// scheme rollover
	if (!signing_scheme_present(ctx) && allowed_general_roll &&
	    !running_rollover(ctx) && ret == KNOT_EOK) {
		ret = generate_ksk(ctx, 0, false);
		if (!ctx->policy->singe_type_signing && ret == KNOT_EOK) {
			ret = generate_key(ctx, DNSKEY_GENERATE_ZSK, 0, false);
		}
		log_zone_info(ctx->zone->dname, "DNSSEC, signing scheme rollover started");
		if (ret == KNOT_EOK) {
			reschedule->keys_changed = true;
		}
	}
	if (ret != KNOT_EOK) {
		return ret;
	}

	roll_action_t next = next_action(ctx, flags);

	reschedule->next_rollover = next.time;

	if (knot_time_cmp(reschedule->next_rollover, ctx->now) <= 0) {
		switch (next.type) {
		case GENERATE:
			if (next.ksk) {
				ret = generate_ksk(ctx, 0, false);
			} else {
				ret = generate_key(ctx, DNSKEY_GENERATE_ZSK, 0, false);
			}
			if (ret == KNOT_EOK) {
				log_zone_info(ctx->zone->dname, "DNSSEC, %cSK rollover started",
				              (next.ksk ? 'K' : 'Z'));
			}
			break;
		case PUBLISH:
			ret = exec_publish(ctx, next.key);
			break;
		case SUBMIT:
			ret = submit_key(ctx, next.key);
			reschedule->plan_ds_query = true;
			break;
		case REPLACE:
			ret = exec_new_signatures(ctx, next.key);
			break;
		case RETIRE:
			ret = exec_ksk_retire(ctx, next.key);
			break;
		case REMOVE:
			ret = exec_remove_old_key(ctx, next.key);
			break;
		default:
			ret = KNOT_EINVAL;
		}

		if (ret == KNOT_EOK) {
			reschedule->keys_changed = true;
			next = next_action(ctx, flags);
			reschedule->next_rollover = next.time;
		} else {
			log_zone_warning(ctx->zone->dname, "DNSSEC, key rollover, action %s (%s)",
			                 roll_action_name(next.type), knot_strerror(ret));
			// fail => try in 10 seconds #TODO better?
			reschedule->next_rollover = knot_time_add(knot_time(), 10);
		}
	}

	if (ret == KNOT_EOK && knot_time_cmp(reschedule->next_rollover, ctx->now) <= 0) {
		return knot_dnssec_key_rollover(ctx, flags, reschedule);
	}

	if (reschedule->keys_changed) {
		ret = kdnssec_ctx_commit(ctx);
	}
	return ret;
}

int knot_dnssec_ksk_sbm_confirm(kdnssec_ctx_t *ctx)
{
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (key->is_ksk && get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_READY) {
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
		if (key->is_ksk &&
		    (get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_READY ||
		     get_key_state(key, ctx->now) == DNSSEC_KEY_STATE_ACTIVE)) {
			return true;
		}
	}
	return false;
}
