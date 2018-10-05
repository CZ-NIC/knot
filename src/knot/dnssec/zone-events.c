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

#include "libdnssec/error.h"
#include "libdnssec/random.h"
#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/common/log.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/policy.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"

static int sign_init(const zone_contents_t *zone, zone_sign_flags_t flags, zone_sign_roll_flags_t roll_flags,
		     kdnssec_ctx_t *ctx, zone_sign_reschedule_t *reschedule)
{
	assert(zone);
	assert(ctx);

	const knot_dname_t *zone_name = zone->apex->owner;

	int r = kdnssec_ctx_init(conf(), ctx, zone_name, NULL);
	if (r != KNOT_EOK) {
		return r;
	}

	// perform nsec3resalt if pending

	if (roll_flags & KEY_ROLL_DO_NSEC3RESALT) {
		r = knot_dnssec_nsec3resalt(ctx, &reschedule->last_nsec3resalt, &reschedule->next_nsec3resalt);
		if (r != KNOT_EOK) {
			return r;
		}
	}

	// perform key rollover if needed
	r = knot_dnssec_key_rollover(ctx, roll_flags, reschedule);
	if (r != KNOT_EOK) {
		return r;
	}

	// update policy based on the zone content

	update_policy_from_zone(ctx->policy, zone);

	// RRSIG handling

	ctx->rrsig_drop_existing = flags & ZONE_SIGN_DROP_SIGNATURES;

	return KNOT_EOK;
}

static knot_time_t schedule_next(kdnssec_ctx_t *kctx, const zone_keyset_t *keyset,
				 knot_time_t zone_expire)
{
	knot_time_t zone_refresh = knot_time_add(zone_expire, -(knot_timediff_t)kctx->policy->rrsig_refresh_before);
	assert(zone_refresh > 0);

	knot_time_t dnskey_update = knot_get_next_zone_key_event(keyset);
	knot_time_t next = knot_time_min(zone_refresh, dnskey_update);

	return next;
}

static int generate_salt(dnssec_binary_t *salt, uint16_t length)
{
	assert(salt);
	dnssec_binary_t new_salt = { 0 };

	if (length > 0) {
		int r = dnssec_binary_alloc(&new_salt, length);
		if (r != KNOT_EOK) {
			return knot_error_from_libdnssec(r);
		}

		r = dnssec_random_binary(&new_salt);
		if (r != KNOT_EOK) {
			dnssec_binary_free(&new_salt);
			return knot_error_from_libdnssec(r);
		}
	}

	dnssec_binary_free(salt);
	*salt = new_salt;

	return KNOT_EOK;
}

// TODO preserve the resalt timeout in timers-db instead of kasp_db

int knot_dnssec_nsec3resalt(kdnssec_ctx_t *ctx, knot_time_t *salt_changed, knot_time_t *when_resalt)
{
	int ret = KNOT_EOK;

	if (!ctx->policy->nsec3_enabled || ctx->policy->nsec3_salt_length == 0) {
		return KNOT_EOK;
	}

	if (ctx->policy->manual) {
		return KNOT_EOK;
	}

	if (ctx->zone->nsec3_salt.size != ctx->policy->nsec3_salt_length) {
		*when_resalt = ctx->now;
	} else if (knot_time_cmp(ctx->now, ctx->zone->nsec3_salt_created) < 0) {
		return KNOT_EINVAL;
	} else {
		*when_resalt = ctx->zone->nsec3_salt_created + ctx->policy->nsec3_salt_lifetime;
	}

	if (knot_time_cmp(*when_resalt, ctx->now) <= 0) {
		ret = generate_salt(&ctx->zone->nsec3_salt, ctx->policy->nsec3_salt_length);
		if (ret == KNOT_EOK) {
			ctx->zone->nsec3_salt_created = ctx->now;
			ret = kdnssec_ctx_commit(ctx);
			*salt_changed = ctx->now;
		}
		// continue to planning next resalt even if NOK
		*when_resalt = knot_time_add(ctx->now, ctx->policy->nsec3_salt_lifetime);
	}

	return ret;
}

int knot_dnssec_zone_sign(zone_update_t *update,
                          zone_sign_flags_t flags,
                          zone_sign_roll_flags_t roll_flags,
                          zone_sign_reschedule_t *reschedule)
{
	if (!update || !reschedule) {
		return KNOT_EINVAL;
	}

	int result = KNOT_ERROR;
	const knot_dname_t *zone_name = update->new_cont->apex->owner;
	kdnssec_ctx_t ctx = { 0 };
	zone_keyset_t keyset = { 0 };

	// signing pipeline

	result = sign_init(update->new_cont, flags, roll_flags, &ctx, reschedule);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to initialize (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = load_zone_keys(&ctx, &keyset, true);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		goto done;
	}

	log_zone_info(zone_name, "DNSSEC, signing started");

	knot_time_t next_resign = 0;
	result = knot_zone_sign_update_dnskeys(update, &keyset, &ctx, &next_resign);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to update DNSKEY records (%s)",
			       knot_strerror(result));
		goto done;
	}

	result = knot_zone_create_nsec_chain(update, &keyset, &ctx, false);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC%s chain (%s)",
		               ctx.policy->nsec3_enabled ? "3" : "",
		               knot_strerror(result));
		goto done;
	}

	knot_time_t zone_expire = 0;
	result = knot_zone_sign(update, &keyset, &ctx, &zone_expire);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign zone content (%s)",
		               knot_strerror(result));
		goto done;
	}

	// SOA finishing

	if (zone_update_no_change(update) &&
	    !knot_zone_sign_soa_expired(update->new_cont, &keyset, &ctx)) {
		log_zone_info(zone_name, "DNSSEC, zone is up-to-date");
		goto done;
	}

	if (!(flags & ZONE_SIGN_KEEP_SERIAL) && zone_update_to(update) == NULL) {
		result = zone_update_increment_soa(update, conf());
		if (result == KNOT_EOK) {
			result = knot_zone_sign_soa(update, &keyset, &ctx);
		}
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to update SOA record (%s)",
				       knot_strerror(result));
			goto done;
		}
	}

	log_zone_info(zone_name, "DNSSEC, successfully signed");

done:
	if (result == KNOT_EOK) {
		reschedule->next_sign = schedule_next(&ctx, &keyset, knot_time_min(zone_expire, next_resign));
	}

	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return result;
}

int knot_dnssec_sign_update(zone_update_t *update, zone_sign_reschedule_t *reschedule)
{
	if (update == NULL || reschedule == NULL) {
		return KNOT_EINVAL;
	}

	int result = KNOT_ERROR;
	const knot_dname_t *zone_name = update->new_cont->apex->owner;
	kdnssec_ctx_t ctx = { 0 };
	zone_keyset_t keyset = { 0 };

	// signing pipeline

	result = sign_init(update->new_cont, 0, 0, &ctx, reschedule);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to initialize (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = load_zone_keys(&ctx, &keyset, false);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		goto done;
	}

	knot_time_t expire_at = 0;
	result = knot_zone_sign_update(update, &keyset, &ctx, &expire_at);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign changeset (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = knot_zone_fix_nsec_chain(update, &keyset, &ctx, true);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to fix NSEC%s chain (%s)",
		               ctx.policy->nsec3_enabled ? "3" : "",
		               knot_strerror(result));
		goto done;
	}

	bool soa_changed = (knot_soa_serial(node_rdataset(update->zone->contents->apex, KNOT_RRTYPE_SOA)->rdata) !=
			    knot_soa_serial(node_rdataset(update->new_cont->apex, KNOT_RRTYPE_SOA)->rdata));

	if (zone_update_no_change(update) && !soa_changed &&
	    !knot_zone_sign_soa_expired(update->new_cont, &keyset, &ctx)) {
		log_zone_info(zone_name, "DNSSEC, zone is up-to-date");
		goto done;
	}

	if (!soa_changed) {
		// incrementing SOA just of it has not been modified by the update
		result = zone_update_increment_soa(update, conf());
	}
	if (result == KNOT_EOK) {
		result = knot_zone_sign_soa(update, &keyset, &ctx);
	}
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to update SOA record (%s)",
		               knot_strerror(result));
		goto done;
	}

	log_zone_info(zone_name, "DNSSEC, successfully signed");

	// schedule next re-signing (only new signatures are made)
	reschedule->next_sign = ctx.now + ctx.policy->rrsig_lifetime - ctx.policy->rrsig_refresh_before;
	assert(reschedule->next_sign > 0);
	(void)expire_at; // the result of expire_at is actually unused because we computed next_sign easily
			 // we can freely reschedule dnssec event to next_sign because if it's already scheduled
			 // to earlier time, it won't get postponed

done:
	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return result;
}
