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

#include "dnssec/error.h"
#include "dnssec/random.h"
#include "contrib/macros.h"
#include "libknot/libknot.h"
#include "knot/conf/conf.h"
#include "knot/common/log.h"
#include "knot/dnssec/context.h"
#include "knot/dnssec/policy.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/serial.h"

static int sign_init(const zone_contents_t *zone, int flags, kdnssec_ctx_t *ctx)
{
	assert(zone);
	assert(ctx);

	const knot_dname_t *zone_name = zone->apex->owner;

	int r = kdnssec_ctx_init(conf(), ctx, zone_name);
	if (r != KNOT_EOK) {
		return r;
	}

	// update policy based on the zone content

	update_policy_from_zone(ctx->policy, zone);

	// RRSIG handling

	ctx->rrsig_drop_existing = flags & ZONE_SIGN_DROP_SIGNATURES;

	// SOA handling

	ctx->old_serial = zone_contents_serial(zone);
	if (flags & ZONE_SIGN_KEEP_SOA_SERIAL) {
		ctx->new_serial = ctx->old_serial;
	} else {
		conf_val_t val = conf_zone_get(conf(), C_SERIAL_POLICY, zone_name);
		ctx->new_serial = serial_next(ctx->old_serial, conf_opt(&val));
	}

	return KNOT_EOK;
}

static int sign_update_soa(const zone_contents_t *zone, changeset_t *chset,
                           kdnssec_ctx_t *ctx, zone_keyset_t *keyset)
{
	knot_rrset_t soa = node_rrset(zone->apex, KNOT_RRTYPE_SOA);
	knot_rrset_t rrsigs = node_rrset(zone->apex, KNOT_RRTYPE_RRSIG);
	assert(!knot_rrset_empty(&soa));
	return knot_zone_sign_update_soa(&soa, &rrsigs, keyset, ctx, chset);
}

static uint32_t schedule_next(kdnssec_ctx_t *kctx, const zone_keyset_t *keyset,
                              uint32_t zone_expire)
{
	uint32_t zone_refresh = zone_expire - kctx->policy->rrsig_refresh_before;
	assert(zone_refresh > 0);

	uint32_t dnskey_update = MIN(MAX(knot_get_next_zone_key_event(keyset), 0),
	                             UINT32_MAX);
	uint32_t next = MIN(zone_refresh, dnskey_update);

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

int knot_dnssec_nsec3resalt(kdnssec_ctx_t *ctx, bool *salt_changed, time_t *when_resalt)
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
	} else if (ctx->now < ctx->zone->nsec3_salt_created) {
		return KNOT_EINVAL;
	} else {
		*when_resalt = ctx->zone->nsec3_salt_created + ctx->policy->nsec3_salt_lifetime;
	}

	if (*when_resalt <= ctx->now) {
		ret = generate_salt(&ctx->zone->nsec3_salt, ctx->policy->nsec3_salt_length);
		if (ret == KNOT_EOK) {
			ctx->zone->nsec3_salt_created = ctx->now;
			ret = kdnssec_ctx_commit(ctx);
			*salt_changed = true;
		}
		// continue to planning next resalt even if NOK
		*when_resalt = ctx->now + ctx->policy->nsec3_salt_lifetime;
	}

	return ret;
}

int knot_dnssec_zone_sign(zone_contents_t *zone, changeset_t *out_ch,
                          zone_sign_flags_t flags, uint32_t *refresh_at)
{
	if (!zone || !out_ch || !refresh_at) {
		return KNOT_EINVAL;
	}

	int result = KNOT_ERROR;
	const knot_dname_t *zone_name = zone->apex->owner;
	kdnssec_ctx_t ctx = { 0 };
	zone_keyset_t keyset = { 0 };

	// signing pipeline

	result = sign_init(zone, flags, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to initialize (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = load_zone_keys(ctx.zone, ctx.keystore,
	                        ctx.policy->nsec3_enabled, ctx.now, &keyset);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		goto done;
	}

	log_zone_info(zone_name, "DNSSEC, signing started");

	result = knot_zone_create_nsec_chain(zone, out_ch, &keyset, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC%s chain (%s)",
		               ctx.policy->nsec3_enabled ? "3" : "",
		               knot_strerror(result));
		goto done;
	}

	uint32_t zone_expire = 0;
	result = knot_zone_sign(zone, &keyset, &ctx, out_ch, &zone_expire);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign zone content (%s)",
		               knot_strerror(result));
		goto done;
	}

	// SOA finishing

	if (changeset_empty(out_ch) &&
	    !knot_zone_sign_soa_expired(zone, &keyset, &ctx)) {
		log_zone_info(zone_name, "DNSSEC, zone is up-to-date");
		goto done;
	}

	result = sign_update_soa(zone, out_ch, &ctx, &keyset);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to update SOA record (%s)",
		               knot_strerror(result));
		goto done;
	}

	log_zone_info(zone_name, "DNSSEC, successfully signed");

done:
	if (result == KNOT_EOK) {
		*refresh_at = schedule_next(&ctx, &keyset, zone_expire);
	}

	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return result;
}

int knot_dnssec_sign_changeset(const zone_contents_t *zone,
                               const changeset_t *in_ch,
                               changeset_t *out_ch,
                               uint32_t *refresh_at)
{
	if (zone == NULL || in_ch == NULL || out_ch == NULL || refresh_at == NULL) {
		return KNOT_EINVAL;
	}

	int result = KNOT_ERROR;
	const knot_dname_t *zone_name = zone->apex->owner;
	kdnssec_ctx_t ctx = { 0 };
	zone_keyset_t keyset = { 0 };

	// signing pipeline

	result = sign_init(zone, ZONE_SIGN_KEEP_SOA_SERIAL, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to initialize (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = load_zone_keys(ctx.zone, ctx.keystore,
	                        ctx.policy->nsec3_enabled, ctx.now, &keyset);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = knot_zone_sign_changeset(zone, in_ch, out_ch, &keyset, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign changeset (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = knot_zone_create_nsec_chain(zone, out_ch, &keyset, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC%s chain (%s)",
		               ctx.policy->nsec3_enabled ? "3" : "",
		               knot_strerror(result));
		goto done;
	}

	result = knot_zone_sign_nsecs_in_changeset(&keyset, &ctx, out_ch);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign changeset (%s)",
		               knot_strerror(result));
		goto done;
	}

	// update SOA

	result = sign_update_soa(zone, out_ch, &ctx, &keyset);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to update SOA record (%s)",
		               knot_strerror(result));
		goto done;
	}

	// schedule next resigning (only new signatures are made)

	*refresh_at = ctx.now + ctx.policy->rrsig_lifetime - ctx.policy->rrsig_refresh_before;
	assert(refresh_at > 0);

done:
	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return KNOT_EOK;
}
