/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "dnssec/error.h"
#include "dnssec/event.h"
#include "contrib/macros.h"
#include "contrib/string.h"
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
#include "knot/zone/zone.h"

static int sign_init(const zone_contents_t *zone, int flags, kdnssec_ctx_t *ctx)
{
	assert(zone);
	assert(ctx);

	const knot_dname_t *zone_name = zone->apex->owner;

	conf_val_t val = conf_zone_get(conf(), C_STORAGE, zone_name);
	char *storage = conf_abs_path(&val, NULL);
	val = conf_zone_get(conf(), C_KASP_DB, zone_name);
	char *kasp_db = conf_abs_path(&val, storage);
	free(storage);

	char *zone_name_str = knot_dname_to_str_alloc(zone_name);
	if (zone_name_str == NULL) {
		free(kasp_db);
		return KNOT_ENOMEM;
	}

	int r = kdnssec_ctx_init(ctx, kasp_db, zone_name_str);
	free(zone_name_str);
	free(kasp_db);
	if (r != KNOT_EOK) {
		return r;
	}

	// update policy based on the zone content

	update_policy_from_zone(ctx->policy, zone);
	ctx->policy->nsec3_enabled = knot_is_nsec3_enabled(zone); // TODO: temporary

	// RRSIG handling

	ctx->rrsig_drop_existing = flags & ZONE_SIGN_DROP_SIGNATURES;

	// SOA handling

	ctx->old_serial = zone_contents_serial(zone);
	if (flags & ZONE_SIGN_KEEP_SOA_SERIAL) {
		ctx->new_serial = ctx->old_serial;
	} else {
		val = conf_zone_get(conf(), C_SERIAL_POLICY, zone_name);
		ctx->new_serial = serial_next(ctx->old_serial, conf_opt(&val));
	}

	return KNOT_EOK;
}

static dnssec_event_ctx_t kctx2ctx(const kdnssec_ctx_t *kctx)
{
	dnssec_event_ctx_t ctx = {
		.now      = kctx->now,
		.kasp     = kctx->kasp,
		.zone     = kctx->zone,
		.policy   = kctx->policy,
		.keystore = kctx->keystore
	};

	return ctx;
}

static int sign_process_events(const knot_dname_t *zone_name,
                               const kdnssec_ctx_t *kctx)
{
	dnssec_event_t event = { 0 };
	dnssec_event_ctx_t ctx = kctx2ctx(kctx);

	int r = dnssec_event_get_next(&ctx, &event);
	if (r != DNSSEC_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to get next event (%s)",
		               dnssec_strerror(r));
		return r;
	}

	if (event.type == DNSSEC_EVENT_NONE || kctx->now < event.time) {
		return DNSSEC_EOK;
	}

	log_zone_info(zone_name, "DNSSEC, executing event '%s'",
	              dnssec_event_name(event.type));

	r = dnssec_event_execute(&ctx, &event);
	if (r != DNSSEC_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to execute event (%s)",
		               dnssec_strerror(r));
		return r;
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
	// signatures refresh

	uint32_t zone_refresh = zone_expire - kctx->policy->rrsig_refresh_before;
	assert(zone_refresh > 0);

	// DNSKEY modification

	uint32_t dnskey_update = MIN(MAX(knot_get_next_zone_key_event(keyset), 0), UINT32_MAX);

	// zone events

	dnssec_event_t event = { 0 };
	dnssec_event_ctx_t ctx = kctx2ctx(kctx);
	dnssec_event_get_next(&ctx, &event);

	// result

	uint32_t next = MIN(zone_refresh, dnskey_update);
	if (event.type != DNSSEC_EVENT_NONE) {
		next = MIN(next, event.time);
	}

	return next;
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

	result = sign_process_events(zone_name, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to process events (%s)",
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
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC chain (%s)",
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
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC chain (%s)",
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
