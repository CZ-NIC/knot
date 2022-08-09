/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/dnssec/key_records.h"
#include "knot/dnssec/policy.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-nsec.h"
#include "knot/dnssec/zone-sign.h"
#include "knot/zone/adjust.h"
#include "knot/zone/digest.h"

static knot_time_t schedule_next(kdnssec_ctx_t *kctx, const zone_keyset_t *keyset,
				 knot_time_t keys_expire, knot_time_t rrsigs_expire)
{
	knot_time_t rrsigs_refresh = knot_time_add(rrsigs_expire, -(knot_timediff_t)kctx->policy->rrsig_refresh_before);
	knot_time_t zone_refresh = knot_time_min(keys_expire, rrsigs_refresh);

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

int knot_dnssec_nsec3resalt(kdnssec_ctx_t *ctx, bool soa_rrsigs_ok,
                            knot_time_t *salt_changed, knot_time_t *when_resalt)
{
	int ret = KNOT_EOK;

	if (!ctx->policy->nsec3_enabled) {
		return KNOT_EOK;
	}

	if (ctx->policy->nsec3_salt_lifetime < 0 && !soa_rrsigs_ok) {
		*when_resalt = ctx->now;
	} else if (ctx->zone->nsec3_salt.size != ctx->policy->nsec3_salt_length || ctx->zone->nsec3_salt_created == 0) {
		*when_resalt = ctx->now;
	} else if (knot_time_cmp(ctx->now, ctx->zone->nsec3_salt_created) < 0) {
		return KNOT_EINVAL;
	} else if (ctx->policy->nsec3_salt_lifetime > 0) {
		*when_resalt = knot_time_plus(ctx->zone->nsec3_salt_created, ctx->policy->nsec3_salt_lifetime);
	}

	if (knot_time_cmp(*when_resalt, ctx->now) <= 0) {
		if (ctx->policy->nsec3_salt_length == 0) {
			ctx->zone->nsec3_salt.size = 0;
			ctx->zone->nsec3_salt_created = ctx->now;
			*salt_changed = ctx->now;
			*when_resalt = 0;
			return kdnssec_ctx_commit(ctx);
		}

		ret = generate_salt(&ctx->zone->nsec3_salt, ctx->policy->nsec3_salt_length);
		if (ret == KNOT_EOK) {
			ctx->zone->nsec3_salt_created = ctx->now;
			ret = kdnssec_ctx_commit(ctx);
			*salt_changed = ctx->now;
		}
		// continue to planning next resalt even if NOK
		if (ctx->policy->nsec3_salt_lifetime > 0) {
			*when_resalt = knot_time_plus(ctx->now, ctx->policy->nsec3_salt_lifetime);
		}
	}

	return ret;
}

static void check_offline_records(kdnssec_ctx_t *ctx)
{
	if (!ctx->policy->offline_ksk) {
		return;
	}

	int ret;
	knot_time_t last;
	if (ctx->offline_next_time == 0) {
		log_zone_warning(ctx->zone->dname,
		                 "DNSSEC, using last offline KSK record set available, "
		                 "import new SKR before RRSIGs expire");
	} else if ((ret = key_records_last_timestamp(ctx, &last)) != KNOT_EOK) {
		log_zone_error(ctx->zone->dname,
		               "DNSSEC, failed to load offline KSK records (%s)",
		               knot_strerror(ret));
	} else if (knot_time_diff(last, ctx->now) < 7 * 24 * 3600) {
		log_zone_notice(ctx->zone->dname,
		                "DNSSEC, having offline KSK records for less than "
		                "a week, import new SKR");
	}
}

int knot_dnssec_zone_sign(zone_update_t *update,
                          conf_t *conf,
                          zone_sign_flags_t flags,
                          zone_sign_roll_flags_t roll_flags,
                          knot_time_t adjust_now,
                          zone_sign_reschedule_t *reschedule)
{
	if (!update || !reschedule) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *zone_name = update->new_cont->apex->owner;
	kdnssec_ctx_t ctx = { 0 };
	zone_keyset_t keyset = { 0 };
	knot_time_t zone_expire = 0;

	int result = kdnssec_ctx_init(conf, &ctx, zone_name, zone_kaspdb(update->zone), NULL);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to initialize signing context (%s)",
		               knot_strerror(result));
		return result;
	}
	if (adjust_now) {
		ctx.now = adjust_now;
	}

	// update policy based on the zone content
	update_policy_from_zone(ctx.policy, update->new_cont);

	if (ctx.policy->rrsig_refresh_before < ctx.policy->zone_maximal_ttl + ctx.policy->propagation_delay) {
		log_zone_error(zone_name, "DNSSEC, rrsig-refresh too low to prevent expired RRSIGs in resolver caches");
		result = KNOT_EINVAL;
		goto done;
	}

	// perform key rollover if needed
	result = knot_dnssec_key_rollover(&ctx, roll_flags, reschedule);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to update key set (%s)",
		               knot_strerror(result));
		goto done;
	}

	ctx.rrsig_drop_existing = flags & ZONE_SIGN_DROP_SIGNATURES;

	conf_val_t val = conf_zone_get(conf, C_ZONEMD_GENERATE, zone_name);
	unsigned zonemd_alg = conf_opt(&val);
	if (zonemd_alg != ZONE_DIGEST_NONE) {
		result = zone_update_add_digest(update, zonemd_alg, true);
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to reserve dummy ZONEMD (%s)",
			               knot_strerror(result));
			goto done;
		}
	}

	uint32_t ms;
	if (zone_is_slave(conf, update->zone) && zone_get_master_serial(update->zone, &ms) == KNOT_ENOENT) {
		// zone had been XFRed before on-slave-signing turned on
		zone_set_master_serial(update->zone, zone_contents_serial(update->new_cont));
	}

	result = load_zone_keys(&ctx, &keyset, true);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		goto done;
	}

	// perform nsec3resalt if pending
	if (roll_flags & KEY_ROLL_ALLOW_NSEC3RESALT) {
		knot_rdataset_t *rrsig = node_rdataset(update->new_cont->apex, KNOT_RRTYPE_RRSIG);
		bool issbaz = is_soa_signed_by_all_zsks(&keyset, rrsig);
		result = knot_dnssec_nsec3resalt(&ctx, issbaz, &reschedule->last_nsec3resalt, &reschedule->next_nsec3resalt);
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to update NSEC3 salt (%s)",
			               knot_strerror(result));
			goto done;
		}
	}

	log_zone_info(zone_name, "DNSSEC, signing started");

	result = knot_zone_sign_update_dnskeys(update, &keyset, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to update DNSKEY records (%s)",
			       knot_strerror(result));
		goto done;
	}

	result = zone_adjust_contents(update->new_cont, adjust_cb_flags, NULL,
	                              false, false, 1, update->a_ctx->node_ptrs);
	if (result != KNOT_EOK) {
		return result;
	}

	result = knot_zone_create_nsec_chain(update, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to create NSEC%s chain (%s)",
		               ctx.policy->nsec3_enabled ? "3" : "",
		               knot_strerror(result));
		goto done;
	}

	check_offline_records(&ctx);

	result = knot_zone_sign(update, &keyset, &ctx, &zone_expire);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign zone content (%s)",
		               knot_strerror(result));
		goto done;
	}

	// SOA finishing

	if (zone_update_no_change(update)) {
		log_zone_info(zone_name, "DNSSEC, zone is up-to-date");
		update->zone->zonefile.resigned = false;
		goto done;
	} else {
		update->zone->zonefile.resigned = true;
	}

	if (!(flags & ZONE_SIGN_KEEP_SERIAL) && zone_update_to(update) == NULL) {
		result = zone_update_increment_soa(update, conf);
		if (result == KNOT_EOK) {
			result = knot_zone_sign_apex_rr(update, KNOT_RRTYPE_SOA, &keyset, &ctx);
		}
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to update SOA record (%s)",
				       knot_strerror(result));
			goto done;
		}
	}

	if (zonemd_alg != ZONE_DIGEST_NONE) {
		result = zone_update_add_digest(update, zonemd_alg, false);
		if (result == KNOT_EOK) {
			result = knot_zone_sign_apex_rr(update, KNOT_RRTYPE_ZONEMD, &keyset, &ctx);
		}
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to update ZONEMD record (%s)",
			               knot_strerror(result));
			goto done;
		}
	}

	log_zone_info(zone_name, "DNSSEC, successfully signed");

done:
	if (result == KNOT_EOK) {
		reschedule->next_sign = schedule_next(&ctx, &keyset, ctx.offline_next_time, zone_expire);
	} else {
		reschedule->next_sign = knot_dnssec_failover_delay(&ctx);
		reschedule->next_rollover = 0;
	}

	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return result;
}

int knot_dnssec_sign_update(zone_update_t *update, conf_t *conf)
{
	if (update == NULL || conf == NULL) {
		return KNOT_EINVAL;
	}

	const knot_dname_t *zone_name = update->new_cont->apex->owner;
	kdnssec_ctx_t ctx = { 0 };
	zone_keyset_t keyset = { 0 };
	knot_time_t zone_expire = 0;

	int result = kdnssec_ctx_init(conf, &ctx, zone_name, zone_kaspdb(update->zone), NULL);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to initialize signing context (%s)",
		               knot_strerror(result));
		return result;
	}

	update_policy_from_zone(ctx.policy, update->new_cont);

	conf_val_t val = conf_zone_get(conf, C_ZONEMD_GENERATE, zone_name);
	unsigned zonemd_alg = conf_opt(&val);
	if (zonemd_alg != ZONE_DIGEST_NONE) {
		result = zone_update_add_digest(update, zonemd_alg, true);
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to reserve dummy ZONEMD (%s)",
			               knot_strerror(result));
			goto done;
		}
	}

	result = load_zone_keys(&ctx, &keyset, false);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to load keys (%s)",
		               knot_strerror(result));
		goto done;
	}

	if (zone_update_changes_dnskey(update)) {
		result = knot_zone_sign_update_dnskeys(update, &keyset, &ctx);
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to update DNSKEY records (%s)",
				       knot_strerror(result));
			goto done;
		}
	}

	result = zone_adjust_contents(update->new_cont, adjust_cb_flags, NULL,
	                              false, false, 1, update->a_ctx->node_ptrs);
	if (result != KNOT_EOK) {
		goto done;
	}

	check_offline_records(&ctx);

	result = knot_zone_sign_update(update, &keyset, &ctx, &zone_expire);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to sign changeset (%s)",
		               knot_strerror(result));
		goto done;
	}

	result = knot_zone_fix_nsec_chain(update, &keyset, &ctx);
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to fix NSEC%s chain (%s)",
		               ctx.policy->nsec3_enabled ? "3" : "",
		               knot_strerror(result));
		goto done;
	}

	bool soa_changed = (knot_soa_serial(node_rdataset(update->zone->contents->apex, KNOT_RRTYPE_SOA)->rdata) !=
			    knot_soa_serial(node_rdataset(update->new_cont->apex, KNOT_RRTYPE_SOA)->rdata));

	if (zone_update_no_change(update) && !soa_changed) {
		log_zone_info(zone_name, "DNSSEC, zone is up-to-date");
		update->zone->zonefile.resigned = false;
		goto done;
	} else {
		update->zone->zonefile.resigned = true;
	}

	if (!soa_changed) {
		// incrementing SOA just of it has not been modified by the update
		result = zone_update_increment_soa(update, conf);
	}
	if (result == KNOT_EOK) {
		result = knot_zone_sign_apex_rr(update, KNOT_RRTYPE_SOA, &keyset, &ctx);
	}
	if (result != KNOT_EOK) {
		log_zone_error(zone_name, "DNSSEC, failed to update SOA record (%s)",
		               knot_strerror(result));
		goto done;
	}

	if (zonemd_alg != ZONE_DIGEST_NONE) {
		result = zone_update_add_digest(update, zonemd_alg, false);
		if (result == KNOT_EOK) {
			result = knot_zone_sign_apex_rr(update, KNOT_RRTYPE_ZONEMD, &keyset, &ctx);
		}
		if (result != KNOT_EOK) {
			log_zone_error(zone_name, "DNSSEC, failed to update ZONEMD record (%s)",
			               knot_strerror(result));
			goto done;
		}
	}

	log_zone_info(zone_name, "DNSSEC, incrementally signed");

done:
	if (result == KNOT_EOK) {
		knot_time_t next = knot_time_min(ctx.offline_next_time, zone_expire);
		// NOTE: this is usually NOOP since signing planned earlier
		zone_events_schedule_at(update->zone, ZONE_EVENT_DNSSEC, next ? next : -1);
	}

	free_zone_keys(&keyset);
	kdnssec_ctx_deinit(&ctx);

	return result;
}

knot_time_t knot_dnssec_failover_delay(const kdnssec_ctx_t *ctx)
{
	if (ctx->policy == NULL) {
		return ctx->now + 3600; // failed before allocating ctx->policy, use default
	} else {
		return ctx->now + ctx->policy->rrsig_prerefresh;
	}
}

int knot_dnssec_validate_zone(zone_update_t *update, conf_t *conf, knot_time_t now, bool incremental)
{
	kdnssec_ctx_t ctx = { 0 };
	int ret = kdnssec_validation_ctx(conf, &ctx, update->new_cont);
	if (now != 0) {
		ctx.now = now;
	}
	if (ret == KNOT_EOK) {
		ret = knot_zone_check_nsec_chain(update, &ctx, incremental);
	}
	if (ret == KNOT_EOK) {
		knot_time_t unused = 0;
		assert(ctx.validation_mode);
		if (incremental) {
			ret = knot_zone_sign_update(update, NULL, &ctx, &unused);
		} else {
			ret = knot_zone_sign(update, NULL, &ctx, &unused);
		}
	}
	kdnssec_ctx_deinit(&ctx);
	return ret;
}
