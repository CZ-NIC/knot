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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "utils/keymgr/offline_ksk.h"
#include "knot/dnssec/kasp/policy.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-sign.h"
#include "libzscanner/scanner.h"

static int pregenerate_once(kdnssec_ctx_t *ctx, knot_time_t *next)
{
	zone_sign_reschedule_t resch = { 0 };

	// generate ZSKs
	int ret = knot_dnssec_key_rollover(ctx, KEY_ROLL_ALLOW_ZSK_ROLL, &resch);
	if (ret != KNOT_EOK) {
		printf("rollover failed\n");
		return ret;
	}
	// we don't need to do anything explicitly with the generated ZSKs
	// they're simply stored in KASP db

	*next = resch.next_rollover;
	return KNOT_EOK;
}

static void update_next_resign(knot_time_t *next, knot_time_t now, knot_time_t key_timer)
{
	if (knot_time_cmp(now, key_timer) < 0) {
		*next = knot_time_min(*next, key_timer);
	}
}

static int presign_once(kdnssec_ctx_t *ctx, knot_time_t *next)
{
	// prepare the DNSKEY rrset to be signed
	zone_keyset_t keyset = { 0 };
	int ret = load_zone_keys(ctx, &keyset, false);
	if (ret != KNOT_EOK) {
		printf("load keys failed\n");
		return ret;
	}
	knot_rrset_t *dnskey = knot_rrset_new(ctx->zone->dname, KNOT_RRTYPE_DNSKEY, KNOT_CLASS_IN, ctx->policy->dnskey_ttl, NULL);
	knot_rrset_t *rrsig = knot_rrset_new(ctx->zone->dname, KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, ctx->policy->dnskey_ttl, NULL);
	if (dnskey == NULL || rrsig == NULL) {
		ret = KNOT_ENOMEM;
		goto done;
	}
	for (int i = 0; i < keyset.count; i++) {
		zone_key_t *key = &keyset.keys[i];
		if (key->is_public) {
			ret = rrset_add_zone_key(dnskey, key);
			if (ret != KNOT_EOK) {
				printf("add zone key failed\n");
				goto done;
			}
		}
	}

	// sign the DNSKEY rrset
	for (int i = 0; i < keyset.count; i++) {
		zone_key_t *key = &keyset.keys[i];
		if (key->is_active && key->is_ksk) {
			ret = knot_sign_rrset(rrsig, dnskey, key->key, key->ctx, ctx, NULL);
			if (ret != KNOT_EOK) {
				printf("sign rrset failed\n");
				goto done;
			}
		}
	}

	// store it to KASP db
	assert(!knot_rrset_empty(rrsig));
	ret = kasp_db_store_offline_rrsig(*ctx->kasp_db, ctx->now, rrsig);
	if (ret != KNOT_EOK) {
		printf("store rrsig failed\n");
		goto done;
	}

	// next re-sign when rrsig expire or dnskey rrset changes
	*next = ctx->now + ctx->policy->rrsig_lifetime - ctx->policy->rrsig_refresh_before;
	for (int i = 0; i < ctx->zone->num_keys; i++) {
		update_next_resign(next, ctx->now, ctx->zone->keys[i].timing.publish);
		update_next_resign(next, ctx->now, ctx->zone->keys[i].timing.retire_active);
		update_next_resign(next, ctx->now, ctx->zone->keys[i].timing.remove);
	}

done:
	knot_rrset_free(dnskey, NULL);
	knot_rrset_free(rrsig, NULL);
	free_zone_keys(&keyset);
	return ret;
}

int keymgr_pregenerate_zsks(kdnssec_ctx_t *ctx, knot_time_t upto)
{
	knot_time_t next = ctx->now;
	int ret = KNOT_EOK;

	ctx->keep_deleted_keys = true;
	ctx->rollover_only_zsk = true;
	ctx->policy->manual = false;

	while (ret == KNOT_EOK && knot_time_cmp(next, upto) <= 0) {
		ctx->now = next;
		printf("pregenerate %lu\n", ctx->now);
		ret = pregenerate_once(ctx,  &next);
	}

	return ret;
}

int keymgr_presign_zsks(kdnssec_ctx_t *ctx, knot_time_t upto)
{
	knot_time_t next = ctx->now;
	int ret = KNOT_EOK;

	ctx->keep_deleted_keys = true;
	ctx->policy->manual = true;

	while (ret == KNOT_EOK && knot_time_cmp(next, upto) <= 0) {
		ctx->now = next;
		printf("presign %lu\n", ctx->now);
		ret = presign_once(ctx, &next);
	}

	return ret;
}

int keymgr_print_rrsig(kdnssec_ctx_t *ctx, knot_time_t when)
{
	knot_rrset_t rrsig = { 0 };
	knot_rrset_init_empty(&rrsig);
	int ret = kasp_db_load_offline_rrsig(*ctx->kasp_db, ctx->zone->dname, when, &rrsig);
	if (ret == KNOT_EOK) {
		size_t out_size = 512;
		char *out = malloc(out_size);
		if (out == NULL) {
			ret = KNOT_ENOMEM;
		} else {
			ret = knot_rrset_txt_dump(&rrsig, &out, &out_size, &KNOT_DUMP_STYLE_DEFAULT);
			if (ret >= 0) {
				printf("%s\n", out);
				ret = KNOT_EOK;
			}
			free(out);
		}
	}
	knot_rrset_clear(&rrsig, NULL);
	return ret;
}

int keymgr_del_all_old(kdnssec_ctx_t *ctx)
{
	for (size_t i = 0; i < ctx->zone->num_keys; i++) {
		knot_kasp_key_t *key = &ctx->zone->keys[i];
		if (knot_time_cmp(key->timing.remove, ctx->now) < 0) {
			int ret = kdnssec_delete_key(ctx, key);
			printf("- %s\n", knot_strerror(ret));
		}
	}
	return kdnssec_ctx_commit(ctx);
}
