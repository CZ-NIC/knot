/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <string.h>
#include <stdio.h>
#include <time.h>

#include "utils/keymgr/offline_ksk.h"
#include "knot/dnssec/kasp/policy.h"
#include "knot/dnssec/key-events.h"
#include "knot/dnssec/key_records.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/dnssec/zone-events.h"
#include "knot/dnssec/zone-keys.h"
#include "knot/dnssec/zone-sign.h"
#include "libzscanner/scanner.h"
#include "utils/keymgr/functions.h"

#define KSR_SKR_VER "1.0"

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

// please free *_dnskey and keyset even if returned error
static int load_dnskey_rrset(kdnssec_ctx_t *ctx, knot_rrset_t **_dnskey, zone_keyset_t *keyset)
{
	// prepare the DNSKEY rrset to be signed
	knot_rrset_t *dnskey = knot_rrset_new(ctx->zone->dname, KNOT_RRTYPE_DNSKEY,
	                                      KNOT_CLASS_IN, ctx->policy->dnskey_ttl, NULL);
	if (dnskey == NULL) {
		return KNOT_ENOMEM;
	}
	*_dnskey = dnskey;

	int ret = load_zone_keys(ctx, keyset, false);
	if (ret != KNOT_EOK) {
		printf("load keys failed\n");
		return ret;
	}

	for (int i = 0; i < keyset->count; i++) {
		zone_key_t *key = &keyset->keys[i];
		if (key->is_public) {
			ret = rrset_add_zone_key(dnskey, key);
			if (ret != KNOT_EOK) {
				printf("add zone key failed\n");
				return ret;
			}
		}
	}

	return KNOT_EOK;
}

int keymgr_pregenerate_zsks(kdnssec_ctx_t *ctx, char *arg)
{
	knot_time_t upto;
	int ret = parse_timestamp(arg, &upto);
	if (ret != KNOT_EOK) {
		return ret;
	}

	knot_time_t next = ctx->now;
	ret = KNOT_EOK;

	ctx->keep_deleted_keys = true;
	ctx->policy->manual = false;

	if (ctx->policy->dnskey_ttl       == UINT32_MAX ||
	    ctx->policy->zone_maximal_ttl == UINT32_MAX) {
		printf("Error: dnskey-ttl and zone-max-ttl not configured.\n");
		return KNOT_ESEMCHECK;
	}

	while (ret == KNOT_EOK && knot_time_cmp(next, upto) <= 0) {
		ctx->now = next;
		ret = pregenerate_once(ctx, &next);
	}

	return ret;
}

static int dump_rrset_to_buf(const knot_rrset_t *rrset, char **buf, size_t *buf_size)
{
	if (*buf == NULL) {
		*buf = malloc(*buf_size);
		if (*buf == NULL) {
			return KNOT_ENOMEM;
		}
	}

	knot_dump_style_t style = {
		.wrap = true,
		.show_ttl = true,
		.verbose = true,
		.original_ttl = true,
		.human_tmstamp = true
	};
	return knot_rrset_txt_dump(rrset, buf, buf_size, &style);
}

static void print_header(const char *of_what, knot_time_t timestamp, const char *contents)
{
	char date[64] = { 0 };
	(void)knot_time_print(TIME_PRINT_ISO8601, timestamp, date, sizeof(date));
	printf(";; %s %"PRIu64" (%s) =========\n%s", of_what,
	       timestamp, date, contents);
}

int keymgr_print_offline_records(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to)
{
	knot_time_t from = 0, to = 0, next = 0;
	int ret = parse_timestamp(arg_from, &from);
	if (ret != KNOT_EOK) {
		return ret;
	}
	if (arg_to != NULL) {
		ret = parse_timestamp(arg_to, &to);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	char *buf = NULL;
	size_t buf_size = 512;
	for (knot_time_t i = from; ret == KNOT_EOK && i != 0 && (arg_to == NULL || knot_time_cmp(i, to) < 0); i = next) {
		key_records_t r = { { 0 } };
		ret = kasp_db_load_offline_records(ctx->kasp_db, ctx->zone->dname, i, &next, &r);
		if (ret == KNOT_EOK) {
			ret = key_records_dump(&buf, &buf_size, &r, true);
		}
		if (ret == KNOT_EOK) {
			print_header("Offline records for", i, buf);
		}
		key_records_clear(&r);
	}
	free(buf);

	return ret;
}

int keymgr_delete_offline_records(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to)
{
	knot_time_t from, to;
	int ret = parse_timestamp(arg_from, &from);
	if (ret != KNOT_EOK) {
		return ret;
	}
	ret = parse_timestamp(arg_to, &to);
	if (ret != KNOT_EOK) {
		return ret;
	}
	return kasp_db_delete_offline_records(ctx->kasp_db, ctx->zone->dname, from, to);
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

static void print_generated_message(void)
{
	char buf[64] = { 0 };
	knot_time_print(TIME_PRINT_ISO8601, knot_time(), buf, sizeof(buf));
	printf("generated at %s by Knot DNS %s\n", buf, VERSION);
}

static int ksr_once(kdnssec_ctx_t *ctx, char **buf, size_t *buf_size, knot_time_t *next_ksr)
{
	knot_rrset_t *dnskey = NULL;
	zone_keyset_t keyset = { 0 };
	int ret = load_dnskey_rrset(ctx, &dnskey, &keyset);
	if (ret != KNOT_EOK) {
		goto done;
	}
	ret = dump_rrset_to_buf(dnskey, buf, buf_size);
	if (ret >= 0) {
		print_header("KeySigningRequest "KSR_SKR_VER, ctx->now, *buf);
		ret = KNOT_EOK;
	}

done:
	if (ret == KNOT_EOK && next_ksr != NULL) {
		*next_ksr = knot_get_next_zone_key_event(&keyset);
	}
	knot_rrset_free(dnskey, NULL);
	free_zone_keys(&keyset);
	return ret;
}

int keymgr_print_ksr(kdnssec_ctx_t *ctx, char *arg_from, char *arg_to)
{
	knot_time_t from, to;
	int ret = parse_timestamp(arg_from, &from);
	if (ret != KNOT_EOK) {
		return ret;
	}
	ret = parse_timestamp(arg_to, &to);
	if (ret != KNOT_EOK) {
		return ret;
	}

	char *buf = NULL;
	size_t buf_size = 4096;
	while (ret == KNOT_EOK && knot_time_cmp(from, to) < 0) {
		ctx->now = from;
		ret = ksr_once(ctx, &buf, &buf_size, &from);
	}
	if (ret != KNOT_EOK) {
		free(buf);
		return ret;
	}
	ctx->now = to;
	// force end of period as a KSR timestamp
	ret = ksr_once(ctx, &buf, &buf_size, NULL);

	printf(";; KeySigningRequest %s ", KSR_SKR_VER);
	print_generated_message();

	free(buf);
	return ret;
}

typedef struct {
	int ret;
	key_records_t r;
	knot_time_t timestamp;
	kdnssec_ctx_t *kctx;
} ksr_sign_ctx_t;

static int ksr_sign_dnskey(kdnssec_ctx_t *ctx, knot_rrset_t *zsk, knot_time_t now,
                           knot_time_t *next_sign)
{
	zone_keyset_t keyset = { 0 };
	char *buf = NULL;
	size_t buf_size = 4096;
	knot_time_t rrsigs_expire = 0;

	ctx->now = now;

	int ret = load_zone_keys(ctx, &keyset, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	key_records_t r;
	key_records_init(ctx, &r);

	ret = knot_zone_sign_add_dnskeys(&keyset, ctx, &r);
	if (ret != KNOT_EOK) {
		goto done;
	}

	ret = knot_rdataset_merge(&r.dnskey.rrs, &zsk->rrs, NULL);
	if (ret != KNOT_EOK) {
		goto done;
	}

	// no check if the KSK used for signing (in keyset) is contained in DNSKEY record being signed (in KSR) !
	for (int i = 0; i < keyset.count; i++) {
		ret = key_records_sign(&keyset.keys[i], &r, ctx, &rrsigs_expire);
		if (ret != KNOT_EOK) {
			goto done;
		}
	}
	ret = key_records_dump(&buf, &buf_size, &r, true);
	if (ret == KNOT_EOK) {
		print_header("SignedKeyResponse "KSR_SKR_VER, ctx->now, buf);
		*next_sign = knot_time_min(
			knot_get_next_zone_key_event(&keyset),
			knot_time_add(rrsigs_expire, -(knot_timediff_t)ctx->policy->rrsig_refresh_before)
		);
	}

done:
	free(buf);
	key_records_clear(&r);
	free_zone_keys(&keyset);
	return ret;
}

static int process_skr_between_ksrs(ksr_sign_ctx_t *ctx, knot_time_t from, knot_time_t to)
{
	for (knot_time_t t = from; t < to /* if (t == infinity) stop */; ) {
		int ret = ksr_sign_dnskey(ctx->kctx, &ctx->r.dnskey, t, &t);
		if (ret != KNOT_EOK) {
			return ret;
		}
	}
	return KNOT_EOK;
}

static void ksr_sign_header(zs_scanner_t *sc)
{
	ksr_sign_ctx_t *ctx = sc->process.data;

	// parse header
	float header_ver;
	knot_time_t next_timestamp = 0;
	if (sc->error.code != 0 || ctx->ret != KNOT_EOK ||
	    sscanf((const char *)sc->buffer, "; KeySigningRequest %f %"PRIu64,
	           &header_ver, &next_timestamp) < 1) {
		return;
	}
	(void)header_ver;

	// sign previous KSR and inbetween KSK changes
	if (ctx->timestamp > 0) {
		knot_time_t inbetween_from;
		ctx->ret = ksr_sign_dnskey(ctx->kctx, &ctx->r.dnskey, ctx->timestamp,
		                           &inbetween_from);
		if (next_timestamp > 0 && ctx->ret == KNOT_EOK) {
			ctx->ret = process_skr_between_ksrs(ctx, inbetween_from,
			                                    next_timestamp);
		}
		key_records_clear_rdatasets(&ctx->r);
	}

	// start new KSR
	ctx->timestamp = next_timestamp;
}

static void ksr_sign_once(zs_scanner_t *sc)
{
	ksr_sign_ctx_t *ctx = sc->process.data;
	if (sc->error.code == 0 && ctx->ret == KNOT_EOK) {
		ctx->ret = knot_rrset_add_rdata(&ctx->r.dnskey, sc->r_data, sc->r_data_length, NULL);
		ctx->r.dnskey.ttl = sc->r_ttl;
	}
}

static void skr_import_header(zs_scanner_t *sc)
{
	ksr_sign_ctx_t *ctx = sc->process.data;

	// parse header
	float header_ver;
	knot_time_t next_timestamp;
	if (sc->error.code != 0 || ctx->ret != KNOT_EOK ||
	    sscanf((const char *)sc->buffer, "; SignedKeyResponse %f %"PRIu64,
	           &header_ver, &next_timestamp) < 1) {
		return;
	}
	(void)header_ver;

	// delete possibly existing conflicting offline records
	ctx->ret = kasp_db_delete_offline_records(
		ctx->kctx->kasp_db, ctx->kctx->zone->dname, next_timestamp, 0
	);

	// store previous SKR
	if (ctx->timestamp > 0 && ctx->ret == KNOT_EOK) {
		ctx->ret = key_records_verify(&ctx->r, ctx->kctx, ctx->timestamp);
		if (ctx->ret != KNOT_EOK) {
			return;
		}

		ctx->ret = kasp_db_store_offline_records(ctx->kctx->kasp_db,
		                                         ctx->timestamp, &ctx->r);
		key_records_clear_rdatasets(&ctx->r);
	}

	// start new SKR
	ctx->timestamp = next_timestamp;
}

static void skr_validate_header(zs_scanner_t *sc)
{
	ksr_sign_ctx_t *ctx = sc->process.data;

	float header_ver;
	knot_time_t next_timestamp;
	if (sc->error.code != 0 || ctx->ret != KNOT_EOK ||
	    sscanf((const char *)sc->buffer, "; SignedKeyResponse %f %"PRIu64,
	           &header_ver, &next_timestamp) < 1) {
		return;
	}
	(void)header_ver;

	if (ctx->timestamp > 0 && ctx->ret == KNOT_EOK) {
		int ret = key_records_verify(&ctx->r, ctx->kctx, ctx->timestamp);
		if (ret != KNOT_EOK) { // ctx->ret untouched
			printf("error: invalid SignedKeyResponse for %lu (%s)\n",
			       ctx->timestamp, knot_strerror(ret));
		}
		key_records_clear_rdatasets(&ctx->r);
	}

	ctx->timestamp = next_timestamp;
}

static void skr_import_once(zs_scanner_t *sc)
{
	ksr_sign_ctx_t *ctx = sc->process.data;
	if (sc->error.code == 0 && ctx->ret == KNOT_EOK) {
		ctx->ret = key_records_add_rdata(&ctx->r, sc->r_type, sc->r_data,
		                                 sc->r_data_length, sc->r_ttl);
	}
}

static int read_ksr_skr(kdnssec_ctx_t *ctx, const char *infile,
                        void (*cb_header)(zs_scanner_t *), void (*cb_record)(zs_scanner_t *))
{
	zs_scanner_t sc = { 0 };
	int ret = zs_init(&sc, "", KNOT_CLASS_IN, 0);
	if (ret < 0) {
		return KNOT_ERROR;
	}

	ret = zs_set_input_file(&sc, infile);
	if (ret < 0) {
		zs_deinit(&sc);
		return KNOT_EFILE;
	}

	ksr_sign_ctx_t pctx = { 0 };
	key_records_init(ctx, &pctx.r);
	pctx.kctx = ctx;
	ret = zs_set_processing(&sc, cb_record, NULL, &pctx);
	if (ret < 0) {
		zs_deinit(&sc);
		return KNOT_EBUSY;
	}
	sc.process.comment = cb_header;

	ret = zs_parse_all(&sc);

	if (sc.error.code != 0) {
		ret = KNOT_EMALF;
	} else if (pctx.ret != KNOT_EOK) {
		ret = pctx.ret;
	} else if (ret < 0 || pctx.r.dnskey.rrs.count > 0 || pctx.r.cdnskey.rrs.count > 0 ||
		   pctx.r.cds.rrs.count > 0 || pctx.r.rrsig.rrs.count > 0) {
		ret = KNOT_EMALF;
	}
	key_records_clear(&pctx.r);
	zs_deinit(&sc);
	return ret;
}

int keymgr_sign_ksr(kdnssec_ctx_t *ctx, const char *ksr_file)
{
	int ret = read_ksr_skr(ctx, ksr_file, ksr_sign_header, ksr_sign_once);
	printf(";; SignedKeyResponse %s ", KSR_SKR_VER);
	print_generated_message();
	return ret;
}

int keymgr_import_skr(kdnssec_ctx_t *ctx, const char *skr_file)
{
	return read_ksr_skr(ctx, skr_file, skr_import_header, skr_import_once);
}

int keymgr_validate_skr(kdnssec_ctx_t *ctx, const char *skr_file)
{
	return read_ksr_skr(ctx, skr_file, skr_validate_header, skr_import_once);
}
