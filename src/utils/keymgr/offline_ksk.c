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

// please free *_dnskey and keyset even if returned error
static int load_dnskey_rrset(kdnssec_ctx_t *ctx, knot_rrset_t **_dnskey, zone_keyset_t *keyset)
{
	// prepare the DNSKEY rrset to be signed
	knot_rrset_t *dnskey = knot_rrset_new(ctx->zone->dname, KNOT_RRTYPE_DNSKEY, KNOT_CLASS_IN, ctx->policy->dnskey_ttl, NULL);
	if (dnskey == NULL) {
		return KNOT_ENOMEM;
	}

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

	*_dnskey = dnskey;
	return KNOT_EOK;
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
	return knot_rrset_txt_dump(rrset, buf, buf_size, &KNOT_DUMP_STYLE_DEFAULT);
}

int keymgr_print_rrsig(kdnssec_ctx_t *ctx, knot_time_t when)
{
	knot_time_t next = 0;
	knot_rrset_t rrsig = { 0 }, dnskey = { 0 }, cdnskey = { 0 }, cds = { 0 };
	knot_rrset_init(&rrsig, knot_dname_copy(ctx->zone->dname, NULL),
	                KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, ctx->policy->dnskey_ttl);
	knot_rrset_init_empty(&dnskey);
	knot_rrset_init_empty(&cdnskey);
	knot_rrset_init_empty(&cds);
	int ret = kasp_db_load_offline_rrsig(*ctx->kasp_db, ctx->zone->dname, when, &next, &rrsig, &dnskey, &cdnskey, &cds);
	if (ret == KNOT_EOK) {
		char *buf = NULL;
		size_t buf_size = 512;
		ret = dump_rrset_to_buf(&rrsig, &buf, &buf_size);
		if (ret >= 0) {
			printf("%s", buf);
			ret = dump_rrset_to_buf(&dnskey, &buf, &buf_size);
		}
		if (ret >= 0) {
			printf("%s", buf);
			ret = dump_rrset_to_buf(&cdnskey, &buf, &buf_size);
		}
		if (ret >= 0) {
			printf("%s", buf);
			ret = dump_rrset_to_buf(&cds, &buf, &buf_size);
		}
		if (ret >= 0) {
			printf("%s", buf);
			ret = KNOT_EOK;
		}
		free(buf);
		printf("; next %lu\n", next);
	}
	knot_rrset_clear(&rrsig, NULL);
	knot_rrset_clear(&dnskey, NULL);
	knot_rrset_clear(&cdnskey, NULL);
	knot_rrset_clear(&cds, NULL);
	return ret;
}

int keymgr_delete_rrsig(kdnssec_ctx_t *ctx, knot_time_t from, knot_time_t to)
{
	return kasp_db_delete_offline_rrsig(*ctx->kasp_db, ctx->zone->dname, from, to);
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

static void print_generated_message()
{
	char buf[64] = { 0 };
	knot_time_print(TIME_PRINT_ISO8601, knot_time(), buf, sizeof(buf));
	printf("generated on %s by KnotDNS %s\n", buf, VERSION);
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
		(*buf)[strlen(*buf) - 1] = '\0'; // remove trailing newline
		printf(";;KSR %lu %hu %d\n%s ; end KSR %lu\n", ctx->now, dnskey->rrs.count, ret, *buf, ctx->now);
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

int keymgr_print_ksr(kdnssec_ctx_t *ctx, knot_time_t upto)
{
	knot_time_t next = ctx->now;
	int ret = KNOT_EOK;
	char *buf = NULL;
	size_t buf_size = 4096;

	while (ret == KNOT_EOK && knot_time_cmp(next, upto) < 0) {
		ctx->now = next;
		ret = ksr_once(ctx, &buf, &buf_size, &next);
	}
	if (ret != KNOT_EOK) {
		free(buf);
		return ret;
	}
	ctx->now = upto;
	// force end of period as a KSR timestamp
	ret = ksr_once(ctx, &buf, &buf_size, NULL);

	printf(";; KeySigningRequest ");
	print_generated_message();

	free(buf);
	return ret;
}

typedef struct {
	knot_rrset_t *dnskey;
	knot_rrset_t *dnskey_prev;
	knot_rrset_t *cdnskey;
	knot_rrset_t *cds;
	knot_rrset_t *rrsig;
	kdnssec_ctx_t *kctx;
} ksr_sign_ctx_t;

static int ksr_sign_dnskey(kdnssec_ctx_t *ctx, knot_rrset_t *zsk, knot_time_t *next_sign)
{
	zone_keyset_t keyset = { 0 };
	char *buf = NULL;
	size_t buf_size = 4096;
	int ret = load_zone_keys(ctx, &keyset, false);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_rrset_t *dnskey = knot_rrset_copy(zsk, NULL);
	knot_rrset_t *cdnskey = knot_rrset_new(zsk->owner, KNOT_RRTYPE_CDNSKEY, zsk->rclass, 0, NULL);
	knot_rrset_t *cds = knot_rrset_new(zsk->owner, KNOT_RRTYPE_CDS, zsk->rclass, 0, NULL);
	knot_rrset_t *rrsig = knot_rrset_new(zsk->owner, KNOT_RRTYPE_RRSIG, zsk->rclass, zsk->ttl, NULL);
	if (dnskey == NULL || cdnskey == NULL || cds == NULL || rrsig == NULL) {
		ret = KNOT_ENOMEM;
		goto done;
	}

	ret = knot_zone_sign_add_dnskeys(&keyset, ctx, dnskey, cdnskey, cds);
	if (ret != KNOT_EOK) {
		goto done;
	}

	// no check if the KSK used for signing (in keyset) is contained in DNSKEY record being signed (in KSR) !
	for (int i = 0; i < keyset.count; i++) {
		zone_key_t *key = &keyset.keys[i];
		if (key->is_active && key->is_ksk) {
			ret = knot_sign_rrset(rrsig, dnskey, key->key, key->ctx, ctx, NULL);
			if (ret != KNOT_EOK) {
				goto done;
			}
		}
	}
	printf(";;SKR ===========\n");
	ret = dump_rrset_to_buf(dnskey, &buf, &buf_size);
	if (ret >= 0) {
		printf("%s", buf);
		ret = dump_rrset_to_buf(cdnskey, &buf, &buf_size);
	}
	if (ret >= 0) {
		printf("%s", buf);
		ret = dump_rrset_to_buf(cds, &buf, &buf_size);
	}
	if (ret >= 0) {
		printf("%s", buf);
		ret = dump_rrset_to_buf(rrsig, &buf, &buf_size);
	}
	if (ret >= 0) {
		buf[strlen(buf) - 1] = '\0'; // remove trailing newline
		printf("%s ; end SKR %lu\n", buf, ctx->now);
		ret = KNOT_EOK;
	}

done:
	free(buf);
	knot_rrset_free(dnskey, NULL);
	knot_rrset_free(cdnskey, NULL);
	knot_rrset_free(cds, NULL);
	knot_rrset_free(rrsig, NULL);
	if (ret == KNOT_EOK) {
		*next_sign = knot_get_next_zone_key_event(&keyset);
	}
	free_zone_keys(&keyset);
	return ret;
}

static int process_skr_between_ksrs(ksr_sign_ctx_t *ctx, knot_time_t next_ksr)
{
	static knot_time_t prev_ksr = 0;

	assert((prev_ksr == 0 ? 1 : 0) == (knot_rrset_empty(ctx->dnskey_prev) ? 1 : 0));

	if (!knot_rrset_empty(ctx->dnskey_prev)) {
		for (knot_time_t inbetween_skr = prev_ksr; inbetween_skr < next_ksr; ) {
			ctx->kctx->now = inbetween_skr;
			int ret = ksr_sign_dnskey(ctx->kctx, ctx->dnskey_prev, &inbetween_skr);
			if (ret != KNOT_EOK) {
				return ret;
			}
		}
	}

	// finally, do the "requested" SKR and copy ctx->dnskey into ct->rrsig
	ctx->kctx->now = next_ksr;
	int ret = ksr_sign_dnskey(ctx->kctx, ctx->dnskey, &prev_ksr);
	if (ret != KNOT_EOK) {
		return ret;
	}
	knot_rdataset_clear(&ctx->dnskey_prev->rrs, NULL);
	ret = knot_rdataset_copy(&ctx->dnskey_prev->rrs, &ctx->dnskey->rrs, NULL);
	return ret;
}

static void ksr_sign_once(zs_scanner_t *sc)
{
	ksr_sign_ctx_t *ctx = sc->process.data;

	sc->error.code = knot_rrset_add_rdata(ctx->dnskey, sc->r_data, sc->r_data_length, NULL);
	ctx->dnskey->ttl = sc->r_ttl;

	if (sc->error.code == KNOT_EOK && sc->buffer_length > 9 && strncmp((const char *)sc->buffer, " end KSR ", 9) == 0) {
		knot_time_t next_ksr = atol((const char *)sc->buffer + 9);
		sc->error.code = process_skr_between_ksrs(ctx, next_ksr);
		knot_rdataset_clear(&ctx->dnskey->rrs, NULL);
	}
}

static void skr_import_once(zs_scanner_t *sc)
{
	ksr_sign_ctx_t *ctx = sc->process.data;
	knot_rrset_t *to_add = NULL;
	switch (sc->r_type) {
	case KNOT_RRTYPE_DNSKEY:
		to_add = ctx->dnskey;
		break;
	case KNOT_RRTYPE_CDNSKEY:
		to_add = ctx->cdnskey;
		break;
	case KNOT_RRTYPE_CDS:
		to_add = ctx->cds;
		break;
	case KNOT_RRTYPE_RRSIG:
		to_add = ctx->rrsig;
		break;
	default:
		sc->error.code = KNOT_EINVAL;
		return;
	}

	sc->error.code = knot_rrset_add_rdata(to_add, sc->r_data, sc->r_data_length, NULL);
	to_add->ttl = sc->r_ttl;

	if (sc->error.code == KNOT_EOK && sc->buffer_length > 9 && strncmp((const char *)sc->buffer, " end SKR ", 9) == 0) {
		knot_time_t for_time = atol((const char *)sc->buffer + 9);
		sc->error.code = kasp_db_store_offline_rrsig(*ctx->kctx->kasp_db, for_time, ctx->rrsig, ctx->dnskey, ctx->cdnskey, ctx->cds);
		knot_rdataset_clear(&ctx->dnskey->rrs, NULL);
		knot_rdataset_clear(&ctx->cdnskey->rrs, NULL);
		knot_rdataset_clear(&ctx->cds->rrs, NULL);
		knot_rdataset_clear(&ctx->rrsig->rrs, NULL);
	}
}

static int read_ksr_skr(kdnssec_ctx_t *ctx, const char *infile, void (*cb)(zs_scanner_t *))
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

	knot_rrset_t dnskey = { 0 }, dnskey_prev = { 0 }, cdnskey = { 0 }, cds = { 0 }, rrsig = { 0 };
	knot_rrset_init(&dnskey, ctx->zone->dname, KNOT_RRTYPE_DNSKEY, KNOT_CLASS_IN, ctx->policy->dnskey_ttl);
	knot_rrset_init(&dnskey_prev, ctx->zone->dname, KNOT_RRTYPE_DNSKEY, KNOT_CLASS_IN, ctx->policy->dnskey_ttl);
	knot_rrset_init(&cdnskey, ctx->zone->dname, KNOT_RRTYPE_CDNSKEY, KNOT_CLASS_IN, 0);
	knot_rrset_init(&cds, ctx->zone->dname, KNOT_RRTYPE_CDS, KNOT_CLASS_IN, 0);
	knot_rrset_init(&rrsig, ctx->zone->dname, KNOT_RRTYPE_RRSIG, KNOT_CLASS_IN, ctx->policy->dnskey_ttl);

	ksr_sign_ctx_t pctx = { &dnskey, &dnskey_prev, &cdnskey, &cds, &rrsig, ctx };
	ret = zs_set_processing(&sc, cb, NULL, &pctx);
	if (ret < 0) {
		zs_deinit(&sc);
		return KNOT_EBUSY;
	}

	ret = zs_parse_all(&sc);

	if (sc.error.code != KNOT_EOK) {
		ret = sc.error.code;
	} else if (ret < 0 || dnskey.rrs.count > 0 || cdnskey.rrs.count > 0 ||
		   cds.rrs.count > 0 || rrsig.rrs.count > 0) {
		ret = KNOT_EMALF;
	}
	knot_rdataset_clear(&dnskey.rrs, NULL);
	knot_rdataset_clear(&dnskey_prev.rrs, NULL);
	knot_rdataset_clear(&cdnskey.rrs, NULL);
	knot_rdataset_clear(&cds.rrs, NULL);
	knot_rdataset_clear(&rrsig.rrs, NULL);
	zs_deinit(&sc);
	return ret;
}

int keymgr_sign_ksr(kdnssec_ctx_t *ctx, const char *ksr_file)
{
	int ret = read_ksr_skr(ctx, ksr_file, ksr_sign_once);
	printf(";; SignedKeyResponse ");
	print_generated_message();
	return ret;
}

int keymgr_import_skr(kdnssec_ctx_t *ctx, const char *skr_file)
{
	return read_ksr_skr(ctx, skr_file, skr_import_once);
}
