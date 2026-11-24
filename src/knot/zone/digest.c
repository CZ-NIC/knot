/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <stdio.h>

#include "knot/zone/digest.h"

#include "knot/common/log.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/updates/zone-update.h"
#include "contrib/wire_ctx.h"
#include "libknot/dnssec/digest.h"
#include "libknot/libknot.h"

#define DIGEST_BUF_MIN 4096

/*! \brief Non-persistent context for one digest computation event. */
typedef struct {
	size_t buf_size;
	uint8_t *buf;
	bool ignore_dnssec;
} contents_digest_ctx_t;

void zone_contents_digest_clear(zone_contents_digest_t *dig)
{
	if (dig->scheme == ZONEMD_SCHEME_MERKLE3) {
		zis2_tree_free(dig->ctx);
	}
	memset(dig, 0, sizeof(*dig));
}

static int hash_cb(uint8_t *out, const uint8_t *in, size_t amount, void *ctx, int algorithm)
{
	(void)ctx;
	dnssec_binary_t in_bin = { .size = amount, .data = (void *)in };
	return dnssec_digest_fast(algorithm, &in_bin, out);
}

static int digest_rrset(knot_rrset_t *rrset, bool is_apex, bool remove, zone_contents_digest_t *dctx, contents_digest_ctx_t *ctx)
{
	// ignore apex ZONEMD
	if (is_apex && rrset->type == KNOT_RRTYPE_ZONEMD) {
		return KNOT_EOK;
	}

	// ignore DNSSEC if verifying on signer
	if (ctx->ignore_dnssec && knot_rrtype_is_dnssec(rrset->type)) {
		return KNOT_EOK;
	}

	// ignore RRSIGs of apex ZONEMD
	if (is_apex && rrset->type == KNOT_RRTYPE_RRSIG) {
		knot_rdataset_t cpy = rrset->rrs, zonemd_rrsig = { 0 };
		int ret = knot_rdataset_copy(&rrset->rrs, &cpy, NULL);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = knot_synth_rrsig(KNOT_RRTYPE_ZONEMD, &rrset->rrs, &zonemd_rrsig, NULL);
		if (ret == KNOT_EOK) {
			ret = knot_rdataset_subtract(&rrset->rrs, &zonemd_rrsig, NULL);
			knot_rdataset_clear(&zonemd_rrsig, NULL);
		}
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			knot_rdataset_clear(&rrset->rrs, NULL);
			return ret;
		}
	}

	size_t buf_req = knot_rrset_size_estimate(rrset);
	if (buf_req > ctx->buf_size) {
		uint8_t *newbuf = realloc(ctx->buf, buf_req);
		if (newbuf == NULL) {
			return KNOT_ENOMEM;
		}
		ctx->buf = newbuf;
		ctx->buf_size = buf_req;
	}

	int ret = knot_rrset_to_wire_extra(rrset, ctx->buf, ctx->buf_size, 0,
	                                   NULL, KNOT_PF_ORIGTTL);

	// cleanup apex RRSIGs mess
	if (is_apex && rrset->type == KNOT_RRTYPE_RRSIG) {
		knot_rdataset_clear(&rrset->rrs, NULL);
	}

	if (ret < 0) {
		return ret;
	}

	// digest serialized RRSet
	dnssec_binary_t bufbin = { ret, ctx->buf };
	if (dctx->scheme == ZONEMD_SCHEME_SIMPLE) {
		return dnssec_digest(dctx->ctx, &bufbin);
	} else if (ctx->scheme == ZONEMD_SCHEME_MERKLE3) {
		uint8_t rrhash[dnssec_digest_length(dctx->algorithm)];
		ret = dnssec_digest_fast(dctx->algorithm, &bufbin, rrhash);
		if (ret == KNOT_EOK && remove) {
			ret = zis2_tree_rem(dctx->ctx, rrhash);
		} else if (ret == KNOT_EOK) {
			ret = zis2_tree_add(dctx->ctx, rrhash);
		}
		return ret;
	} else {
		assert(0);
		return KNOT_EINVAL;
	}
}

int zone_contents_digest(zone_contents_t *contents,
                         zone_update_t *update,
                         int algorithm, int scheme,
                         bool ignore_dnssec, bool validate,
                         uint8_t *out)
{
	if (out == NULL || (contents == NULL) == (update == NULL)) {
		return KNOT_EINVAL;
	}

	zone_contents_digest_t *dctx = &contents->digest[validate];
	if (algorithm != dctx->algorithm || scheme != dctx->scheme) {
		zone_contents_digest_clear(dctx);
		dctx->algorithm = algorithm;
		dctx->scheme = scheme;
	}

	contents_digest_ctx_t ctx = {
		.buf_size = DIGEST_BUF_MIN,
		.buf = malloc(DIGEST_BUF_MIN),
		.ignore_dnssec = ignore_dnssec,
	};
	if (ctx.buf == NULL) {
		return KNOT_ENOMEM;
	}

	bool incremental = (scheme == ZONEMD_SCHEME_MERKLE3 && dctx->ctx != NULL && update != NULL && (update->flags & UPDATE_INCREMENTAL));

	int ret = KNOT_EOK;
	if (scheme == ZONEMD_SCHEME_SIMPLE) {
		ret = dnssec_digest_init(algorithm, (dnssec_digest_ctx_t **)&dctx->ctx);
	} else if (scheme == ZONEMD_SCHEME_MERKLE3 && dctx->ctx == NULL) {
		dctx->ctx = zis2_tree_new(3, dnssec_digest_length(algorithm), true, NULL);
		ret = dctx->ctx == NULL ? KNOT_ENOMEM : KNOT_EOK;
	}

	if (incremental) {
		zone_update_it_t it = { 0 };
		ret = zone_update_it_begin(&it, update, UPDATE_IT_BOTH);
		while (ret == KNOT_EOK && !zone_update_it_finished(&it)) {
			knot_rrset_t *rr = zone_update_it_val(&it);
			ret = digest_rrset(rr, zone_update_it_apex(&it), !zone_update_it_addition(&it), dctx, &ctx);
			zone_update_it_next(&it);
		}
		ret = zone_update_it_free(&it, ret);
	} else {
		zone_tree_sorted2rr_it_t it = { 0 };
		ret = zone_tree_sorted2rr_it_begin(contents->nodes, contents->nsec3_nodes, &it);
		bool is_apex = true;

		while (!zone_tree_sorted2rr_it_finished(&it) && ret == KNOT_EOK) {
			knot_rrset_t rr = zone_tree_sorted2rr_it_val(&it);
			if (is_apex && !knot_dname_is_equal(rr.owner, contents->apex->owner)) {
				is_apex = false;
			}

			ret = digest_rrset(&rr, is_apex, false, dctx, &ctx);
			zone_tree_sorted2rr_it_next(&it);
		}
		zone_tree_sorted2rr_it_free(&it);
	}

	if (ret != KNOT_EOK) {
		if (scheme == ZONEMD_SCHEME_SIMPLE) {
			dnssec_digest_clear(dctx->ctx);
		} else if (scheme == ZONEMD_SCHEME_MERKLE3) {
			zis2_tree_free(dctx->ctx);
		}
		zone_contents_digest_clear(dctx);
		free(ctx.buf);
		return ret;
	}
	dnssec_binary_t res = { 0 };
	if (scheme == ZONEMD_SCHEME_SIMPLE) {
		ret = dnssec_digest_finish2(dctx->ctx, out);
	} else if (scheme == ZONEMD_SCHEME_MERKLE3) {
		ret = zis2_tree_hash(dctx->ctx, hash_cb, NULL, out);
	} else {
		assert(0);
		ret = KNOT_EINVAL;
	}
	free(ctx.buf);
	return ret;
}

static int verify_zonemd(const knot_rdata_t *zonemd, const zone_contents_t *contents,
                         bool ignore_dnssec)
{
	uint8_t *computed = NULL;
	size_t comp_size = 0;
	int ret = zone_contents_digest(contents, knot_zonemd_algorithm(zonemd),
	                               ignore_dnssec, &computed, &comp_size);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(computed);

	if (comp_size != knot_zonemd_digest_size(zonemd)) {
		ret = KNOT_EFEWDATA;
	} else if (memcmp(knot_zonemd_digest(zonemd), computed, comp_size) != 0) {
		ret = KNOT_EMALF;
	}
	free(computed);
	return ret;
}

bool zone_contents_digest_exists(const zone_contents_t *contents, int alg, bool no_verify,
                                 bool ignore_dnssec)
{
	if (alg == 0) {
		return true;
	}

	knot_rdataset_t *zonemd = node_rdataset(contents->apex, KNOT_RRTYPE_ZONEMD);

	if (alg == ZONE_DIGEST_REMOVE) {
		return (zonemd == NULL || zonemd->count == 0);
	}

	if (zonemd == NULL || zonemd->count != 1 || knot_zonemd_algorithm(zonemd->rdata) != alg) {
		return false;
	}

	if (no_verify) {
		return true;
	}

	return verify_zonemd(zonemd->rdata, contents, ignore_dnssec) == KNOT_EOK;
}

static bool check_duplicate_schalg(const knot_rdataset_t *zonemd, int check_upto,
                                   uint8_t scheme, uint8_t alg)
{
	knot_rdata_t *check = zonemd->rdata;
	assert(check_upto <= zonemd->count);
	for (int i = 0; i < check_upto; i++) {
		if (knot_zonemd_scheme(check) == scheme &&
		    knot_zonemd_algorithm(check) == alg) {
			return false;
		}
		check = knot_rdataset_next(check);
	}
	return true;
}

int zone_contents_digest_verify(const zone_contents_t *contents, bool ignore_dnssec)
{
	if (contents == NULL) {
		return KNOT_EEMPTYZONE;
	}

	knot_rdataset_t *zonemd = node_rdataset(contents->apex, KNOT_RRTYPE_ZONEMD);
	if (zonemd == NULL) {
		return KNOT_ENOENT;
	}

	uint32_t soa_serial = zone_contents_serial(contents);

	knot_rdata_t *rr = zonemd->rdata, *supported = NULL;
	for (int i = 0; i < zonemd->count; i++) {
		if (knot_zonemd_scheme(rr) == KNOT_ZONEMD_SCHEME_SIMPLE &&
		    knot_zonemd_digest_size(rr) > 0 &&
		    knot_zonemd_soa_serial(rr) == soa_serial) {
			supported = rr;
		}
		if (!check_duplicate_schalg(zonemd, i, knot_zonemd_scheme(rr),
		                            knot_zonemd_algorithm(rr))) {
			return KNOT_ESEMCHECK;
		}
		rr = knot_rdataset_next(rr);
	}

	return supported == NULL ? KNOT_ENOTSUP : verify_zonemd(supported, contents, ignore_dnssec);
}

static ptrdiff_t zonemd_hash_offs(void)
{
	knot_rdata_t fake = { 0 };
	return knot_zonemd_digest(&fake) - fake.data;
}

int zone_update_add_digest(struct zone_update *update, int algorithm, bool placeholder)
{
	if (update == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t zero = 0, *digest = &zero;
	size_t dsize = sizeof(zero);

	knot_rrset_t exists = node_rrset(update->new_cont->apex, KNOT_RRTYPE_ZONEMD);
	if (algorithm == ZONE_DIGEST_REMOVE) {
		return zone_update_remove(update, &exists);
	}
	if (placeholder) {
		if (!knot_rrset_empty(&exists) &&
		    !check_duplicate_schalg(&exists.rrs, exists.rrs.count,
		                            KNOT_ZONEMD_SCHEME_SIMPLE, algorithm)) {
			return KNOT_EOK;
		}
	} else {
		struct timespec beg = time_now();
		int ret = zone_contents_digest(update->new_cont, algorithm, false, &digest, &dsize);

		struct timespec end = time_now();

		char meminfo[256] = { 0 };
		// TODO for incremental algorithm(s) with persistent data structure, fill in meminfo
		log_zone_debug(update->zone->name, "ZONEMD computed in %.02f seconds%s (%s)", time_diff_ms(&beg, &end) / 1000.0, meminfo, knot_strerror(ret));

		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = zone_update_remove(update, &exists);
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			if (digest != &zero) {
				free(digest);
			}
			return ret;
		}
	}

	knot_rrset_t soa = node_rrset(update->new_cont->apex, KNOT_RRTYPE_SOA);

	uint8_t rdata[zonemd_hash_offs() + dsize], buf[KNOT_RRSET_STATIC_BUFSIZE(sizeof(rdata))];
	wire_ctx_t wire = wire_ctx_init(rdata, sizeof(rdata));
	wire_ctx_write_u32(&wire, knot_soa_serial(soa.rrs.rdata));
	wire_ctx_write_u8(&wire, KNOT_ZONEMD_SCHEME_SIMPLE);
	wire_ctx_write_u8(&wire, algorithm);
	wire_ctx_write(&wire, digest, dsize);
	assert(wire.error == KNOT_EOK && wire_ctx_available(&wire) == 0);

	if (digest != &zero) {
		free(digest);
	}

	return zone_update_add(update, knot_rrset_static(buf, sizeof(buf), update->new_cont->apex->owner,
	                               KNOT_RRTYPE_ZONEMD, soa.ttl, rdata, sizeof(rdata), false));
}
