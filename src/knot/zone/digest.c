/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdio.h>

#include "knot/zone/digest.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/updates/zone-update.h"
#include "contrib/hr_tree.h"
#include "contrib/wire_ctx.h"
#include "libknot/dnssec/digest.h"
#include "libknot/libknot.h"

#define DIGEST_BUF_MIN 4096

typedef struct {
	size_t buf_size;
	uint8_t *buf;
	struct dnssec_digest_ctx *digest_ctx;
	const zone_node_t *apex;
	hr_tree_t *hr_tree;
	int algorithm;
	int scheme;
	bool ignore_dnssec;
	bool allow_alg_change;
	bool removals;
} contents_digest_ctx_t;

static int rehash_2hashes(uint8_t *target, const uint8_t *a, const uint8_t *b, void *ctx, int algorithm)
{
	size_t size = dnssec_digest_size(algorithm);
	uint8_t both[2*size];
	memcpy(both, a, size);
	memcpy(both + size, b, size);
	dnssec_binary_t bin = { .size = 2 * size, .data = both }, out = { 0 };
	int ret = dnssec_digest_fast(algorithm, &bin, &out);
	assert(out.size == size || ret != 0);
	memcpy(target, out.data, out.size);
	dnssec_binary_free(&out);
	return ret;
}

static bool rrset_is_apex(const knot_rrset_t *rrset, const contents_digest_ctx_t *ctx)
{
	bool res1 = (rrset->owner == ctx->apex->owner);
	bool res2 = knot_dname_is_equal(rrset->owner, ctx->apex->owner);
	assert(res1 == res2);
	return res1;
}

static int digest_rrset(const knot_rrset_t *_rrset, void *vctx)
{
	contents_digest_ctx_t *ctx = vctx;
	knot_rrset_t shallow = *_rrset, *rrset = &shallow;

	// ignore apex ZONEMD
	if (rrset_is_apex(rrset, ctx) && rrset->type == KNOT_RRTYPE_ZONEMD) {
		return KNOT_EOK;
	}

	// ignore DNSSEC if verifying on signer
	if (ctx->ignore_dnssec && knot_rrtype_is_dnssec(rrset->type)) {
		return KNOT_EOK;
	}

	// ignore RRSIGs of apex ZONEMD
	if (rrset_is_apex(rrset, ctx) && rrset->type == KNOT_RRTYPE_RRSIG) {
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
	if (rrset_is_apex(rrset, ctx) && rrset->type == KNOT_RRTYPE_RRSIG) {
		knot_rdataset_clear(&rrset->rrs, NULL);
	}

	if (ret < 0) {
		return ret;
	}

	// digest serialized RRSet
	dnssec_binary_t bufbin = { ret, ctx->buf };
	assert(ctx->scheme == ZONEMD_SCHEME_SIMPLE || ctx->scheme == ZONEMD_SCHEME_RADIX);
	if (ctx->scheme == ZONEMD_SCHEME_SIMPLE) {
                return dnssec_digest(ctx->digest_ctx, &bufbin);
	}

	// per-RRset digest in case of incremental scheme
	dnssec_binary_t rrset_hash = { 0 };
	ret = dnssec_digest_fast(ctx->algorithm, &bufbin, &rrset_hash);
	ctx->digest_ctx = NULL;
	if (ctx->hr_tree->hash_len == 0) {
		assert(hr_tree_empty(ctx->hr_tree));
                ctx->hr_tree->hash_len = rrset_hash.size;
        }
	assert(rrset_hash.size == ctx->hr_tree->hash_len);
	if (ret == KNOT_EOK) {
		if (ctx->removals) {
			ret = hr_tree_rem(ctx->hr_tree, rrset_hash.data);
		} else {
			ret = hr_tree_add(ctx->hr_tree, rrset_hash.data);
		}
	}
	dnssec_binary_free(&rrset_hash);

	return ret;
}

static int digest_node(zone_node_t *node, void *ctx)
{
	int i = 0, ret = KNOT_EOK;
	for ( ; i < node->rrset_count && ret == KNOT_EOK; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		ret = digest_rrset(&rrset, ctx);
	}
	return ret;
}

int zone_contents_digest(struct zone_update *update, zone_contents_t *contents,
                         int algorithm, int scheme, bool ignore_dnssec, bool validation,
                         uint8_t **out_digest, size_t *out_size)
{
	if (out_digest == NULL || out_size == NULL || (contents != NULL && update != NULL) || (scheme != ZONEMD_SCHEME_SIMPLE && scheme != ZONEMD_SCHEME_RADIX)) {
		return KNOT_EINVAL;
	}

	if (contents == NULL && update == NULL) {
		return KNOT_EEMPTYZONE;
	}
	if (contents == NULL) {
                contents = update->new_cont;
	}

	contents_digest_ctx_t ctx = {
		.buf_size = DIGEST_BUF_MIN,
		.buf = malloc(DIGEST_BUF_MIN),
		.apex = contents->apex,
	        .hr_tree = zone_contents_zonemd_tree(contents, validation ? CONTENTS_ZONEMD_TREE_VALIDATE : CONTENTS_ZONEMD_TREE_GENERATE),
	        .algorithm = algorithm,
	        .scheme = scheme,
		.ignore_dnssec = ignore_dnssec,
		.allow_alg_change = true,
	};
	if (ctx.buf == NULL || ctx.hr_tree == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = KNOT_EOK;
	bool incremental = false;
	if (scheme > ZONEMD_SCHEME_SIMPLE && update != NULL && !(update->flags & UPDATE_FULL) && !hr_tree_empty(ctx.hr_tree) && ctx.hr_tree->algorithm == algorithm) {
		incremental = true;
	} else if (scheme == ZONEMD_SCHEME_RADIX) {
		hr_tree_clear(ctx.hr_tree);
		ctx.hr_tree->hash_len = 0;
		ctx.hr_tree->algorithm = algorithm;
	}

	if (scheme == ZONEMD_SCHEME_SIMPLE) {
                ret = dnssec_digest_init(algorithm, &ctx.digest_ctx);
                if (ret != KNOT_EOK) {
                        free(ctx.buf);
                        return ret;
		}
	}

	zone_tree_t *conts = contents->nodes;
	if (scheme == ZONEMD_SCHEME_SIMPLE && !zone_tree_is_empty(contents->nsec3_nodes)) {
		conts = zone_tree_shallow_copy(conts);
		if (conts == NULL) {
			ret = KNOT_ENOMEM;;
		}
		if (ret == KNOT_EOK) {
			ret = zone_tree_merge(conts, contents->nsec3_nodes);
		}
	}

	if (incremental && ret == KNOT_EOK) {
		ctx.removals = true;
		ret = zone_update_foreach(update, false, digest_rrset, &ctx);
		ctx.removals = false;
		if (ret == KNOT_EOK) {
			ret = zone_update_foreach(update, true, digest_rrset, &ctx);
		}
	} else if (ret == KNOT_EOK) {
		ret = zone_tree_apply(conts, digest_node, &ctx);
	}

	if (conts != contents->nodes) {
		zone_tree_free(&conts);
	}

	if (scheme == ZONEMD_SCHEME_RADIX && ret == KNOT_EOK) {
		assert(ctx.digest_ctx == NULL);
		ret = hr_tree_hash(ctx.hr_tree, rehash_2hashes, (void *)(intptr_t)algorithm, out_digest);
		*out_size = ctx.hr_tree->hash_len;
	} else if (ret == KNOT_EOK) {
		dnssec_binary_t res = { 0 };
		ret = dnssec_digest_finish(ctx.digest_ctx, &res);
		*out_digest = res.data;
		*out_size = res.size;
	} else {
		hr_tree_clear(ctx.hr_tree);
	}
	free(ctx.buf);
	return ret;
}

static int verify_zonemd(const knot_rdata_t *zonemd, zone_update_t *update,
                         zone_contents_t *contents, bool ignore_dnssec)
{
	uint8_t *computed = NULL;
	size_t comp_size = 0;
	int ret = zone_contents_digest(update, contents, knot_zonemd_algorithm(zonemd),
	                               knot_zonemd_scheme(zonemd),
	                               ignore_dnssec, true, &computed, &comp_size);
	if (ret != KNOT_EOK) {
		return ret;
	}
	assert(computed);

	if (comp_size != knot_zonemd_digest_size(zonemd)) {
		ret = KNOT_EFEWDATA;
	} else if (memcmp(knot_zonemd_digest(zonemd), computed, comp_size) != 0) {
		ret = KNOT_EMALF;
	}
	if (knot_zonemd_scheme(zonemd) == ZONEMD_SCHEME_SIMPLE) { // otherwise the hash is owner by the hash tree
                free(computed);
	}
	return ret;
}

bool zone_contents_digest_exists(struct zone_update *update, zone_contents_t *contents,
                                 int alg, bool no_verify, bool ignore_dnssec)
{
	if (alg == 0) {
		return true;
	}

	zone_node_t *apex = update == NULL ? contents->apex : update->new_cont->apex;
	knot_rdataset_t *zonemd = node_rdataset(apex, KNOT_RRTYPE_ZONEMD);

	if (alg == ZONE_DIGEST_REMOVE) {
		return (zonemd == NULL || zonemd->count == 0);
	}

	if (zonemd == NULL || zonemd->count != 1 || knot_zonemd_algorithm(zonemd->rdata) != alg) {
		return false;
	}

	if (no_verify) {
		return true;
	}

	return verify_zonemd(zonemd->rdata, update, contents, ignore_dnssec) == KNOT_EOK;
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

int zone_contents_digest_verify(struct zone_update *update, zone_contents_t *contents, bool ignore_dnssec)
{
	if (update != NULL && contents != NULL) {
		return KNOT_EINVAL;
	}

	if (contents == NULL && update == NULL) {
		return KNOT_EEMPTYZONE;
	}

	zone_node_t *apex = update == NULL ? contents->apex : update->new_cont->apex;
	knot_rdataset_t *zonemd = node_rdataset(apex, KNOT_RRTYPE_ZONEMD);
	if (zonemd == NULL) {
		return KNOT_ENOENT;
	}

	uint32_t soa_serial = zone_contents_serial(update == NULL ? contents: update->new_cont);

	knot_rdata_t *rr = zonemd->rdata, *supported = NULL;
	for (int i = 0; i < zonemd->count; i++) {
		if ((knot_zonemd_scheme(rr) == ZONEMD_SCHEME_SIMPLE || knot_zonemd_scheme(rr) == ZONEMD_SCHEME_RADIX) &&
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

	return supported == NULL ? KNOT_ENOTSUP : verify_zonemd(supported, update, contents, ignore_dnssec);
}

static ptrdiff_t zonemd_hash_offs(void)
{
	knot_rdata_t fake = { 0 };
	return knot_zonemd_digest(&fake) - fake.data;
}

int zone_update_add_digest(conf_t *conf, struct zone_update *update, int algorithm, bool placeholder)
{
	if (update == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t zero = 0, *digest = &zero;
	size_t dsize = sizeof(zero);
	conf_val_t scheme = conf_zone_get(conf, C_ZONEMD_SCHEME, update->zone->name);

	knot_rrset_t exists = node_rrset(update->new_cont->apex, KNOT_RRTYPE_ZONEMD);
	if (algorithm == ZONE_DIGEST_REMOVE) {
		return zone_update_remove(update, &exists);
	}
	if (placeholder) {
		if (!knot_rrset_empty(&exists) &&
		    !check_duplicate_schalg(&exists.rrs, exists.rrs.count,
		                            conf_opt(&scheme), algorithm)) {
			return KNOT_EOK;
		}
	} else {

		int ret = zone_contents_digest(update, NULL, algorithm, conf_opt(&scheme), false, false, &digest, &dsize);
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

	knot_rrset_t zonemd, soa = node_rrset(update->new_cont->apex, KNOT_RRTYPE_SOA);

	uint8_t rdata[zonemd_hash_offs() + dsize];
	wire_ctx_t wire = wire_ctx_init(rdata, sizeof(rdata));
	wire_ctx_write_u32(&wire, knot_soa_serial(soa.rrs.rdata));
	wire_ctx_write_u8(&wire, conf_opt(&scheme));
	wire_ctx_write_u8(&wire, algorithm);
	wire_ctx_write(&wire, digest, dsize);
	assert(wire.error == KNOT_EOK && wire_ctx_available(&wire) == 0);

	if (digest != &zero && conf_opt(&scheme) == ZONEMD_SCHEME_SIMPLE) {
		free(digest);
	}

	knot_rrset_init(&zonemd, update->new_cont->apex->owner, KNOT_RRTYPE_ZONEMD,
	                KNOT_CLASS_IN, soa.ttl);
	int ret = knot_rrset_add_rdata(&zonemd, rdata, sizeof(rdata), NULL);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = zone_update_add(update, &zonemd);
	knot_rdataset_clear(&zonemd.rrs, NULL);
	return ret;
}
