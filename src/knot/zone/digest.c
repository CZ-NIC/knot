/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/zone/digest.h"

#include <stdio.h>

#include "libdnssec/digest.h"
#include "libknot/error.h"
#include "libknot/packet/rrset-wire.h"
#include "libknot/rrtype/rrsig.h"
#include "libknot/rrtype/zonemd.h"
#include "knot/dnssec/rrset-sign.h" // only knot_synth_rrsig()

#define DIGEST_BUF_MIN 4096
#define DIGEST_BUF_MAX (40 * 1024 * 1024)

typedef struct {
	size_t buf_size;
	uint8_t *buf;
	struct dnssec_digest_ctx *digest_ctx;
	const zone_node_t *apex;
} contents_digest_ctx_t;

static int digest_rrset(knot_rrset_t *rrset, const zone_node_t *node, void *vctx)
{
	contents_digest_ctx_t *ctx = vctx;

	// ignore apex ZONEMD
	if (node == ctx->apex && rrset->type == KNOT_RRTYPE_ZONEMD) {
		return KNOT_EOK;
	}

	// ignore RRSIGs of apex ZONEMD
	if (node == ctx->apex && rrset->type == KNOT_RRTYPE_RRSIG) {
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

	// serialize RRSet, expand buf as needed
	int ret = knot_rrset_to_wire_extra(rrset, ctx->buf, ctx->buf_size, 0,
	                                   NULL, KNOT_PF_ORIGTTL);
	while (ret == KNOT_ESPACE && ctx->buf_size < DIGEST_BUF_MAX) {
		free(ctx->buf);
		ctx->buf_size *= 2;
		ctx->buf = malloc(ctx->buf_size);
		if (ctx->buf == NULL) {
			return KNOT_ENOMEM;
		}
		ret = knot_rrset_to_wire_extra(rrset, ctx->buf, ctx->buf_size, 0,
		                               NULL, KNOT_PF_ORIGTTL);
	}

	// cleanup apex RRSIGs mess
	if (node == ctx->apex && rrset->type == KNOT_RRTYPE_RRSIG) {
		knot_rdataset_clear(&rrset->rrs, NULL);
	}

	if (ret < 0) {
		return ret;
	}

	// digest serialized RRSet
	dnssec_binary_t bufbin = { ret, ctx->buf };
	return dnssec_digest(ctx->digest_ctx, &bufbin);
}

static int digest_node(zone_node_t *node, void *ctx)
{
	int i = 0, ret = KNOT_EOK;
	for ( ; i < node->rrset_count && ret == KNOT_EOK; i++) {
		knot_rrset_t rrset = node_rrset_at(node, i);
		ret = digest_rrset(&rrset, node, ctx);
	}
	return ret;
}

int zone_contents_digest(const zone_contents_t *contents, int algorithm, uint8_t **out_digest, size_t *out_size)
{
	if (contents == NULL || out_digest == NULL || out_size == NULL) {
		return KNOT_EINVAL;
	}

	contents_digest_ctx_t ctx = {
		.buf_size = DIGEST_BUF_MIN,
		.buf = malloc(DIGEST_BUF_MIN),
		.apex = contents->apex,
	};
	if (ctx.buf == NULL) {
		return KNOT_ENOMEM;
	}

	int ret = dnssec_digest_init(algorithm, &ctx.digest_ctx);
	if (ret != DNSSEC_EOK) {
		free(ctx.buf);
		return knot_error_from_libdnssec(ret);
	}

	ret = zone_contents_apply((zone_contents_t *)contents, digest_node, &ctx);
	if (ret == KNOT_EOK) {
		ret = zone_contents_nsec3_apply((zone_contents_t *)contents, digest_node, &ctx);
	}

	dnssec_binary_t res = { 0 };
	if (ret == KNOT_EOK) {
		ret = dnssec_digest_finish(ctx.digest_ctx, &res);
	}
	free(ctx.buf);
	*out_digest = res.data;
	*out_size = res.size;
	return ret;
}

static int verify_zonemd(const knot_rdata_t *zonemd, const zone_contents_t *contents)
{
	uint8_t *computed = NULL;
	size_t comp_size = 0;
	int ret = zone_contents_digest(contents, knot_zonemd_algorithm(zonemd),
	                               &computed, &comp_size);
	if (ret != KNOT_EOK) {
		return ret;
	}

	if (comp_size != knot_zonemd_digest_size(zonemd)) {
		ret = KNOT_EFEWDATA;
	} else if (memcmp(knot_zonemd_digest(zonemd), computed, comp_size) != 0) {
		ret = KNOT_EMALF;
	}
	free(computed);
	return ret;
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

int zone_contents_digest_verify(const zone_contents_t *contents)
{
	if (contents == NULL) {
		return KNOT_EINVAL;
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

	return supported == NULL ? KNOT_ENOTSUP : verify_zonemd(supported, contents);
}
