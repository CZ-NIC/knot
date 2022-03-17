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

#include <stdio.h>

#include "knot/zone/digest.h"
#include "knot/dnssec/rrset-sign.h"
#include "knot/updates/zone-update.h"
#include "contrib/wire_ctx.h"
#include "libdnssec/digest.h"
#include "libknot/libknot.h"

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

int zone_contents_digest(const zone_contents_t *contents, int algorithm,
                         uint8_t **out_digest, size_t *out_size)
{
	if (out_digest == NULL || out_size == NULL) {
		return KNOT_EINVAL;
	}

	if (contents == NULL) {
		return KNOT_EEMPTYZONE;
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

	zone_tree_t *conts = contents->nodes;
	if (!zone_tree_is_empty(contents->nsec3_nodes)) {
		conts = zone_tree_shallow_copy(conts);
		if (conts == NULL) {
			ret = KNOT_ENOMEM;;
		}
		if (ret == KNOT_EOK) {
			ret = zone_tree_merge(conts, contents->nsec3_nodes);
		}
	}

	if (ret == KNOT_EOK) {
		ret = zone_tree_apply(conts, digest_node, &ctx);
	}

	if (conts != contents->nodes) {
		zone_tree_free(&conts);
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
	assert(computed);

	if (comp_size != knot_zonemd_digest_size(zonemd)) {
		ret = KNOT_EFEWDATA;
	} else if (memcmp(knot_zonemd_digest(zonemd), computed, comp_size) != 0) {
		ret = KNOT_EMALF;
	}
	free(computed);
	return ret;
}

bool zone_contents_digest_exists(const zone_contents_t *contents, int alg, bool no_verify)
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

	return verify_zonemd(zonemd->rdata, contents) == KNOT_EOK;
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

	return supported == NULL ? KNOT_ENOTSUP : verify_zonemd(supported, contents);
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

	uint8_t *digest = NULL;
	size_t dsize = 0;

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
		int ret = zone_contents_digest(update->new_cont, algorithm, &digest, &dsize);
		if (ret != KNOT_EOK) {
			return ret;
		}

		ret = zone_update_remove(update, &exists);
		if (ret != KNOT_EOK && ret != KNOT_ENOENT) {
			free(digest);
			return ret;
		}
	}

	knot_rrset_t zonemd, soa = node_rrset(update->new_cont->apex, KNOT_RRTYPE_SOA);

	uint8_t rdata[zonemd_hash_offs() + dsize];
	wire_ctx_t wire = wire_ctx_init(rdata, sizeof(rdata));
	wire_ctx_write_u32(&wire, knot_soa_serial(soa.rrs.rdata));
	wire_ctx_write_u8(&wire, KNOT_ZONEMD_SCHEME_SIMPLE);
	wire_ctx_write_u8(&wire, algorithm);
	wire_ctx_write(&wire, digest, dsize);
	assert(wire.error == KNOT_EOK && wire_ctx_available(&wire) == 0);

	free(digest);

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
