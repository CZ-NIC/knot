/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include "libknot/dnssec/digest.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

#include "libknot/dnssec/shared/shared.h"

struct dnssec_digest_ctx {
	gnutls_hash_hd_t gtctx;
	unsigned size;
};

static gnutls_digest_algorithm_t lookup_algorithm(dnssec_digest_t algorithm)
{
	switch (algorithm) {
	case DNSSEC_DIGEST_SHA384: return GNUTLS_DIG_SHA384;
	case DNSSEC_DIGEST_SHA512: return GNUTLS_DIG_SHA512;
	default:
		return GNUTLS_DIG_UNKNOWN;
	};
}

_public_
int dnssec_digest_init(dnssec_digest_t algorithm, dnssec_digest_ctx_t **out_ctx)
{
	if (out_ctx == NULL) {
		return DNSSEC_EINVAL;
	}

	gnutls_digest_algorithm_t gtalg = lookup_algorithm(algorithm);
	if (gtalg == GNUTLS_DIG_UNKNOWN) {
		return DNSSEC_INVALID_DIGEST_ALGORITHM;
	}

	dnssec_digest_ctx_t *res = malloc(sizeof(*res));
	if (res == NULL) {
		return KNOT_ENOMEM;
	}

	res->size = gnutls_hash_get_len(gtalg);
	if (res->size == 0 || gnutls_hash_init(&res->gtctx, gtalg) < 0) {
		free(res);
		return DNSSEC_DIGEST_ERROR;
	}

	*out_ctx = res;
	return KNOT_EOK;
}

static void digest_ctx_free(dnssec_digest_ctx_t *ctx)
{
	free_gnutls_hash_ptr(&ctx->gtctx);
	free(ctx);
}

_public_
int dnssec_digest(dnssec_digest_ctx_t *ctx, dnssec_binary_t *data)
{
	if (ctx == NULL || data == NULL) {
		return DNSSEC_EINVAL;
	}

	int r = gnutls_hash(ctx->gtctx, data->data, data->size);
	if (r != 0) {
		digest_ctx_free(ctx);
		return DNSSEC_DIGEST_ERROR;
	}
	return KNOT_EOK;
}

_public_
int dnssec_digest_finish(dnssec_digest_ctx_t *ctx, dnssec_binary_t *out)
{
	if (ctx == NULL || out == NULL) {
		return DNSSEC_EINVAL;
	}

	int r = dnssec_binary_resize(out, ctx->size);
	if (r < 0) {
		dnssec_binary_free(out);
		digest_ctx_free(ctx);
		return r;
	}

	gnutls_hash_output(ctx->gtctx, out->data);

	digest_ctx_free(ctx);
	return KNOT_EOK;
}
