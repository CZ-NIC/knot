/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "utils/common/sign.h"
#include "libknot/errcode.h"
#include "libknot/tsig-op.h"

int sign_context_init_tsig(sign_context_t *ctx, const knot_tsig_key_t *key)
{
	if (!ctx || !key) {
		return KNOT_EINVAL;
	}

	size_t digest_size = dnssec_tsig_algorithm_size(key->algorithm);
	if (digest_size == 0) {
		return KNOT_EINVAL;
	}

	uint8_t *digest = calloc(1, digest_size);
	if (!digest) {
		return KNOT_ENOMEM;
	}

	ctx->digest_size = digest_size;
	ctx->digest = digest;
	ctx->tsig_key = key;

	return KNOT_EOK;
}

void sign_context_deinit(sign_context_t *ctx)
{
	if (!ctx) {
		return;
	}

	free(ctx->digest);

	memset(ctx, 0, sizeof(*ctx));
}

int sign_packet(knot_pkt_t *pkt, sign_context_t *sign_ctx)
{
	if (pkt == NULL || sign_ctx == NULL || sign_ctx->digest == NULL) {
		return KNOT_EINVAL;
	}

	uint8_t *wire = pkt->wire;
	size_t  *wire_size = &pkt->size;
	size_t  max_size = pkt->max_size;

	knot_pkt_reserve(pkt, knot_tsig_wire_size(sign_ctx->tsig_key));

	return knot_tsig_sign(wire, wire_size, max_size, NULL, 0,
	                      sign_ctx->digest, &sign_ctx->digest_size,
	                      sign_ctx->tsig_key, 0, 0);
}

int verify_packet(const knot_pkt_t *pkt, const sign_context_t *sign_ctx)
{
	if (pkt == NULL || sign_ctx == NULL || sign_ctx->digest == NULL) {
		return KNOT_EINVAL;
	}

	const uint8_t *wire = pkt->wire;
	const size_t  *wire_size = &pkt->size;

	if (pkt->tsig_rr == NULL) {
		return KNOT_ENOTSIG;
	}

	int ret = knot_tsig_client_check(pkt->tsig_rr, wire, *wire_size,
	                                 sign_ctx->digest, sign_ctx->digest_size,
	                                 sign_ctx->tsig_key, 0);
	if (ret != KNOT_EOK) {
		return ret;
	}

	switch (knot_tsig_rdata_error(pkt->tsig_rr)) {
	case KNOT_RCODE_BADSIG:
		return KNOT_TSIG_EBADSIG;
	case KNOT_RCODE_BADKEY:
		return KNOT_TSIG_EBADKEY;
	case KNOT_RCODE_BADTIME:
		return KNOT_TSIG_EBADTIME;
	case KNOT_RCODE_BADTRUNC:
		return KNOT_TSIG_EBADTRUNC;
	default:
		return KNOT_EOK;
	}
}
