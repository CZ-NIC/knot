/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdint.h>
#include <stdlib.h>

#include "libknot/errcode.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/tsig-op.h"
#include "knot/nameserver/tsig_ctx.h"

void tsig_init(tsig_ctx_t *ctx, const knot_tsig_key_t *key)
{
	if (!ctx) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->key = key;
}

int tsig_sign_packet(tsig_ctx_t *ctx, knot_pkt_t *packet)
{
	if (!ctx || !packet) {
		return KNOT_EINVAL;
	}

	if (ctx->key == NULL) {
		return KNOT_EOK;
	}

	int ret = KNOT_ERROR;
	if (ctx->digest_size == 0) {
		ctx->digest_size = knot_tsig_digest_length(ctx->key->algorithm);
		ret = knot_tsig_sign(packet->wire, &packet->size, packet->max_size,
		                     NULL, 0,
		                     ctx->digest, &ctx->digest_size,
		                     ctx->key, 0, 0);
	} else {
		uint8_t previous_digest[ctx->digest_size];
		memcpy(previous_digest, ctx->digest, ctx->digest_size);

		ret = knot_tsig_sign_next(packet->wire, &packet->size, packet->max_size,
		                          previous_digest, ctx->digest_size,
		                          ctx->digest, &ctx->digest_size,
		                          ctx->key, packet->wire, packet->size);
	}

	return ret;
}

static int update_ctx_after_verify(tsig_ctx_t *ctx, knot_rrset_t *tsig_rr)
{
	assert(ctx);
	assert(tsig_rr);

	if (ctx->digest_size != tsig_rdata_mac_length(tsig_rr)) {
		return KNOT_EMALF;
	}

	memcpy(ctx->digest, tsig_rdata_mac(tsig_rr), ctx->digest_size);
	ctx->prev_signed_time = tsig_rdata_time_signed(tsig_rr);
	ctx->unsigned_count = 0;

	return KNOT_EOK;
}

int tsig_verify_packet(tsig_ctx_t *ctx, knot_pkt_t *packet)
{
	if (!ctx || !packet) {
		return KNOT_EINVAL;
	}

	if (ctx->key == NULL) {
		return KNOT_EOK;
	}

	if (packet->tsig_rr == NULL) {
		ctx->unsigned_count += 1;
		return KNOT_EOK;
	}

	int ret = KNOT_ERROR;
	if (ctx->prev_signed_time == 0) {
		ret = knot_tsig_client_check(packet->tsig_rr, packet->wire,
		                             packet->size, ctx->digest,
		                             ctx->digest_size, ctx->key, 0);
	} else {
		ret = knot_tsig_client_check_next(packet->tsig_rr, packet->wire,
		                                  packet->size, ctx->digest,
		                                  ctx->digest_size, ctx->key,
		                                  ctx->prev_signed_time);
	}

	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = update_ctx_after_verify(ctx, packet->tsig_rr);
	if (ret != KNOT_EOK) {
		return ret;
	}

	return KNOT_EOK;
}

unsigned tsig_unsigned_count(tsig_ctx_t *ctx)
{
	if (!ctx) {
		return -1;
	}

	return ctx->unsigned_count;
}
