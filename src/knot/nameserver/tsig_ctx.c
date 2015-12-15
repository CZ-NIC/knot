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

#include <assert.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "libknot/libknot.h"
#include "libknot/rrtype/tsig.h"
#include "libknot/tsig-op.h"
#include "knot/nameserver/tsig_ctx.h"

/*!
 * Maximal total size for unsigned messages.
 */
static const size_t TSIG_BUFFER_MAX_SIZE = (UINT16_MAX * 100);

void tsig_init(tsig_ctx_t *ctx, const knot_tsig_key_t *key)
{
	if (!ctx) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->key = key;
}

void tsig_cleanup(tsig_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	free(ctx->buffer);
	memset(ctx, 0, sizeof(*ctx));
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
		ctx->digest_size = dnssec_tsig_algorithm_size(ctx->key->algorithm);
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

	if (ctx->digest_size != knot_tsig_rdata_mac_length(tsig_rr)) {
		return KNOT_EMALF;
	}

	memcpy(ctx->digest, knot_tsig_rdata_mac(tsig_rr), ctx->digest_size);
	ctx->prev_signed_time = knot_tsig_rdata_time_signed(tsig_rr);
	ctx->unsigned_count = 0;
	ctx->buffer_used = 0;

	return KNOT_EOK;
}

static int buffer_add_packet(tsig_ctx_t *ctx, knot_pkt_t *packet)
{
	size_t need = ctx->buffer_used + packet->size;

	// Inflate the buffer if necessary.

	if (need > TSIG_BUFFER_MAX_SIZE) {
		return KNOT_ENOMEM;
	}

	if (need > ctx->buffer_size) {
		uint8_t *buffer = realloc(ctx->buffer, need);
		if (!buffer) {
			return KNOT_ENOMEM;
		}

		ctx->buffer = buffer;
		ctx->buffer_size = need;
	}

	// Buffer the packet.

	uint8_t *write = ctx->buffer + ctx->buffer_used;
	memcpy(write, packet->wire, packet->size);
	ctx->buffer_used = need;

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

	int ret = buffer_add_packet(ctx, packet);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Unsigned packet.

	if (packet->tsig_rr == NULL) {
		ctx->unsigned_count += 1;
		return KNOT_EOK;
	}

	// Signed packet.

	if (ctx->prev_signed_time == 0) {
		ret = knot_tsig_client_check(packet->tsig_rr, ctx->buffer,
		                             ctx->buffer_used, ctx->digest,
		                             ctx->digest_size, ctx->key, 0);
	} else {
		ret = knot_tsig_client_check_next(packet->tsig_rr, ctx->buffer,
		                                  ctx->buffer_used, ctx->digest,
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
