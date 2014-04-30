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

#include "common/errcode.h"
#include "libknot/rdata/tsig.h"
#include "libknot/tsig-op.h"
#include "knot/nameserver/requestor_tsig.h"

void requestor_tsig_init(requestor_tsig_ctx_t *ctx, const knot_tsig_key_t *key)
{
	if (!ctx) {
		return;
	}

	memset(ctx, 0, sizeof(*ctx));
	ctx->key = key;
}

void requestor_tsig_cleanup(requestor_tsig_ctx_t *ctx)
{
	if (!ctx) {
		return;
	}

	free(ctx->digest);
	memset(ctx, 0, sizeof(*ctx));
}

int requestor_tsig_sign_packet(requestor_tsig_ctx_t *ctx, knot_pkt_t *packet)
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
		ctx->digest = malloc(ctx->digest_size);
		if (!ctx->digest) {
			return KNOT_ENOMEM;
		}

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

int requestor_tsig_verify_packet(requestor_tsig_ctx_t *ctx, knot_pkt_t *packet)
{
	if (!ctx || !packet) {
		return KNOT_EINVAL;
	}

	if (ctx->key == NULL) {
		return KNOT_EOK;
	}

	#warning "TODO: TSIG verify invocation."
	//return KNOT_ENOTSUP;
	return KNOT_EOK;
}
