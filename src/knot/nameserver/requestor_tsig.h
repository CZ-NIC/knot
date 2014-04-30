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

#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "libknot/packet/pkt.h"
#include "libknot/rdata/tsig.h"

typedef struct requestor_tsig_ctx {
	const knot_tsig_key_t *key;
	uint8_t *digest;
	size_t digest_size;
} requestor_tsig_ctx_t;

void requestor_tsig_init(requestor_tsig_ctx_t *ctx, const knot_tsig_key_t *key);

void requestor_tsig_cleanup(requestor_tsig_ctx_t *ctx);

int requestor_tsig_sign_packet(requestor_tsig_ctx_t *ctx, knot_pkt_t *packet);

int requestor_tsig_verify_packet(requestor_tsig_ctx_t *ctx, knot_pkt_t *packet);
