/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "libknot/packet/pkt.h"
#include "libknot/tsig.h"

/*!
 * \brief Holds data required between signing and signature verification.
 */
struct sign_context {
	size_t digest_size;
	uint8_t *digest;
	const knot_tsig_key_t *tsig_key;
};

typedef struct sign_context sign_context_t;

/*!
 * \brief Initialize signing context for TSIG.
 */
int sign_context_init_tsig(sign_context_t *ctx, const knot_tsig_key_t *key);

/*!
 * \brief Clean up signing context.
 *
 * \param ctx  Sign context.
 */
void sign_context_deinit(sign_context_t *ctx);

/*!
 * \brief Signs outgoing DNS packet.
 *
 * \param pkt       Packet to sign.
 * \param sign_ctx  Signing context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int sign_packet(knot_pkt_t *pkt, sign_context_t *sign_ctx);

/*!
 * \brief Verifies signature for incoming DNS packet.
 *
 * \param pkt       Packet verify sign.
 * \param sign_ctx  Signing context.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int verify_packet(const knot_pkt_t *pkt, const sign_context_t *sign_ctx);
