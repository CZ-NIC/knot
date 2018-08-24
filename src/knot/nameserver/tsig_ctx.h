/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include <stdint.h>

#include "libknot/packet/pkt.h"
#include "libknot/tsig.h"

#define TSIG_MAX_DIGEST_SIZE 64

/*!
  \brief TSIG context.
 */
typedef struct tsig_ctx {
	const knot_tsig_key_t *key;
	uint64_t prev_signed_time;

	uint8_t digest[TSIG_MAX_DIGEST_SIZE];
	size_t digest_size;

	/* Unsigned packets handling. */
	unsigned unsigned_count;
	uint8_t *buffer;
	size_t buffer_used;
	size_t buffer_size;
} tsig_ctx_t;

/*!
 * \brief Initialize TSIG context.
 *
 * \param ctx  TSIG context to be initialized.
 * \param key  Key to be used for signing. If NULL, all performed operations
 *             will do nothing and always successful.
 */
void tsig_init(tsig_ctx_t *ctx, const knot_tsig_key_t *key);

/*!
 * \brief Cleanup TSIG context.
 *
 * \param ctx TSIG context to be cleaned up.
 */
void tsig_cleanup(tsig_ctx_t *ctx);

/*!
 * \brief Reset TSIG context for new message exchange.
 */
void tsig_reset(tsig_ctx_t *ctx);

/*!
 * \brief Sign outgoing packet.
 *
 * \param ctx     TSIG signing context.
 * \param packet  Packet to be signed.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int tsig_sign_packet(tsig_ctx_t *ctx, knot_pkt_t *packet);

/*!
 * \brief Verify incoming packet.
 *
 * If the packet is not signed, the function will succeed, but an internal
 * counter of unsigned packets is increased. When a packet is signed, the
 * same counter is reset to zero.
 *
 * \see tsig_unsigned_count
 *
 * \param ctx     TSIG signing context.
 * \param packet  Packet to be verified.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int tsig_verify_packet(tsig_ctx_t *ctx, knot_pkt_t *packet);

/*!
 * \brief Get number of unsigned packets since the last signed one.
 *
 * \param ctx  TSIG signing context.
 *
 * \return Number of unsigned packets since the last signed one.
 */
unsigned tsig_unsigned_count(tsig_ctx_t *ctx);
