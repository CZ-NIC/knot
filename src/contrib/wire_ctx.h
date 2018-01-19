/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "libknot/endian.h"
#include "libknot/errcode.h"

/*!
 * \brief Struct to keep the wire context.
 */
typedef struct wire_ctx {
	size_t size;
	uint8_t *wire;
	uint8_t *position;
	int error;
	bool readonly;
} wire_ctx_t;

/*!
 * \brief Initialize wire context.
 */
static inline wire_ctx_t wire_ctx_init(uint8_t *data, size_t size)
{
	assert(data);

	wire_ctx_t result = {
		.size = size,
		.wire = data,
		.position = data,
		.error = KNOT_EOK,
		.readonly = false
	};

	return result;
}

/*!
 * \brief Initialize read only wire context.
 *
 * \note No write is performed, and error is set to KNOT_EACCES.
 *
 */
static inline wire_ctx_t wire_ctx_init_const(const uint8_t *data, size_t size)
{
	assert(data);

	wire_ctx_t result = wire_ctx_init((uint8_t *)data, size);
	result.readonly = true;

	return result;
}

/*!
 * \brief Gets actual position.
 *
 * \return position from the begin.
 */
static inline size_t wire_ctx_offset(wire_ctx_t *ctx)
{
	assert(ctx);

	return ctx->position - ctx->wire;
}

/*!
 * \brief Set position offset from the begin.
 *
 * \param offset Wire offset (starts from 0).
 *
 * \note Noop if previous error.
 */
static inline void wire_ctx_set_offset(wire_ctx_t *ctx, size_t offset)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return;
	}

	if (offset > ctx->size) {
		ctx->error = KNOT_ERANGE;
		return;
	}

	ctx->position = ctx->wire + offset;
}

/*!
 * \brief Gets available bytes.
 *
 * \return Number of bytes to end.
 */
static inline size_t wire_ctx_available(wire_ctx_t *ctx)
{
	assert(ctx);

	return ctx->size - wire_ctx_offset(ctx);
}

/*!
 * \brief Add offset to the current position.
 *
 * \note Noop if previous error.
 */
static inline void wire_ctx_skip(wire_ctx_t *ctx, ssize_t offset)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return;
	}

	// Check for out of scope skip.
	if (offset >= 0) {
		if (offset > wire_ctx_available(ctx)) {
			ctx->error = KNOT_ERANGE;
			return;
		}
	} else {
		if (-offset > wire_ctx_offset(ctx)) {
			ctx->error = KNOT_ERANGE;
			return;
		}
	}

	ctx->position += offset;
}

/*!
 * \brief Check the context if reading is possible.
 */
static inline int wire_ctx_can_read(wire_ctx_t *ctx, size_t size)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return ctx->error;
	}

	if (wire_ctx_available(ctx) < size) {
		return KNOT_EFEWDATA;
	}

	return KNOT_EOK;
}

/*!
 * \brief Check the context if writing is possible.
 */
static inline int wire_ctx_can_write(wire_ctx_t *ctx, size_t size)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return ctx->error;
	}

	if (ctx->readonly) {
		return KNOT_EACCES;
	}

	if (wire_ctx_available(ctx) < size) {
		return KNOT_ESPACE;
	}

	return KNOT_EOK;
}


static inline void wire_ctx_read(wire_ctx_t *ctx, void *data, size_t size)
{
	assert(ctx);
	assert(data);

	if (ctx->error != KNOT_EOK) {
		/* Avoid leaving data uninitialized. */
		memset(data, 0, size);
		return;
	}

	int ret = wire_ctx_can_read(ctx, size);
	if (ret != KNOT_EOK) {
		ctx->error = ret;
		memset(data, 0, size);
		return;
	}

	memcpy(data, ctx->position, size);
	ctx->position += size;
}

static inline uint8_t wire_ctx_read_u8(wire_ctx_t *ctx)
{
	uint8_t result;
	wire_ctx_read(ctx, &result, sizeof(result));

	return result;
}

static inline uint16_t wire_ctx_read_u16(wire_ctx_t *ctx)
{
	uint16_t result;
	wire_ctx_read(ctx, &result, sizeof(result));

	return be16toh(result);
}

static inline uint32_t wire_ctx_read_u32(wire_ctx_t *ctx)
{
	uint32_t result;
	wire_ctx_read(ctx, &result, sizeof(result));

	return be32toh(result);
}

static inline uint64_t wire_ctx_read_u48(wire_ctx_t *ctx)
{
	/* This case is slightly tricky. */
	uint64_t result = 0;
	wire_ctx_read(ctx, (uint8_t *)&result + 1, 6);

	return be64toh(result) >> 8;
}

static inline uint64_t wire_ctx_read_u64(wire_ctx_t *ctx)
{
	uint64_t result;
	wire_ctx_read(ctx, &result, sizeof(result));

	return be64toh(result);
}


static inline void wire_ctx_write(wire_ctx_t *ctx, const void *data, size_t size)
{
	assert(ctx);

	if (ctx->error != KNOT_EOK) {
		return;
	}

	if (size == 0) {
		return;
	}

	assert(data);

	int ret = wire_ctx_can_write(ctx, size);
	if (ret != KNOT_EOK) {
		ctx->error = ret;
		return;
	}

	memcpy(ctx->position, data, size);
	ctx->position += size;
}

static inline void wire_ctx_write_u8(wire_ctx_t *ctx, uint8_t value)
{
	wire_ctx_write(ctx, &value, sizeof(value));
}

static inline void wire_ctx_write_u16(wire_ctx_t *ctx, uint16_t value)
{
	uint16_t beval = htobe16(value);
	wire_ctx_write(ctx, &beval, sizeof(beval));
}

static inline void wire_ctx_write_u32(wire_ctx_t *ctx, uint32_t value)
{
	uint32_t beval = htobe32(value);
	wire_ctx_write(ctx, &beval, sizeof(beval));
}

static inline void wire_ctx_write_u48(wire_ctx_t *ctx, uint64_t value)
{
	/* This case is slightly tricky. */
	uint64_t swapped = htobe64(value << 8);
	wire_ctx_write(ctx, (uint8_t *)&swapped + 1, 6);
}

static inline void wire_ctx_write_u64(wire_ctx_t *ctx, uint64_t value)
{
	uint64_t beval = htobe64(value);
	wire_ctx_write(ctx, &beval, sizeof(beval));
}


static inline void wire_ctx_memset(wire_ctx_t *dst, int value, size_t size)
{
	assert(dst);

	if (dst->error != KNOT_EOK) {
		return;
	}

	if (size == 0) {
		return;
	}

	int ret = wire_ctx_can_write(dst, size);
	if (ret != KNOT_EOK) {
		dst->error = ret;
		return;
	}

	memset(dst->position, value, size);
	dst->position += size;
}

static inline void wire_ctx_clear(wire_ctx_t *ctx, size_t size)
{
	wire_ctx_memset(ctx, 0, size);
}

static inline void wire_ctx_copy(wire_ctx_t *dst, wire_ctx_t *src, size_t size)
{
	assert(dst);
	assert(src);

	if (size == 0 || dst->error != KNOT_EOK) {
		return;
	}

	if (wire_ctx_can_read(src, size) != KNOT_EOK) {
		dst->error = KNOT_EFEWDATA;
		return;
	}

	int ret = wire_ctx_can_write(dst, size);
	if (ret != KNOT_EOK) {
		dst->error = ret;
		return;
	}

	memcpy(dst->position, src->position, size);
	dst->position += size;
	src->position += size;
}

