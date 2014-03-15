#pragma once

#include <arpa/inet.h>
#include <assert.h>
#include <gnutls/gnutls.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"
#include "shared.h"

typedef struct wire_ctx {
	uint8_t *wire;
	size_t size;
	uint8_t *position;
} wire_ctx_t;

static inline void wire_init(wire_ctx_t *ctx, uint8_t *wire, size_t size)
{
	assert(ctx);
	assert(wire);

	clear_struct(ctx);
	ctx->wire = wire;
	ctx->size = size;
	ctx->position = wire;
}

static inline void wire_init_binary(wire_ctx_t *ctx, const dnssec_binary_t *wire)
{
	assert(wire);

	wire_init(ctx, wire->data, wire->size);
}

static inline void wire_seek(wire_ctx_t *ctx, size_t offset)
{
	assert(ctx);

	ctx->position = ctx->wire + offset;
}

static inline size_t wire_tell(wire_ctx_t *ctx)
{
	assert(ctx);

	return ctx->position - ctx->wire;
}

static inline size_t wire_available(wire_ctx_t *ctx)
{
	assert(ctx);

	size_t position = wire_tell(ctx);

	return ctx->size > position ? (ctx->size - position) : 0;
}

static inline uint8_t wire_read_u8(wire_ctx_t *ctx)
{
	assert(ctx);

	uint8_t result = *ctx->position;
	ctx->position += 1;

	return result;
}

static inline uint16_t wire_read_u16(wire_ctx_t *ctx)
{
	assert(ctx);

	uint16_t result = *((uint16_t *)ctx->position);
	ctx->position += 2;

	return ntohs(result);
}

static inline void wire_read(wire_ctx_t *ctx, uint8_t *data, size_t size)
{
	assert(ctx);
	assert(data);

	memcpy(data, ctx->position, size);
	ctx->position += size;
}

static inline void wire_read_binary(wire_ctx_t *ctx, dnssec_binary_t *data)
{
	assert(data);

	wire_read(ctx, data->data, data->size);
}

static inline void wire_read_datum(wire_ctx_t *ctx, gnutls_datum_t *data)
{
	assert(data);

	wire_read(ctx, data->data, data->size);
}

static inline void wire_write_u8(wire_ctx_t *ctx, uint8_t value)
{
	assert(ctx);

	*ctx->position = value;
	ctx->position += 1;
}

static inline void wire_write_u16(wire_ctx_t *ctx, uint16_t value)
{
	assert(ctx);

	*((uint16_t *)ctx->position) = htons(value);
	ctx->position += 2;
}

static inline void wire_write(wire_ctx_t *ctx, const uint8_t *data, size_t size)
{
	assert(ctx);
	assert(data);

	memcpy(ctx->position, data, size);
	ctx->position += size;
}

static inline void wire_write_binary(wire_ctx_t *ctx, const dnssec_binary_t *data)
{
	assert(data);

	wire_write(ctx, data->data, data->size);
}

static inline void wire_write_ralign(wire_ctx_t *ctx, size_t width,
				     const uint8_t *data, size_t size)
{
	assert(ctx);
	assert(data);
	assert(width >= size);

	size_t padding = width - size;
	if (padding > 0) {
		memset(ctx->position, 0, padding);
		ctx->position += padding;
	}

	wire_write(ctx, data, size);
}

static inline void wire_write_ralign_binary(wire_ctx_t *ctx, size_t width,
					    const dnssec_binary_t *data)
{
	assert(data);

	wire_write_ralign(ctx, width, data->data, data->size);
}

static inline void wire_write_datum(wire_ctx_t *ctx, gnutls_datum_t *data)
{
	assert(data);

	wire_write(ctx, data->data, data->size);
}
