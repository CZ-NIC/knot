#pragma once

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "binary.h"

typedef struct wire_ctx {
	uint8_t *wire;
	size_t size;
	uint8_t *position;
} wire_ctx_t;

static inline void wire_init(wire_ctx_t *ctx, uint8_t *wire, size_t size)
{
	assert(ctx);
	assert(wire);

	memset(ctx, 0, sizeof(wire_ctx_t));
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

static inline void wire_write(wire_ctx_t *ctx, uint8_t *data, size_t size)
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
