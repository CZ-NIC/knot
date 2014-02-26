#pragma once

#include <stdint.h>

struct dnssec_sign_ctx;
typedef struct dnssec_sign_ctx dnssec_sign_ctx_t;

dnssec_sign_ctx_t *dnssec_sign_new(dnssec_key_t *key);
void dnssec_sign_free(dnssec_sign_ctx_t *ctx);

int dnssec_sign_init(dnssec_sign_ctx_t *ctx);
int dnssec_sign_add(dnssec_sign_ctx_t *ctx, uint8_t *data, size_t size);
size_t dnssec_sign_size(dnssec_sign_ctx_t *ctx);
int dnssec_sign_write(dnssec_sign_ctx_t *ctx, uint8_t *data, size_t size);
int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, uint8_t *data, size_t size);
