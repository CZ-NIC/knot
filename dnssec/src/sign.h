#pragma once

#include <stdint.h>
#include <stdlib.h>

#include "key.h"
#include "binary.h"

struct dnssec_sign_ctx;
typedef struct dnssec_sign_ctx dnssec_sign_ctx_t;

int dnssec_sign_new(dnssec_sign_ctx_t **ctx_ptr, const dnssec_key_t *key);
void dnssec_sign_free(dnssec_sign_ctx_t *ctx);

int dnssec_sign_init(dnssec_sign_ctx_t *ctx);
int dnssec_sign_add(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *data);
int dnssec_sign_write(dnssec_sign_ctx_t *ctx, dnssec_binary_t *signature);
int dnssec_sign_verify(dnssec_sign_ctx_t *ctx, const dnssec_binary_t *signature);
