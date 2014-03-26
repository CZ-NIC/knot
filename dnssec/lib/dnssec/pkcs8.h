#pragma once

#include "binary.h"
#include "key.h"

/*!
 * PKCS #8 key store context.
 */
struct dnssec_pkcs8_ctx;
typedef struct dnssec_pkcs8_ctx dnssec_pkcs8_ctx_t;

/*!
 * PKCS #8 key store callback functions for custom providers.
 */
typedef struct dnssec_pkcs8_functions {
	int (*open)(void **data_ptr, const char *config);
	int (*close)(void *data);
	int (*refresh)(void *data);
	int (*read)(void *data, const dnssec_key_id_t id, dnssec_binary_t *pem);
	int (*write)(void *data, const dnssec_key_id_t id, const dnssec_binary_t *pem);
} dnssec_pkcs8_functions_t;

/*!
 * Retrieve default PKCS #8 provider.
 */
const dnssec_pkcs8_functions_t *dnssec_pkcs8_dir_functions(void);
