#pragma once

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include "key.h"
#include "keystore.h"

typedef struct keystore_functions {
	// construction of internal context
	int (*ctx_new)(void **ctx_ptr, void *custom_data);
	void (*ctx_free)(void *ctx);
	// keystore open/close
	int (*open)(void *ctx, const char *config);
	int (*close)(void *ctx);
	// keystore access
	int (*list_keys)(void *ctx, void *list);
	int (*generate_key)(void *ctx, gnutls_pk_algorithm_t algorithm,
			    unsigned bits, dnssec_key_id_t id);
	int (*delete_key)(void *ctx, const dnssec_key_id_t id);
	// private key access
	int (*get_private)(void *ctx, const dnssec_key_id_t id, gnutls_privkey_t *key_ptr);
} keystore_functions_t;

struct dnssec_keystore {
	const keystore_functions_t *functions;
	void *ctx;
};

int keystore_create(dnssec_keystore_t **store_ptr,
		    const keystore_functions_t *functions,
		    void *ctx_custom_data, const char *open_config);
