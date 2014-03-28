#pragma once

#include "keystore.h"

typedef struct keystore_functions {
	// construction of internal context
	void *(*ctx_new)(void *custom_data);
	void (*ctx_free)(void *ctx);
	// keystore open/close
	int (*open)(void *ctx, const char *config);
	int (*close)(void *ctx);
	// keystore access
	int (*list_keys)(void *ctx, void *list);
	int (*generate_key)(void *ctx, dnssec_key_algorithm_t algorithm,
			    unsigned bits, dnssec_key_id_t id);
	int (*delete_key)(void *ctxx, const dnssec_key_id_t id);
} keystore_functions_t;

struct dnssec_keystore {
	const keystore_functions_t *functions;
	void *ctx;
};

int keystore_create(dnssec_keystore_t **store_ptr,
		    const keystore_functions_t *functions,
		    void *ctx_custom_data, const char *open_config);

//extern const keystore_functions_t PKCS8_FUNCTIONS;
//extern const keystore_functions_t PKCS11_FUNCTIONS;
//
//extern const dnssec_keystore_pkcs8_functions_t PKCS8_DIR_FUNCTIONS;
