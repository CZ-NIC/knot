#pragma once

#include "key.h"

typedef struct keystore_callbacks {
	int a;
} keystore_callbacks_t;

typedef struct dnssec_keystore {
	const keystore_callbacks_t *callbacks;
	void *context;
} dnssec_keystore_t;

dnssec_keystore_t *dnssec_keystore_create_pkcs8(void);
dnssec_keystore_t *dnssec_keystore_create_pkcs11(void);
//dnssec_keystore_t *dnssec_keystore_create_custom_pkcs8(const dnssec_keystore_callbacks_t *callbacks);

int dnssec_keystore_open(dnssec_keystore_t *keystore, const char *path);
int dnssec_keystore_close(dnssec_keystore_t *keystore);
void *dnssec_keystore_list_key_ids(dnssec_keystore_t *keystore);

int dnssec_keystore_load_key(dnssec_keystore_t *keystore, dnssec_key_t *key);
