/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>

#include "libdnssec/binary.h"
#include "libdnssec/key.h"
#include "libdnssec/keystore.h"

typedef struct keystore_functions {
	// construction of internal context
	int (*ctx_new)(void **ctx_ptr);
	void (*ctx_free)(void *ctx);
	// keystore init/open/close
	int (*init)(void *ctx, const char *config);
	int (*open)(void *ctx, const char *config);
	int (*close)(void *ctx);
	// keystore access
	int (*generate_key)(void *ctx, gnutls_pk_algorithm_t algorithm,
			    unsigned bits, const char *label, char **id_ptr);
	int (*import_key)(void *ctx, const dnssec_binary_t *pem, char **id_ptr);
	int (*remove_key)(void *ctx, const char *id);
	// private key access
	int (*get_private)(void *ctx, const char *id, gnutls_privkey_t *key_ptr);
	int (*set_private)(void *ctx, gnutls_privkey_t key);
} keystore_functions_t;

struct dnssec_keystore {
	const keystore_functions_t *functions;
	void *ctx;
};

int keystore_create(dnssec_keystore_t **store_ptr,
		    const keystore_functions_t *functions);
