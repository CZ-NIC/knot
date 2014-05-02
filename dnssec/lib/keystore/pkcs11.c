/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <gnutls/gnutls.h>

#include "error.h"
#include "keystore.h"
#include "keystore/internal.h"
#include "shared.h"

/*!
 * PKCS #11 key store context.
 */
typedef struct pkcs11_ctx {
	int tmp;
} pkcs11_ctx_t;

/* -- internal API --------------------------------------------------------- */

static int pkcs11_ctx_new(void **ctx_ptr, _unused_ void *data)
{
	pkcs11_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) {
		return DNSSEC_ENOMEM;
	}

	*ctx_ptr = ctx;
	return DNSSEC_EOK;
}

static void pkcs11_ctx_free(void *ctx)
{
	free(ctx);
}

static int pkcs11_open(void *_ctx, const char *config)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_close(void *_ctx)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_list_keys(void *ctx, void *list)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_generate_key(void *_ctx, gnutls_pk_algorithm_t algorithm,
			       unsigned bits, char **id_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_delete_key(void *_ctx, const char *id)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

const keystore_functions_t PKCS11_FUNCTIONS = {
	.ctx_new = pkcs11_ctx_new,
	.ctx_free = pkcs11_ctx_free,
	.open = pkcs11_open,
	.close = pkcs11_close,
	.list_keys = pkcs11_list_keys,
	.generate_key = pkcs11_generate_key,
	.delete_key = pkcs11_delete_key,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_create_pkcs11(dnssec_keystore_t **store_ptr, const char *config)
{
	if (!config) {
		return DNSSEC_EINVAL;
	}

	return keystore_create(store_ptr, &PKCS11_FUNCTIONS, NULL, config);
}
