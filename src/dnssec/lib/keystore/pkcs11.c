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

/* -- internal API --------------------------------------------------------- */

static int pkcs11_ctx_new(void **ctx_ptr, _unused_ void *data)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_ctx_free(void *ctx)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_init(void *ctx, const char *config)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_open(void *_ctx, const char *config)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_close(void *ctx)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_list_keys(void *ctx, dnssec_list_t **list)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_generate_key(void *ctx, gnutls_pk_algorithm_t algorithm,
			       unsigned bits, char **id_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_import_key(void *ctx, const dnssec_binary_t *pem, char **id_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_remove_key(void *ctx, const char *id)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

static int pkcs11_get_private(void *ctx, const char *id, gnutls_privkey_t *key_ptr)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_init_pkcs11(dnssec_keystore_t **store_ptr)
{
	static const keystore_functions_t IMPLEMENTATION = {
		.ctx_new      = pkcs11_ctx_new,
		.ctx_free     = pkcs11_ctx_free,
		.init         = pkcs11_init,
		.open         = pkcs11_open,
		.close        = pkcs11_close,
		.list_keys    = pkcs11_list_keys,
		.generate_key = pkcs11_generate_key,
		.import_key   = pkcs11_import_key,
		.remove_key   = pkcs11_remove_key,
		.get_private  = pkcs11_get_private,
	};

	return keystore_create(store_ptr, &IMPLEMENTATION, NULL);
}
