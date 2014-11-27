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

const keystore_functions_t PKCS11_FUNCTIONS = {
	.ctx_new = pkcs11_ctx_new,
};

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_keystore_create_pkcs11(dnssec_keystore_t **store_ptr)
{
	return keystore_create(store_ptr, &PKCS11_FUNCTIONS, NULL);
}
