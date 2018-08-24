/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <gnutls/pkcs11.h>
#include <stdlib.h>
#include <string.h>

#include "libdnssec/p11/p11.h"
#include "libdnssec/error.h"

#ifdef ENABLE_PKCS11

#define PKCS11_MODULES_MAX 16

static char *pkcs11_modules[PKCS11_MODULES_MAX] = { 0 };
static int pkcs11_modules_count = 0;

static int map_result(int gnutls_result)
{
	return gnutls_result == GNUTLS_E_SUCCESS ? DNSSEC_EOK : DNSSEC_ERROR;
}

int p11_init(void)
{
	int r = gnutls_pkcs11_init(GNUTLS_PKCS11_FLAG_MANUAL, NULL);
	return map_result(r);
}

int p11_reinit(void)
{
	int r = gnutls_pkcs11_reinit();
	return map_result(r);
}

int p11_load_module(const char *module)
{
	for (int i = 0; i < pkcs11_modules_count; i++) {
		if (strcmp(pkcs11_modules[i], module) == 0) {
			return DNSSEC_EOK;
		}
	}

	assert(pkcs11_modules_count <= PKCS11_MODULES_MAX);
	if (pkcs11_modules_count == PKCS11_MODULES_MAX) {
		return DNSSEC_P11_TOO_MANY_MODULES;
	}

	char *copy = strdup(module);
	if (!copy) {
		return DNSSEC_ENOMEM;
	}

	int r = gnutls_pkcs11_add_provider(module, NULL);
	if (r != GNUTLS_E_SUCCESS) {
		free(copy);
		return DNSSEC_P11_FAILED_TO_LOAD_MODULE;
	}

	pkcs11_modules[pkcs11_modules_count] = copy;
	pkcs11_modules_count += 1;

	return DNSSEC_EOK;
}

void p11_cleanup(void)
{
	for (int i = 0; i < pkcs11_modules_count; i++) {
		free(pkcs11_modules[i]);
		pkcs11_modules[i] = NULL;
	}

	pkcs11_modules_count = 0;

	gnutls_pkcs11_deinit();
}

#else

int p11_init(void)
{
	return DNSSEC_EOK;
}

int p11_reinit(void)
{
	return DNSSEC_EOK;
}

int p11_load_module(const char *module)
{
	return DNSSEC_NOT_IMPLEMENTED_ERROR;
}

void p11_cleanup(void)
{
	// this function intentionally left blank
}

#endif
