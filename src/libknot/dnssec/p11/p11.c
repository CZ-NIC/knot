/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <gnutls/pkcs11.h>
#include <stdlib.h>
#include <string.h>

#include "libknot/dnssec/p11/p11.h"
#include "libknot/errcode.h"

#ifdef ENABLE_PKCS11

#define PKCS11_MODULES_MAX 16

static char *pkcs11_modules[PKCS11_MODULES_MAX] = { 0 };
static int pkcs11_modules_count = 0;

static int map_result(int gnutls_result)
{
	return gnutls_result == GNUTLS_E_SUCCESS ? KNOT_EOK : KNOT_ERROR;
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
			return KNOT_EOK;
		}
	}

	assert(pkcs11_modules_count <= PKCS11_MODULES_MAX);
	if (pkcs11_modules_count == PKCS11_MODULES_MAX) {
		return KNOT_ERANGE;
	}

	char *copy = strdup(module);
	if (!copy) {
		return KNOT_ENOMEM;
	}

	int r = gnutls_pkcs11_add_provider(module, NULL);
	if (r != GNUTLS_E_SUCCESS) {
		free(copy);
		return KNOT_P11_ELOAD;
	}

	pkcs11_modules[pkcs11_modules_count] = copy;
	pkcs11_modules_count += 1;

	return KNOT_EOK;
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
	return KNOT_EOK;
}

int p11_reinit(void)
{
	return KNOT_EOK;
}

int p11_load_module(const char *module)
{
	return KNOT_ENOTSUP;
}

void p11_cleanup(void)
{
	// this function intentionally left blank
}

#endif
