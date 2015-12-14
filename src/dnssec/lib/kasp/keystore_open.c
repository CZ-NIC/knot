/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <stdio.h>

#include "error.h"
#include "kasp.h"
#include "kasp/internal.h"
#include "keystore.h"
#include "shared.h"

/*!
 * Construct path to the PKCS8 key store.
 *
 * If the key store path is relative, use KASP base path as the base.
 */
static int pkcs8_path(dnssec_kasp_t *kasp, const char *config, char **path_ptr)
{
	assert(kasp);
	assert(config);
	assert(path_ptr);

	char *path = NULL;

	if (config[0] == '/') {
		path = strdup(config);
	} else {
		const char *base = kasp->functions->base_path(kasp->ctx);
		if (base == NULL) {
			return DNSSEC_EINVAL;
		}

		if (asprintf(&path, "%s/%s", base, config) == -1) {
			path = NULL;
		}
	}

	if (!path) {
		return DNSSEC_ENOMEM;
	}

	*path_ptr = path;
	return DNSSEC_EOK;
}

/*!
 * Open PKCS8 key store.
 */
static int pkcs8_open(dnssec_kasp_t *kasp, const char *config,
		      dnssec_keystore_t **keystore_ptr)
{
	dnssec_keystore_t *store = NULL;
	int r = dnssec_keystore_init_pkcs8_dir(&store);
	if (r != DNSSEC_EOK) {
		return r;
	}

	_cleanup_free_ char *path = NULL;
	r = pkcs8_path(kasp, config, &path);
	if (r != DNSSEC_EOK) {
		dnssec_keystore_deinit(store);
		return r;
	}

	r = dnssec_keystore_open(store, path);
	if (r != DNSSEC_EOK) {
		dnssec_keystore_deinit(store);
		return r;
	}

	*keystore_ptr = store;
	return DNSSEC_EOK;
}

/*!
 * Open PKCS11 key store.
 */
static int pkcs11_open(dnssec_kasp_t *kasp, const char *config,
		       dnssec_keystore_t **keystore_ptr)
{
	dnssec_keystore_t *store = NULL;
	int r = dnssec_keystore_init_pkcs11(&store);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = dnssec_keystore_open(store, config);
	if (r != DNSSEC_EOK) {
		dnssec_keystore_deinit(store);
		return r;
	}

	*keystore_ptr = store;
	return DNSSEC_EOK;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_keystore_open(dnssec_kasp_t *kasp, const char *name,
			      dnssec_keystore_t **keystore_ptr)
{
	if (!kasp || !name || !keystore_ptr) {
		return DNSSEC_EINVAL;
	}

	dnssec_kasp_keystore_t *info = NULL;
	int r = dnssec_kasp_keystore_load(kasp, name, &info);
	if (r != DNSSEC_EOK) {
		return r;
	}

	if (strcmp(info->backend, DNSSEC_KASP_KEYSTORE_PKCS8) == 0) {
		r = pkcs8_open(kasp, info->config, keystore_ptr);
	} else if (strcmp(info->backend, DNSSEC_KASP_KEYSTORE_PKCS11) == 0) {
		r = pkcs11_open(kasp, info->config, keystore_ptr);
	} else {
		r = DNSSEC_KEYSTORE_INVALID_BACKEND;
	}

	dnssec_kasp_keystore_free(info);

	return r;
}
