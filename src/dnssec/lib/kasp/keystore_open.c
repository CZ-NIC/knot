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
 * Fix path to the PKCS8 key store.
 *
 * If the key store path is relative, use KASP base path as the base.
 */
static int fix_path(dnssec_kasp_t *kasp, const char *config, char **path_ptr)
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

struct backend {
	//! Backend name
	const char *name;
	//! Keystore initialization function
	int (*init)(dnssec_keystore_t **kasp);
	//! Callback to patch configuration string
	int (*patch_config)(dnssec_kasp_t *, const char *, char **);
};

static const struct backend BACKENDS[] = {
	{ DNSSEC_KASP_KEYSTORE_PKCS8,  dnssec_keystore_init_pkcs8_dir, fix_path },
	{ DNSSEC_KASP_KEYSTORE_PKCS11, dnssec_keystore_init_pkcs11,    NULL },
	{ 0 }
};

static const struct backend *get_backend(const char *name)
{
	for (const struct backend *b = BACKENDS; b->name; b++) {
		if (strcmp(b->name, name) == 0) {
			return b;
		}
	}

	return NULL;
}

/*!
 * Lookup correct backend, fix config, and perform keystore init/open callback.
 */
static int backend_exec(dnssec_kasp_t *kasp, const char *name, const char *config,
			int (*callback)(dnssec_keystore_t *, const char *),
			dnssec_keystore_t **keystore_ptr)
{
	if (!kasp || !name || !callback || !keystore_ptr) {
		return DNSSEC_EINVAL;
	}

	const struct backend *backend = get_backend(name);
	if (!backend) {
		return DNSSEC_KEYSTORE_INVALID_BACKEND;
	}

	_cleanup_free_ char *patched_config = NULL;
	if (backend->patch_config) {
		int r = backend->patch_config(kasp, config, &patched_config);
		if (r != DNSSEC_EOK) {
			return r;
		}
	}

	dnssec_keystore_t *keystore = NULL;
	int r = backend->init(&keystore);
	if (r != DNSSEC_EOK) {
		return r;
	}

	r = callback(keystore, patched_config ? patched_config : config);
	if (r != DNSSEC_EOK) {
		dnssec_keystore_deinit(keystore);
	}

	*keystore_ptr = keystore;
	return DNSSEC_EOK;
}

/* -- public API ----------------------------------------------------------- */

_public_
int dnssec_kasp_keystore_init(dnssec_kasp_t *kasp, const char *backend,
			      const char *config, dnssec_keystore_t **store)
{
	return backend_exec(kasp, backend, config, dnssec_keystore_init, store);

}

_public_
int dnssec_kasp_keystore_open(dnssec_kasp_t *kasp, const char *backend,
			      const char *config, dnssec_keystore_t **store)
{
	return backend_exec(kasp, backend, config, dnssec_keystore_open, store);
}
