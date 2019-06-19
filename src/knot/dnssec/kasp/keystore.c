/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stdio.h>
#include <string.h>

#include "libdnssec/error.h"
#include "knot/dnssec/kasp/keystore.h"
#include "knot/conf/schema.h"
#include "libknot/error.h"

static char *fix_path(const char *config, const char *base_path)
{
	assert(config);
	assert(base_path);

	char *path = NULL;

	if (config[0] == '/') {
		path = strdup(config);
	} else {
		if (asprintf(&path, "%s/%s", base_path, config) == -1) {
			path = NULL;
		}
	}

	return path;
}

int keystore_load(const char *config, unsigned backend,
                  const char *kasp_base_path, dnssec_keystore_t **keystore)
{
	int ret = DNSSEC_EINVAL;
	char *fixed_config = NULL;

	switch (backend) {
	case KEYSTORE_BACKEND_PEM:
		ret = dnssec_keystore_init_pkcs8(keystore);
		fixed_config = fix_path(config, kasp_base_path);
		break;
	case KEYSTORE_BACKEND_PKCS11:
		ret = dnssec_keystore_init_pkcs11(keystore);
		fixed_config = strdup(config);
		break;
	default:
		assert(0);
	}
	if (ret != DNSSEC_EOK) {
		free(fixed_config);
		return knot_error_from_libdnssec(ret);
	}
	if (fixed_config == NULL) {
		dnssec_keystore_deinit(*keystore);
		*keystore = NULL;
		return KNOT_ENOMEM;
	}

	ret = dnssec_keystore_init(*keystore, fixed_config);
	if (ret != DNSSEC_EOK) {
		free(fixed_config);
		dnssec_keystore_deinit(*keystore);
		*keystore = NULL;
		return knot_error_from_libdnssec(ret);
	}

	ret = dnssec_keystore_open(*keystore, fixed_config);
	free(fixed_config);
	if (ret != DNSSEC_EOK) {
		dnssec_keystore_deinit(*keystore);
		*keystore = NULL;
		return knot_error_from_libdnssec(ret);
	}

	return KNOT_EOK;
}
