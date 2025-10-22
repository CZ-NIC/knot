/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

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
	int ret = KNOT_EINVAL;
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
	if (ret != KNOT_EOK) {
		free(fixed_config);
		return ret;
	}
	if (fixed_config == NULL) {
		dnssec_keystore_deinit(*keystore);
		*keystore = NULL;
		return KNOT_ENOMEM;
	}

	ret = dnssec_keystore_init(*keystore, fixed_config);
	if (ret != KNOT_EOK) {
		free(fixed_config);
		dnssec_keystore_deinit(*keystore);
		*keystore = NULL;
		return ret;
	}

	ret = dnssec_keystore_open(*keystore, fixed_config);
	free(fixed_config);
	if (ret != KNOT_EOK) {
		dnssec_keystore_deinit(*keystore);
		*keystore = NULL;
		return ret;
	}

	return KNOT_EOK;
}
