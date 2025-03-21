/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/conf.h"
#include "libknot/errcode.h"

/* Prepare server configuration. */
static inline int test_conf(const char *conf_str, const yp_item_t *schema)
{
	// Use default schema if not specified.
	if (schema == NULL) {
		schema = conf_schema;
	}

	conf_t *new_conf = NULL;
	int ret = conf_new(&new_conf, schema, NULL, 2 * 1024 * 1024, CONF_FNONE);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = conf_import(new_conf, conf_str, 0);
	if (ret != KNOT_EOK) {
		conf_free(new_conf);
		return ret;
	}

	conf_update(new_conf, CONF_UPD_FNONE);

	return KNOT_EOK;
}

static inline void test_conf_free(void)
{
	conf_update(NULL, CONF_UPD_FNONE);
}
