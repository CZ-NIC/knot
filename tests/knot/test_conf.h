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
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

	ret = conf_import(new_conf, conf_str, false);
	if (ret != KNOT_EOK) {
		conf_free(new_conf);
		return ret;
	}

	conf_update(new_conf, CONF_UPD_FNONE);

	return KNOT_EOK;
}
