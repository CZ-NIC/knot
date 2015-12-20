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

#pragma once

#include "knot/conf/conf.h"
#include "libknot/errcode.h"

/* Prepare server configuration. */
static inline int test_conf(const char *conf_str, const yp_item_t *scheme)
{
	// Use default scheme if not specified.
	if (scheme == NULL) {
		scheme = conf_scheme;
	}

	conf_t *conf;
	int ret = conf_new(&conf, scheme, NULL, false);
	if (ret != KNOT_EOK) {
		return ret;
	}

	ret = conf_import(conf, conf_str, false);
	if (ret != KNOT_EOK) {
		conf_free(conf, false);
		return ret;
	}

	ret = conf_post_open(conf);
	if (ret != KNOT_EOK) {
		conf_free(conf, false);
		return ret;
	}

	conf_update(conf);

	return KNOT_EOK;
}
