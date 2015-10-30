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
/*!
 * \file
 *
 * Configuration scheme callbacks.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "knot/conf/conf.h"
#include "libknot/yparser/ypscheme.h"

typedef struct {
	conf_t *conf;
	namedb_txn_t *txn;
	const yp_item_t *item;
	const uint8_t *id;
	size_t id_len;
	const uint8_t *data;
	size_t data_len;
	const char *file_name;
	size_t line;
	const char *err_str;
} conf_check_t;

int conf_exec_callbacks(
	const yp_item_t *item,
	conf_check_t *args
);

int mod_id_to_bin(
	YP_TXT_BIN_PARAMS
);

int mod_id_to_txt(
	YP_BIN_TXT_PARAMS
);

int edns_opt_to_bin(
	YP_TXT_BIN_PARAMS
);

int edns_opt_to_txt(
	YP_BIN_TXT_PARAMS
);

int addr_range_to_bin(
	YP_TXT_BIN_PARAMS
);

int addr_range_to_txt(
	YP_BIN_TXT_PARAMS
);

int check_ref(
	conf_check_t *args
);

int check_modref(
	conf_check_t *args
);

int check_remote(
	conf_check_t *args
);

int check_template(
	conf_check_t *args
);

int check_zone(
	conf_check_t *args
);

int include_file(
	conf_check_t *args
);
