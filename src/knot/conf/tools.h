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
	const char *file_name; // Current config file.
	size_t *incl_depth; // Current include depth.
	const yp_item_t *key0;
	const yp_item_t *key1;
	const uint8_t *id;
	size_t id_len;
	const uint8_t *data;
	size_t data_len;
} conf_args_t;

typedef int conf_call_f(conf_args_t *);

int hex_text_to_bin(
	char const *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len
);

int hex_text_to_txt(
	uint8_t const *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len
);

int mod_id_to_bin(
	char const *txt,
	size_t txt_len,
	uint8_t *bin,
	size_t *bin_len
);

int mod_id_to_txt(
	uint8_t const *bin,
	size_t bin_len,
	char *txt,
	size_t *txt_len
);

int check_ref(
	conf_args_t *args
);

int check_modref(
	conf_args_t *args
);

int include_file(
	conf_args_t *args
);
