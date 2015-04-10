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
 * Configuration database interface.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "knot/conf/conf.h"
#include "libknot/internal/namedb/namedb.h"
#include "libknot/yparser/ypscheme.h"

/*! Current version of the configuration database structure. */
#define CONF_DB_VERSION		1
/*! Minimum length of a database key ([category_id, item_id]. */
#define CONF_MIN_KEY_LEN	(2 * sizeof(uint8_t))
/*! Maximum length of a database key ([category_id, item_id, identifier]. */
#define CONF_MAX_KEY_LEN	(CONF_MIN_KEY_LEN + YP_MAX_ID_LEN)
/*! Maximum size of database data. */
#define CONF_MAX_DATA_LEN	65536

enum knot_conf_code {
	CONF_CODE_KEY0_ROOT    =   0,
	CONF_CODE_KEY1_ITEMS   =   0,
	CONF_CODE_KEY1_ID      =   1,
	CONF_CODE_KEY1_FIRST   =   2,
	CONF_CODE_KEY1_LAST    = 200,
	CONF_CODE_KEY1_VERSION = 255
};

int conf_db_init(
	conf_t *conf,
	namedb_txn_t *txn
);

int conf_db_set(
	conf_t *conf,
	namedb_txn_t *txn,
	yp_check_ctx_t *in
);

int conf_db_get(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	conf_val_t *out
);

void conf_db_val(
	conf_val_t *val
);

void conf_db_val_next(
	conf_val_t *val
);

int conf_db_iter_begin(
	conf_t *conf,
	namedb_txn_t *txn,
	const yp_name_t *key0,
	conf_iter_t *iter
);

int conf_db_iter_next(
	conf_t *conf,
	conf_iter_t *iter
);

int conf_db_iter_id(
	conf_t *conf,
	conf_iter_t *iter,
	uint8_t **data,
	size_t *data_len
);

void conf_db_iter_finish(
	conf_t *conf,
	conf_iter_t *iter
);

int conf_db_code(
	conf_t *conf,
	namedb_txn_t *txn,
	uint8_t section_code,
	const yp_name_t *name,
	bool read_only,
	uint8_t *db_code
);

int conf_db_raw_dump(
	conf_t *conf,
	const char *file_name
);
