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
#include "libknot/libknot.h"
#include "libknot/yparser/ypscheme.h"

/*! Current version of the configuration database structure. */
#define CONF_DB_VERSION		2
/*! Minimum length of a database key ([category_id, item_id]. */
#define CONF_MIN_KEY_LEN	(2 * sizeof(uint8_t))
/*! Maximum length of a database key ([category_id, item_id, identifier]. */
#define CONF_MAX_KEY_LEN	(CONF_MIN_KEY_LEN + YP_MAX_ID_LEN)
/*! Maximum size of database data. */
#define CONF_MAX_DATA_LEN	65536

/*!
 * Opens and checks or initializes the configuration DB.
 *
 * \param[in] conf  Configuration.
 * \param[in] txn   Configuration DB transaction.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_init(
	conf_t *conf,
	knot_db_txn_t *txn
);

/*!
 * Checks the configuration DB.
 *
 * \param[in] conf  Configuration.
 * \param[in] txn   Configuration DB transaction.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_check(
	conf_t *conf,
	knot_db_txn_t *txn
);

/*!
 * Sets the item with data in the configuration DB.
 *
 * Singlevalued data is rewritten, multivalued data is appended.
 *
 * \note Setting of key0 without key1 has no effect.
 *
 * \param[in] conf      Configuration.
 * \param[in] txn       Configuration DB transaction.
 * \param[in] key0      Section name.
 * \param[in] key1      Item name.
 * \param[in] id        Section identifier.
 * \param[in] id_len    Length of the section identifier.
 * \param[in] data      Item data.
 * \param[in] data_len  Length of the item data.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_set(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	const uint8_t *data,
	size_t data_len
);

/*!
 * Unsets the item data in the configuration DB.
 *
 * If no data is provided, the whole item is remove.
 *
 * \param[in] conf         Configuration.
 * \param[in] txn          Configuration DB transaction.
 * \param[in] key0         Section name.
 * \param[in] key1         Item name.
 * \param[in] id           Section identifier.
 * \param[in] id_len       Length of the section identifier.
 * \param[in] data         Item data.
 * \param[in] data_len     Length of the item data.
 * \param[in] delete_key1  Set to unregister the item from the DB.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_unset(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	const uint8_t *data,
	size_t data_len,
	bool delete_key1
);

/*!
 * Gets the item data from the configuration DB.
 *
 * \param[in] conf    Configuration.
 * \param[in] txn     Configuration DB transaction.
 * \param[in] key0    Section name.
 * \param[in] key1    Item name.
 * \param[in] id      Section identifier.
 * \param[in] id_len  Length of the section identifier.
 * \param[out] data   Item data.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_get(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	const yp_name_t *key1,
	const uint8_t *id,
	size_t id_len,
	conf_val_t *data
);

/*!
 * Gets a configuration DB section iterator.
 *
 * \param[in] conf   Configuration.
 * \param[in] txn    Configuration DB transaction.
 * \param[in] key0   Section name.
 * \param[out] iter  Section iterator.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_iter_begin(
	conf_t *conf,
	knot_db_txn_t *txn,
	const yp_name_t *key0,
	conf_iter_t *iter
);

/*!
 * Moves the section iterator to the next identifier.
 *
 * \param[in] conf      Configuration.
 * \param[in,out] iter  Section iterator.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_iter_next(
	conf_t *conf,
	conf_iter_t *iter
);

/*!
 * Gets the current section iterator value (identifier).
 *
 * \param[in] conf       Configuration.
 * \param[in] iter       Section iterator.
 * \param[out] data      Identifier.
 * \param[out] data_len  Length of the identifier.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_iter_id(
	conf_t *conf,
	conf_iter_t *iter,
	const uint8_t **data,
	size_t *data_len
);

/*!
 * Deletes the current section iterator value (identifier).
 *
 * \param[in] conf      Configuration.
 * \param[in,out] iter  Section iterator.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_iter_del(
	conf_t *conf,
	conf_iter_t *iter
);

/*!
 * Deletes the section iterator.
 *
 * \param[in] conf      Configuration.
 * \param[in,out] iter  Section iterator.
 */
void conf_db_iter_finish(
	conf_t *conf,
	conf_iter_t *iter
);

/*!
 * Dumps the configuration DB in the textual form.
 *
 * \note This function is intended for debugging.
 *
 * \param[in] conf       Configuration.
 * \param[in] txn        Configuration DB transaction.
 * \param[in] file_name  File name to dump to (NULL to dump to stdout).
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_db_raw_dump(
	conf_t *conf,
	knot_db_txn_t *txn,
	const char *file_name
);

/*! @} */
