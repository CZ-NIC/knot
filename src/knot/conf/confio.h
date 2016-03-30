/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * Configuration interface.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include "knot/conf/conf.h"

/*! Configuration interface output. */
typedef struct conf_io conf_io_t;
struct conf_io {
	/*! Section. */
	const yp_item_t *key0;
	/*! Section item. */
	const yp_item_t *key1;
	/*! Section identifier. */
	const uint8_t *id;
	/*! Section identifier length. */
	size_t id_len;
	/*! Consider item identifier as item data. */
	bool id_as_data;

	enum {
		/*! Default item state. */
		NONE,
		/*! New item indicator. */
		NEW,
		/*! Old item indicator. */
		OLD
	} type;

	struct {
		/*! Section item data (NULL if not used). */
		conf_val_t *val;
		/*! Index of data value to format (counted from 1, 0 means all). */
		size_t index;
		/*! Binary data value (NULL if not used). */
		const uint8_t *bin;
		/*! Length of the binary data value. */
		size_t bin_len;
	} data;

	struct {
		/*! Edit operation return code. */
		int code;
		/*! Edit operation return error message. */
		const char *str;
	} error;

	/*! Optional processing callback. */
	int (*fcn)(conf_io_t *);
	/*! Miscellaneous data useful for the callback. */
	void *misc;
};

/*!
 * Starts new writing transaction.
 *
 * \param[in] child  Nested transaction indicator.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_begin(
	bool child
);

/*!
 * Commits the current writing transaction.
 *
 * \note Remember to call conf_refresh to publish the changes into the common
 *       configuration.
 *
 * \param[in] child  Nested transaction indicator.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_commit(
	bool child
);

/*!
 * Aborts the current writing transaction.
 *
 * \param[in] child  Nested transaction indicator.
 */
void conf_io_abort(
	bool child
);

/*!
 * Gets the configuration sections list or section items list.
 *
 * \param[in] key0  Section name (NULL to get section list).
 * \param[out] io   Operation output.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_list(
	const char *key0,
	conf_io_t *io
);

/*!
 * Gets the configuration difference between the current configuration and
 * the active transaction.
 *
 * \param[in] key0  Section name (NULL to diff all sections).
 * \param[in] key1  Item name (NULL to diff all section items).
 * \param[in] id    Section identifier name (NULL to consider all section identifiers).
 * \param[out] io   Operation output.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_diff(
	const char *key0,
	const char *key1,
	const char *id,
	conf_io_t *io
);

/*!
 * Gets the configuration item(s) value(s).
 *
 * \param[in] key0         Section name (NULL to get all sections).
 * \param[in] key1         Item name (NULL to get all section items).
 * \param[in] id           Section identifier name (NULL to consider all section identifiers).
 * \param[in] get_current  The current configuration or the active transaction switch.
 * \param[out] io          Operation output.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_get(
	const char *key0,
	const char *key1,
	const char *id,
	bool get_current,
	conf_io_t *io
);

/*!
 * Sets the configuration item(s) value.
 *
 * \param[in] key0  Section name.
 * \param[in] key1  Item name (NULL to add identifier only).
 * \param[in] id    Section identifier name (NULL to consider all section identifiers).
 * \param[in] data  Item data to set/add.
 * \param[out] io   Operation output (callback error output).
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_set(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data,
	conf_io_t *io
);

/*!
 * Unsets the configuration item(s) value(s).
 *
 * \param[in] key0  Section name (NULL to unset all sections).
 * \param[in] key1  Item name (NULL to unset the whole section).
 * \param[in] id    Section identifier name (NULL to consider all section identifiers).
 * \param[in] data  Item data (NULL to unset all data).
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_unset(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data
);

/*!
 * Checks the configuration database semantics in the current writing transaction.
 *
 * \param[out] io  Operation output.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_check(
	conf_io_t *io
);

/*! @} */
