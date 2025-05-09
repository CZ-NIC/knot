/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/conf.h"

/*! Zone configuration change type. */
typedef enum {
	CONF_IO_TNONE   = 0,      /*!< Unspecified. */
	CONF_IO_TSET    = 1 << 0, /*!< Zone added. */
	CONF_IO_TUNSET  = 1 << 1, /*!< Zone removed. */
	CONF_IO_TCHANGE = 1 << 2, /*!< Zone has changed configuration. */
	CONF_IO_TRELOAD = 1 << 3, /*!< Zone must be reloaded. */
} conf_io_type_t;

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

inline static conf_io_type_t conf_io_trie_val(trie_it_t *it)
{
	return (conf_io_type_t)(uintptr_t)(*trie_it_val(it));
}

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
 * \return    KNOT_TXN_ETHREAD if called from a wrong thread, KNOT_EOK otherwise.
 */
int conf_io_abort(
	bool child
);

/*!
 * Gets the configuration sections list or section items list.
 *
 * \param[in] key0         Section name (NULL to get section list).
 * \param[in] key1         Item name (non-NULL to get value list).
 * \param[in] id           Section identifier name if needed for value list.
 * \param[in] list_schema  List schema items or option values.
 * \param[in] get_current  The current configuration or the active transaction switch.
 * \param[out] io          Operation output.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_list(
	const char *key0,
	const char *key1,
	const char *id,
	bool list_schema,
	bool get_current,
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
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_io_set(
	const char *key0,
	const char *key1,
	const char *id,
	const char *data
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
