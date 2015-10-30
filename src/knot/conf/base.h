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
 * Server configuration core.
 *
 * \addtogroup config
 *
 * @{
 */

#pragma once

#include "libknot/libknot.h"
#include "libknot/internal/lists.h"
#include "libknot/internal/namedb/namedb_lmdb.h"
#include "libknot/yparser/ypscheme.h"

/*! Default template identifier. */
#define CONF_DEFAULT_ID		((uint8_t *)"\x08""default\0")
/*! Default configuration file. */
#define CONF_DEFAULT_FILE	(CONFIG_DIR "/knot.conf")
/*! Default configuration database. */
#define CONF_DEFAULT_DBDIR	(STORAGE_DIR "/confdb")
/*! Maximum depth of nested transactions. */
#define CONF_MAX_TXN_DEPTH	5

/*! Configuration specific logging. */
#define CONF_LOG(severity, msg, ...) do { \
	log_msg(severity, "config, " msg, ##__VA_ARGS__); \
	} while (0)

/*! Configuration context. */
typedef struct {
	/*! Currently used namedb api. */
	const struct namedb_api *api;
	/*! Configuration scheme. */
	yp_item_t *scheme;
	/*! Memory context. */
	mm_ctx_t *mm;
	/*! Configuration database. */
	namedb_t *db;

	/*! Read-only transaction for config access. */
	namedb_txn_t read_txn;

	struct {
		/*! The current writing transaction. */
		namedb_txn_t *txn;
		/*! Stack of nested writing transactions. */
		namedb_txn_t txn_stack[CONF_MAX_TXN_DEPTH];
	} io;

	/*! Prearranged hostname string (for automatic NSID or CH ident value). */
	char *hostname;
	/*! Current config file (for reload if started with config file). */
	char *filename;

	/*! List of active query modules. */
	list_t query_modules;
	/*! Default query modules plan. */
	struct query_plan *query_plan;
} conf_t;

/*!
 * Returns the active configuration.
 */
conf_t* conf(void);

/*!
 * Creates new or opens old configuration database.
 *
 * \param[out] conf Configuration.
 * \param[in] scheme Configuration scheme.
 * \param[in] db_dir Database path or NULL.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_new(
	conf_t **conf,
	const yp_item_t *scheme,
	const char *db_dir
);

/*!
 * Creates a partial copy of the active configuration.
 *
 * Shared objects: api, mm, db, filename.
 *
 * \param[out] conf Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_clone(
	conf_t **conf
);

/*!
 * Processes some additional operations and checks after configuration loading.
 *
 * \param[in] conf Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_post_open(
	conf_t *conf
);

/*!
 * Replaces the active configuration with the specified one.
 *
 * \param[in] conf New configuration.
 */
void conf_update(
	conf_t *conf
);

/*!
 * Removes the specified configuration.
 *
 * \param[in] conf Configuration.
 * \param[in] is_clone Specifies if the configuration is a clone.
 */
void conf_free(
	conf_t *conf,
	bool is_clone
);

/*!
 * Activates configured query modules for the specified zone or for all zones.
 *
 * \param[in] conf Configuration.
 * \param[in] zone_name Zone name, NULL for all zones.
 * \param[in] query_modules Destination query modules list.
 * \param[in] query_plan Destination query plan.
 */
void conf_activate_modules(
	conf_t *conf,
	const knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan
);

/*!
 * Deactivates query modules list.
 *
 * \param[in] conf Configuration.
 * \param[in] query_modules Destination query modules list.
 * \param[in] query_plan Destination query plan.
 */
void conf_deactivate_modules(
	conf_t *conf,
	list_t *query_modules,
	struct query_plan **query_plan
);

/*!
 * Parses textual configuration from the string or from the file.
 *
 * This function is not for direct using, just for includes processing!
 *
 * \param[in] conf Configuration.
 * \param[in] txn Transaction.
 * \param[in] input Configuration string or filename.
 * \param[in] is_file Specifies if the input is string or input filename.
 * \param[in] data Internal data.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_parse(
	conf_t *conf,
	namedb_txn_t *txn,
	const char *input,
	bool is_file,
	void *data
);

/*!
 * Imports textual configuration.
 *
 * \param[in] conf Configuration.
 * \param[in] input Configuration string or input filename.
 * \param[in] is_file Specifies if the input is string or filename.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_import(
	conf_t *conf,
	const char *input,
	bool is_file
);

/*!
 * Exports configuration to textual file.
 *
 * \param[in] conf Configuration.
 * \param[in] input Output filename.
 * \param[in] style Formatting style.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_export(
	conf_t *conf,
	const char *file_name,
	yp_style_t style
);

/*! @} */
