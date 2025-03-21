/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include <stdbool.h>

#include "knot/conf/conf.h"

/*!
 * General note:
 *
 * Those functions operate and manipulate with conf() singleton.
 * Thus they are not threadsafe etc.
 * It is expected to use them just inside the main() function.
 *
 * Those functions already log any error, while returning an errcode.
 */

/*!
 * \brief Return true if conf() for utilities already exists.
 */
bool util_conf_initialized(void);

/*!
 * \brief Initialize conf() for utilities from a configuration database.
 *
 * \param confdb   Path to configuration database.
 *
 * \return KNOT_E*
 */
int util_conf_init_confdb(const char *confdb);

/*!
 * \brief Initialize conf() for utilities from a config file.
 *
 * \param conffile   Path to Knot configuration file.
 *
 * \return KNOT_E*
 */
int util_conf_init_file(const char *conffile);

/*!
 * \brief Initialize basic conf() for utilities just with defaults and some database path.
 *
 * \param db_type   Type of the database to be configured.
 * \param db_path   Path to that database.
 *
 * \return KNOT_E*
 */
int util_conf_init_justdb(const char *db_type, const char *db_path);

/*!
 * \brief Initialize conf() for utilities based on existence of confDB or config
 *        file on default locations.
 *
 * \param allow_db   Direct path to a database is allowed.
 *
 * \return KNOT_E*
 */
int util_conf_init_default(bool allow_db);

/*!
 * \brief Set UID and GID of running utility process to what is configured...
 *
 * ...so that e.g. opened files have correct owner.
 */
void util_update_privileges(void);

/*!
 * \brief Deinitialize utility conf() from util_conf_init_*().
 */
void util_conf_deinit(void);
