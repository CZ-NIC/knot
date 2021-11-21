/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
 * \return KNOT_E*
 */
int util_conf_init_default(void);

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
