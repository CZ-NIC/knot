/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/conf/base.h"

/*!
 * Finds specific module in static or dynamic modules.
 *
 * \param[in] conf       Configuration.
 * \param[in] name       Module name.
 * \param[in] len        Module name length.
 * \param[in] temporary  Find only a temporary module indication.
 *
 * \return Module, NULL if not found.
 */
module_t *conf_mod_find(
	conf_t *conf,
	const char *name,
	size_t len,
	bool temporary
);

/*!
 * Loads common static and shared modules.
 *
 * \param[in] conf  Configuration.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_mod_load_common(
	conf_t *conf
);

/*!
 * Loads extra shared module.
 *
 * \param[in] conf       Configuration.
 * \param[in] mod_name   Module name.
 * \param[in] file_name  Shared library file name.
 * \param[in] temporary  Mark module as temporary.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_mod_load_extra(
	conf_t *conf,
	const char *mod_name,
	const char *file_name,
	bool temporary
);

/*!
 * Purges temporary schemas and modules after all modules loading.
 *
 * \param[in] conf       Configuration.
 * \param[in] temporary  Purge only temporary modules indication.
 */
void conf_mod_load_purge(
	conf_t *conf,
	bool temporary
);

/*!
 * Unloads all shared modules.
 *
 * \param[in] conf  Configuration.
 */
void conf_mod_unload_shared(
	conf_t *conf
);

/*!
 * Activates configured query modules for the specified zone or for all zones.
 *
 * \param[in] conf           Configuration.
 * \param[in] zone_name      Zone name, NULL for all zones.
 * \param[in] query_modules  Destination query modules list.
 * \param[in] query_plan     Destination query plan.
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
 * \param[in] query_modules  Destination query modules list.
 * \param[in] query_plan     Destination query plan.
 */
void conf_deactivate_modules(
	list_t *query_modules,
	struct query_plan **query_plan
);
