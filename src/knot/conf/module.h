/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/base.h"

struct server;

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
 * \param[in] type       Type of module.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_mod_load_extra(
	conf_t *conf,
	const char *mod_name,
	const char *file_name,
	module_type_t type
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
 * \param[in] server         Server context.
 * \param[in] zone_name      Zone name, NULL for all zones.
 * \param[in] query_modules  Destination query modules list.
 * \param[in] query_plan     Destination query plan.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_activate_modules(
	conf_t *conf,
	struct server *server,
	const knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan
);

/*!
 * Activates specified configured query module for the specified zone or for all zones.
 *
 * \param[in] conf           Configuration.
 * \param[in] server         Server context.
 * \param[in] zone_name      Zone name, NULL for all zones.
 * \param[in] query_modules  Destination query modules list.
 * \param[in] query_plan     Destination query plan.
 * \param[in] val            Module configuration to activate.
 *
 * \return Error code, KNOT_EOK if success.
 */
int conf_activate_given_module_conf(
	conf_t *conf,
	struct server *server,
	const knot_dname_t *zone_name,
	list_t *query_modules,
	struct query_plan **query_plan,
	conf_val_t val
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

/*!
 * Re-activates query modules in list.
 *
 * \param[in] conf           Configuration.
 * \param[in] query_modules  Query module list.
 * \param[in] query_plan     Query plan.
 */
void conf_reset_modules(
	conf_t *conf,
	list_t *query_modules,
	struct query_plan **query_plan
);
