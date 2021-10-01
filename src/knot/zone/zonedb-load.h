/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/conf/conf.h"
#include "knot/server/server.h"

/*!
 * \brief Destroy all members of specified catalog zone.
 *
 * \param server   Server with catalog DB.
 * \param conf     Optional: check conf to skip if zone not catalog.
 * \param zone     Catalog zone name.
 *
 * \return KNOT_E*
 */
int catalog_zone_purge(server_t *server, conf_t *conf, const knot_dname_t *zone);

/*!
 * \brief Update zone database according to configuration.
 *
 * \param[in] conf Configuration.
 * \param[in] server Server instance.
 */
void zonedb_reload(conf_t *conf, server_t *server);

/*!
 * \brief Re-create zone_t struct in zoneDB so that the zone is reloaded incl modules.
 *
 * \param conf       Configuration.
 * \param server     Server instance.
 * \param zone_name  Name of zone to be reloaded.
 *
 * \return KNOT_E*
 */
int zone_reload_modules(conf_t *conf, server_t *server, const knot_dname_t *zone_name);
