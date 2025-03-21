/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/server/server.h"

/*!
 * \brief Update zone database according to configuration.
 *
 * \param conf    Configuration.
 * \param server  Server instance.
 * \param mode    Reload mode.
 */
void zonedb_reload(conf_t *conf, server_t *server, reload_t mode);

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
