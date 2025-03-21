/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/zone/zone.h"

/*!
 * \brief Replan timer dependent refresh, expire, and flush.
 */
void replan_from_timers(conf_t *conf, zone_t *zone);

/*!
 * \defgroup replan_load Replan timers after zone load or reload.
 * @{
 */
void replan_load_new(zone_t *zone, bool gen_catalog);
void replan_load_bootstrap(conf_t *conf, zone_t *zone);
void replan_load_current(conf_t *conf, zone_t *zone, zone_t *old_zone);
void replan_load_updated(zone_t *zone, zone_t *old_zone);
/*! @} */
