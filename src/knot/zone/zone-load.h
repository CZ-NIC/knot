/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include "knot/zone/zone.h"
#include "knot/dnssec/zone-events.h" // zone_sign_reschedule_t

/*!
 * \brief Load zone contents according to the configuration.
 *
 * \param conf
 * \param zone_name
 * \param contents
 * \param fail_on_warning
 *
 * \retval KNOT_EOK        if success.
 * \retval KNOT_ESEMCHECK  if any semantic check warning.
 * \retval KNOT_E*         if error.
 */
int zone_load_contents(conf_t *conf, const knot_dname_t *zone_name,
                       zone_contents_t **contents, bool fail_on_warning);

/*!
 * \brief Update zone contents from the journal.
 *
 * \warning If error, the zone is in inconsistent state and should be freed.
 *
 * \param conf
 * \param zone
 * \param contents
 * \return KNOT_EOK or an error
 */
int zone_load_journal(conf_t *conf, zone_t *zone, zone_contents_t *contents);

/*!
 * \brief Load zone contents from journal (headless).
 *
 * \param conf
 * \param zone
 * \param contents
 * \return KNOT_EOK or an error
 */
int zone_load_from_journal(conf_t *conf, zone_t *zone,
                           zone_contents_t **contents);

/*!
 * \brief Check if zone can be bootstrapped.
 *
 * \param conf
 * \param zone_name
 */
bool zone_load_can_bootstrap(conf_t *conf, const knot_dname_t *zone_name);
