/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/zone/semantic-check.h"
#include "knot/zone/zone.h"

#define DEFAULT_TTL 3600

/*!
 * \brief Load zone contents according to the configuration.
 *
 * \param conf
 * \param zone_name
 * \param contents
 * \param semcheck_mode
 * \param fail_on_warning
 *
 * \retval KNOT_EOK        if success.
 * \retval KNOT_ESEMCHECK  if any semantic check warning.
 * \retval KNOT_E*         if error.
 */
int zone_load_contents(conf_t *conf, const knot_dname_t *zone_name,
                       zone_contents_t **contents, semcheck_optional_t semcheck_mode,
                       bool fail_on_warning);

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
int zone_load_from_journal(conf_t *conf, zone_t *zone, zone_contents_t **contents);

/*!
 * \brief Check if zone can be bootstrapped.
 *
 * \param conf
 * \param zone_name
 */
bool zone_load_can_bootstrap(conf_t *conf, const knot_dname_t *zone_name);
