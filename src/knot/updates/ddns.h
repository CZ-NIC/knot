/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/updates/zone-update.h"
#include "libknot/packet/pkt.h"

/*!
 * \brief Checks update prerequisite section.
 *
 * \param query   DNS message containing the update.
 * \param update  Zone to be checked.
 * \param rcode   Returned DNS RCODE.
 *
 * \return KNOT_E*
 */
int ddns_process_prereqs(const knot_pkt_t *query, zone_update_t *update,
                         uint16_t *rcode);

/*!
 * \brief Performs a pre-check of the update'S sanity.
 *
 * \param query      DNS message containing the update.
 * \param update     Zone to be checked.
 * \param rcode      Returned DNS RCODE.
 *
 * \return KNOT_E*
 */
int ddns_precheck_update(const knot_pkt_t *query, zone_update_t *update,
                         uint16_t *rcode);

/*!
 * \brief Processes DNS update and creates a changeset out of it. Zone is left
 *        intact.
 *
 * \param query       DNS message containing the update.
 * \param update      Output changeset.
 * \param rcode       Output DNS RCODE.
 *
 * \return KNOT_E*
 */
int ddns_process_update(const knot_pkt_t *query, zone_update_t *update,
                        uint16_t *rcode);
