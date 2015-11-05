/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file zone-events.h
 *
 * \author Jan Vcelak <jan.vcelak@nic.cz>
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 * \author Jan Kadlec <jan.kadlec@nic.cz>
 *
 * \brief DNSSEC operations triggered on zone events.
 *
 * \addtogroup dnssec
 * @{
 */
#pragma once

#include "knot/zone/zone.h"
#include "knot/updates/changesets.h"
#include "libknot/dnssec/policy.h"
/*!
 * \brief DNSSEC resign zone, store new records into changeset. Valid signatures
 *        and NSEC(3) records will not be changed.
 *
 * \param zone         Zone contents to be signed.
 * \param zone_config  Zone/DNSSEC configuration.
 * \param out_ch       New records will be added to this changeset.
 * \param soa_up       SOA serial update policy.
 * \param refresh_at   Signature refresh time of the oldest signature in zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_zone_sign(zone_contents_t *zone, const conf_zone_t *zone_config,
                          changeset_t *out_ch,
                          knot_update_serial_t soa_up, uint32_t *refresh_at);

/*!
 * \brief DNSSEC sign zone, store new records into changeset. Even valid
 *        signatures will be dropped.
 *
 * \param zone         Zone contents to be signed.
 * \param zone_config  Zone/DNSSEC configuration.
 * \param out_ch       New records will be added to this changeset.
 * \param refresh_at   Signature refresh time of the oldest signature in zone.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_zone_sign_force(zone_contents_t *zone, const conf_zone_t *zone_config,
                                changeset_t *out_ch,
                                uint32_t *refresh_at);

/*!
 * \brief Sign changeset created by DDNS or zone-diff.
 *
 * \param zone            Zone contents to be signed.
 * \param zone_config     Zone/DNSSEC configuration.
 * \param in_ch           Changeset created bvy DDNS or zone-diff
 * \param out_ch          New records will be added to this changeset.
 * \param refresh_at      Signature refresh time of the new signatures.
 *
 * \return Error code, KNOT_EOK if successful.
 */
int knot_dnssec_sign_changeset(zone_contents_t *zone,
                               conf_zone_t *zone_config,
                               const changeset_t *in_ch,
                               changeset_t *out_ch,
                               uint32_t *refresh_at);

/*! @} */
