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

#include "knot/zone/contents.h"

/*!
 * \brief Compute hash over whole zone by concatenating RRSets in wire format.
 *
 * \param contents     Zone contents to digest.
 * \param algorithm    Algorithm to use.
 * \param out_digest   Output: buffer with computed hash (to be freed).
 * \param out_size     Output: size of the resulting hash.
 *
 * \return KNOT_E*
 */
int zone_contents_digest(const zone_contents_t *contents, int algorithm,
                         uint8_t **out_digest, size_t *out_size);

/*!
 * \brief Check whether exactly one ZONEMD exists in the zone, is valid and matches given algorithm.
 *
 * \note Special value 255 of algorithm means that ZONEMD shall not exist.
 *
 * \param contents   Zone contents to be verified.
 * \param alg        Required algorithm of the ZONEMD.
 * \param no_verify  Don't verify the validness of the digest in ZONEMD.
 */
bool zone_contents_digest_exists(const zone_contents_t *contents, int alg, bool no_verify);

/*!
 * \brief Verify zone dgest in ZONEMD record.
 *
 * \param contents   Zone contents ot be verified.
 *
 * \retval KNOT_EEMPTYZONE  The zone is empty.
 * \retval KNOT_ENOENT      There is no ZONEMD in contents' apex.
 * \retval KNOT_ENOTSUP     None of present ZONEMD is supported (scheme+algorithm+SOAserial).
 * \retval KNOT_ESEMCHECK   Duplicate ZONEMD with identical scheme+algorithm pair.
 * \retval KNOT_EFEWDATA    Error in hash length.
 * \retval KNOT_EMALF       The computed hash differs from ZONEMD.
 * \return KNOT_E*
 */
int zone_contents_digest_verify(const zone_contents_t *contents);

struct zone_update;
/*!
 * \brief Add ZONEMD record to zone_update.
 *
 * \param update        Update with contents to be digested.
 * \param algorithm     ZONEMD algorithm.
 * \param placeholder   Don't calculate, just put placeholder (if ZONEMD not yet present).
 *
 * \note Special value 255 of algorithm means to remove ZONEMD.
 *
 * \return KNOT_E*
 */
int zone_update_add_digest(struct zone_update *update, int algorithm, bool placeholder);
