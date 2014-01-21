/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file nsec3-chain-fix.h
 *
 * \author Jan Kadlec <jan.kadlec@nic.cz> (chain fix)
 * \author Jan Vcelak <jan.vcelak@nic.cz> (chain creation)
 *
 * \brief NSEC3 chain fix and creation.
 *
 * \addtogroup dnssec
 * @{
 */

#ifndef _KNOT_DNSSEC_NSEC3_CHAIN_FIX_H_
#define _KNOT_DNSSEC_NSEC3_CHAIN_FIX_H_

#include "libknot/dnssec/zone-nsec.h"
#include "libknot/dnssec/nsec-chain.h"

/*!
 * \brief Creates new NSEC3 chain, add differences from current into a changeset.
 *
 * \param zone       Zone to be checked.
 * \param ttl        TTL for new records.
 * \param changeset  Changeset to store changes into.
 *
 * \return KNOT_E*
 */
int knot_nsec3_create_chain(const knot_zone_contents_t *zone, uint32_t ttl,
                            knot_changeset_t *changeset);

/*!
 * \brief Fixes NSEC3 chain after DDNS/reload.
 *
 * \param sorted_changes  Sorted changes created by changeset sign function.
 * \param fix_data        Chain fix data.
 *
 * \return KNOT_E*
 */
int knot_nsec3_fix_chain(hattrie_t *sorted_changes, chain_fix_data_t *fix_data);

#endif // _KNOT_DNSSEC_NSEC3_CHAIN_FIX_H_
