/*  Copyright (C) 2015 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
 * \file
 *
 * \brief API for quering zone that is being updated.
 *
 * \addtogroup ddns
 * @{
 */

#pragma once

#include "knot/conf/conf.h"
#include "knot/updates/changesets.h"
#include "knot/zone/contents.h"
#include "knot/zone/zone.h"
#include "libknot/mm_ctx.h"

/*! \brief Structure for zone contents updating / querying. */
typedef struct {
	zone_t *zone;                /*!< Zone being updated. */
	zone_contents_t *new_cont;   /*!< New zone contents for full updates. */
	changeset_t change;          /*!< Changes we want to apply. */
	uint8_t flags;               /*!< Zone update flags. */
	knot_mm_t mm;                /*!< Memory context used for intermediate nodes. */
} zone_update_t;

typedef enum {
	UPDATE_FULL           = 1 << 0, /*!< Replace the old zone by a complete new one. */
	UPDATE_INCREMENTAL    = 1 << 1, /*!< Apply changes to the old zone. */
	UPDATE_SIGN           = 1 << 2, /*!< Sign the resulting zone. */
	UPDATE_DIFF           = 1 << 3, /*!< In the case of full update, create a diff for journal. */
} zone_update_flags_t;

/*!
 * \brief Inits given zone update structure, new memory context is created.
 *
 * \param update  Zone update structure to init.
 * \param zone    Init with this zone.
 * \param flags   Flags to control the behavior of the update.
 *
 * \return KNOT_E*
 */
int zone_update_init(zone_update_t *update, zone_t *zone, zone_update_flags_t flags);

/*!
 * \brief Returns node that would be in the zone after updating it.
 *
 * \note Returned node is either zone original or synthesized, do *not* free
 *       or modify. Returned node is allocated on local mempool.
 *
 * \param update  Zone update.
 * \param dname   Dname to search for.
 *
 * \return   Node after zone update.
 */
const zone_node_t *zone_update_get_node(zone_update_t *update,
                                        const knot_dname_t *dname);

/*!
 * \brief Returns updated zone apex.
 *
 * \note Returned node is either zone original or synthesized, do *not* free
 *       or modify.
 *
 * \param update  Zone update.
 *
 * \return   Returns apex after update.
 */
const zone_node_t *zone_update_get_apex(zone_update_t *update);

/*!
 * \brief Returns the serial from the current apex.
 *
 * \param update  Zone update.
 *
 * \return   0 if no apex was found, its serial otherwise.
 */
uint32_t zone_update_current_serial(zone_update_t *update);

/*!
 * \brief Returns the SOA rdataset we're updating from.
 *
 * \param update  Zone update.
 *
 * \return   The original SOA rdataset.
 */
const knot_rdataset_t *zone_update_from(zone_update_t *update);

/*!
 * \brief Returns the SOA rdataset we're updating to.
 *
 * \param update  Zone update.
 *
 * \return   NULL if no new SOA has been added, new SOA otherwise.
 */
const knot_rdataset_t *zone_update_to(zone_update_t *update);

/*!
 * \brief Clear data allocated by given zone update structure.
 *
 * \param  update Zone update to clear.
 */
void zone_update_clear(zone_update_t *update);

/*!
 * \brief Adds an RRSet to the zone.
 *
 * \param update  Zone update.
 *
 * \return KNOT_E*
 */
int zone_update_add(zone_update_t *update, const knot_rrset_t *rrset);

/*!
 * \brief Removes an RRSet from the zone.
 *
 * \param update  Zone update.
 *
 * \return KNOT_E*
 */
int zone_update_remove(zone_update_t *update, const knot_rrset_t *rrset);

/*!
 * \brief Commits all changes to the zone, signs it, saves changes to journal.
 *
 * \param conf          Configuration.
 * \param update        Zone update.
 * \param contents_out  Where to store the resulting zone contents pointer.
 *
 * \return KNOT_E*
 */
int zone_update_commit(conf_t *conf, zone_update_t *update, zone_contents_t **contents_out);

/*!
 * \brief Returns bool whether there are any changes at all.
 *
 * \param update  Zone update.
 */
bool zone_update_no_change(zone_update_t *up);

/*! @} */
