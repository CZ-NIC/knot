/*!
 * \file xfr-in.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief XFR client API.
 *
 * \addtogroup xfr
 * @{
 */
/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_XFR_IN_H_
#define _KNOT_XFR_IN_H_

#include <stdint.h>
#include <string.h>

#include "libknot/dname.h"
#include "knot/zone/zone.h"
#include "libknot/packet/pkt.h"
#include "knot/server/xfr-handler.h"
#include "knot/updates/changesets.h"

struct xfr_proc;
struct ixfrin_proc;

/*----------------------------------------------------------------------------*/

typedef enum xfrin_transfer_result {
	XFRIN_RES_COMPLETE = 1,
	XFRIN_RES_SOA_ONLY = 2,
	XFRIN_RES_FALLBACK = 3
} xfrin_transfer_result_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Checks if a zone transfer is required by comparing the zone's SOA with
 *        the one received from master server.
 *
 * \param zone Zone to check.
 * \param soa_response Response to SOA query received from master server.
 *
 * \retval < 0 if an error occured.
 * \retval 1 if the transfer is needed.
 * \retval 0 if the transfer is not needed.
 */
int xfrin_transfer_needed(const zone_contents_t *zone,
                          knot_pkt_t *soa_response);

/*!
 * \brief Processes one incoming packet of AXFR transfer by updating the given
 *        zone.
 *
 * \param pkt Incoming packet in wire format.
 * \param size Size of the packet in bytes.
 * \param zone Zone being built. If there is no such zone (i.e. this is the
 *             first packet, \a *zone may be set to NULL, in which case a new
 *             zone structure is created).
 *
 * \retval KNOT_EOK
 *
 * \todo Refactor!!!
 */
int xfrin_process_axfr_packet(knot_pkt_t *pkt, struct xfr_proc *proc);

/*!
 * \brief Parses IXFR reply packet and fills in the changesets structure.
 *
 * \param pkt   Packet containing the IXFR reply in wire format.
 * \param proc  Processing context.
 *
 * \return NS_PROC_MORE, NS_PROC_DONE, NS_PROC_FAIL
 */
int xfrin_process_ixfr_packet(knot_pkt_t *pkt, struct ixfrin_proc *proc);

/*!
 * \brief Applies changesets *with* zone shallow copy.
 *
 * \param zone          Zone to be updated.
 * \param chsets        Changes to be made.
 * \param new_contents  New zone will be returned using this arg.
 * \return KNOT_E*
 */
int xfrin_apply_changesets(zone_t *zone,
                           knot_changesets_t *chsets,
                           zone_contents_t **new_contents);

/*!
 * \brief Applies changesets directly to the zone, without copying it.
 *
 * \param contents Zone contents to apply the changesets to. Will be modified.
 * \param chsets   Changesets to be applied to the zone.
 *
 * \retval KNOT_EOK if successful.
 * \retval KNOT_EINVAL if given one of the arguments is NULL.
 * \return Other error code if the application went wrong.
 */
int xfrin_apply_changesets_directly(zone_contents_t *contents,
                                    knot_changesets_t *chsets);

/*!
 * \brief Sets pointers and NSEC3 nodes after signing/DDNS.
 * \param contents_copy    Contents to be updated.
 * \param set_nsec3_names  Set to true if NSEC3 hashes should be set.
 * \return KNOT_E*
 */
int xfrin_finalize_updated_zone(zone_contents_t *contents_copy,
                                bool set_nsec3_names);

zone_contents_t *xfrin_switch_zone(zone_t *zone, zone_contents_t *new_contents);

void xfrin_rollback_update(knot_changesets_t *chgs,
                           zone_contents_t **new_contents);

void xfrin_cleanup_successful_update(knot_changesets_t *chgs);

/* @note Exported because of update.c */
void xfrin_zone_contents_free(zone_contents_t **contents);

#endif /* _KNOTXFR_IN_H_ */

/*! @} */
