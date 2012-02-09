/*!
 * \file xfr-in.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief XFR client API.
 *
 * \addtogroup query_processing
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

#include "dname.h"
#include "zone/zone.h"
#include "packet/packet.h"
#include "nameserver/name-server.h"
#include "updates/changesets.h"

/*----------------------------------------------------------------------------*/

typedef struct xfrin_orphan_rrsig {
	knot_rrset_t *rrsig;
	struct xfrin_orphan_rrsig *next;
} xfrin_orphan_rrsig_t;

typedef struct xfrin_constructed_zone {
	knot_zone_contents_t *contents;
	xfrin_orphan_rrsig_t *rrsigs;
} xfrin_constructed_zone_t;

typedef enum xfrin_transfer_result {
	XFRIN_RES_COMPLETE = 1,
	XFRIN_RES_SOA_ONLY = 2,
	XFRIN_RES_FALLBACK = 3
} xfrin_transfer_result_t;

/*----------------------------------------------------------------------------*/

/*!
 * \brief Creates normal query for the given zone name and the SOA type.
 *
 * \param owner Zone owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_soa_query(knot_dname_t *owner, knot_ns_xfr_t *xfr,
                           size_t *size);

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
int xfrin_transfer_needed(const knot_zone_contents_t *zone,
                          knot_packet_t *soa_response);

/*!
 * \brief Creates normal query for the given zone name and the AXFR type.
 *
 * \param owner Zone owner.
 * \param xfr Data structure holding important data for the query, namely
 *            pointer to the buffer for wireformat and TSIG data.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 * \param use_tsig If TSIG should be used. 
 *
 * \todo Parameter use_tsig probably not needed.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_axfr_query(knot_dname_t *owner, knot_ns_xfr_t *xfr,
                            size_t *size, int use_tsig);

/*!
 * \brief Creates normal query for the given zone name and the IXFR type.
 *
 * \param zone Zone contents.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 * \param use_tsig If TSIG should be used. 
 *
 * \todo Parameter use_tsig probably not needed.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_ixfr_query(const knot_zone_contents_t *zone, 
                            knot_ns_xfr_t *xfr, size_t *size, int use_tsig);

/*!
 * \brief Processes the newly created transferred zone.
 *
 * \param nameserver Name server to update.
 * \param zone Zone build from transfer.
 *
 * \retval KNOT_ENOTSUP
 */
int xfrin_zone_transferred(knot_nameserver_t *nameserver,
                           knot_zone_contents_t *zone);

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
int xfrin_process_axfr_packet(/*const uint8_t *pkt, size_t size,
                              xfrin_constructed_zone_t **zone*/
                              knot_ns_xfr_t *xfr);

void xfrin_free_orphan_rrsigs(xfrin_orphan_rrsig_t **rrsigs);

/*!
 * \brief Destroys the whole changesets structure.
 *
 * Frees all RRSets present in the changesets and all their data. Also frees
 * the changesets structure and sets the parameter to NULL.
 *
 * \param changesets Changesets to destroy.
 */
void xfrin_free_changesets(knot_changesets_t **changesets);

/*!
 * \brief Parses IXFR reply packet and fills in the changesets structure.
 *
 * \param pkt Packet containing the IXFR reply in wire format.
 * \param size Size of the packet in bytes.
 * \param changesets Changesets to be filled in.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_EMALF
 * \retval KNOT_ENOMEM
 */
int xfrin_process_ixfr_packet(knot_ns_xfr_t *xfr/*const uint8_t *pkt, size_t size,
                              knot_changesets_t **changesets*/);

int xfrin_apply_changesets_to_zone(knot_zone_t *zone, 
                                   knot_changesets_t *chsets);

int xfrin_apply_changesets(knot_zone_t *zone,
                           knot_changesets_t *chsets);

#endif /* _KNOTXFR_IN_H_ */

/*! @} */
