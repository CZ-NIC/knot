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

#ifndef _KNOT_XFR_IN_H_
#define _KNOT_XFR_IN_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/dname.h"
#include "dnslib/zone.h"
#include "dnslib/packet.h"
#include "knot/server/name-server.h"
#include "dnslib/changesets.h"

/*!
 * \brief Creates normal query for the given zone name and the SOA type.
 *
 * \param zone Zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_soa_query(const dnslib_zone_contents_t *zone, uint8_t *buffer,
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
int xfrin_transfer_needed(const dnslib_zone_contents_t *zone,
                          dnslib_packet_t *soa_response);

/*!
 * \brief Creates normal query for the given zone name and the AXFR type.
 *
 * \param zone Zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_axfr_query(const dnslib_zone_contents_t *zone, uint8_t *buffer,
                            size_t *size);

/*!
 * \brief Creates normal query for the given zone name and the IXFR type.
 *
 * \param zone Zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_ixfr_query(const dnslib_zone_contents_t *zone, uint8_t *buffer,
                            size_t *size);

/*!
 * \brief Processes the newly created transferred zone.
 *
 * \param nameserver Name server to update.
 * \param zone Zone build from transfer.
 *
 * \retval KNOT_ENOTSUP
 */
int xfrin_zone_transferred(dnslib_nameserver_t *nameserver,
                           dnslib_zone_contents_t *zone);

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
int xfrin_process_axfr_packet(const uint8_t *pkt, size_t size,
                              dnslib_zone_contents_t **zone);

/*!
 * \brief Destroys the whole changesets structure.
 *
 * Frees all RRSets present in the changesets and all their data. Also frees
 * the changesets structure and sets the parameter to NULL.
 *
 * \param changesets Changesets to destroy.
 */
void xfrin_free_changesets(dnslib_changesets_t **changesets);

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
int xfrin_process_ixfr_packet(const uint8_t *pkt, size_t size,
                              dnslib_changesets_t **changesets);

int xfrin_apply_changesets_to_zone(dnslib_zone_t *zone, 
                                   dnslib_changesets_t *chsets);

#endif /* _KNOT_XFR_IN_H_ */

/*! @} */
