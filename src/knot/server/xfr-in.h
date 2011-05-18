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

/*!
 * \brief Creates normal query for the given zone name and the SOA type.
 *
 * \param zone_name Name of the zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_soa_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
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
int xfrin_transfer_needed(const dnslib_zone_t *zone,
                          dnslib_packet_t *soa_response);

/*!
 * \brief Creates normal query for the given zone name and the AXFR type.
 *
 * \param zone_name Name of the zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_axfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size);

/*!
 * \brief Creates normal query for the given zone name and the IXFR type.
 *
 * \param zone_name Name of the zone to ask for - the SOA owner.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int xfrin_create_ixfr_query(const dnslib_dname_t *zone_name, uint8_t *buffer,
                            size_t *size);

#endif /* _KNOT_XFR_IN_H_ */

/*! @} */
