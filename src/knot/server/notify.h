/*!
 * \file notify.h
 *
 * \author Lubos Slovak <lubos.slovak@nic.cz>
 *
 * \brief NOTIFY request/reply API.
 *
 * \addtogroup query_processing
 * @{
 */

#ifndef _KNOT_NOTIFY_H_
#define _KNOT_NOTIFY_H_

#include <stdint.h>
#include <string.h>

#include "dnslib/zone.h"
#include "dnslib/packet.h"
#include "dnslib/zonedb.h"

/*!
 * \brief Creates a NOTIFY request message for SOA RR of the given zone.
 *
 * \param zone Zone from which to take the SOA RR.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int notify_create_request(const dnslib_zone_t *zone, uint8_t *buffer,
                          size_t *size);

/*!
 * \brief Evaluates incoming NOTIFY request and produces a reply.
 *
 * \param notify (Partially) parsed packet with the NOTIFY request.
 * \param zonedb Zone database of the server.
 * \param zone Zone which is probably out-of-date or NULL if there either is no
 *             zone corresponding to the request or if the zone is up-to-date.
 * \param buffer Buffer to fill the message in.
 * \param size In: available space in the buffer. Out: actual size of the
 *             response message in bytes.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 * \retval KNOT_EMALF
 * \retval KNOT_ERROR
 */
int notify_process_request(dnslib_packet_t *notify,
                           const dnslib_zonedb_t *zonedb,
                           const dnslib_zone_t **zone,
                           uint8_t *buffer, size_t *size);

int notify_process_response(const dnslib_zone_t *zone, dnslib_packet_t *notify);

#endif /* _KNOT_NOTIFY_H_ */

/*! @} */
