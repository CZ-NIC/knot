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

#ifndef _KNOTD_NOTIFY_H_
#define _KNOTD_NOTIFY_H_

#include <stdint.h>
#include <string.h>

#include "libknot/zone/zone.h"
#include "libknot/packet/packet.h"
#include "libknot/zone/zonedb.h"
#include "common/lists.h"
#include "common/sockaddr.h"
#include "libknot/nameserver/name-server.h"

/*!
 * \brief Pending NOTIFY event.
 * \see knot_zone_t.notify_pending
 */
typedef struct notify_ev_t {
	node n;
	int timeout;           /*!< Timeout for events. */
	int retries;           /*!< Number of retries. */
	int msgid;             /*!< ID of pending NOTIFY. */
	sockaddr_t addr;       /*!< Slave server address. */
	sockaddr_t saddr;      /*!< Transit interface address. */
	struct event_t *timer; /*!< Event timer. */
	knot_zone_t *zone;   /*!< Associated zone. */
} notify_ev_t;

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
int notify_create_request(const knot_zone_contents_t *zone, uint8_t *buffer,
                          size_t *size);

/*!
 * \brief Creates a response for NOTIFY query.
 *
 * Valid NOTIFY query expires REFRESH timer for received qname.
 *
 * \see RFC1996 for query and response format.
 *
 * \param nameserver Name server structure to provide the needed data.
 * \param query Response structure with parsed query.
 * \param response_wire Place for the response in wire format.
 * \param rsize Input: maximum acceptable size of the response. Output: real
 *              size of the response.
 *
 * \retval KNOT_EOK if a valid response was created.
 * \retval KNOT_EACCES sender is not authorized to request NOTIFY.
 * \retval KNOT_EMALF if an error occured and the response is not valid.
 */
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
int notify_process_request(knot_nameserver_t *nameserver,
                           knot_packet_t *notify,
                           sockaddr_t *from,
                           uint8_t *buffer, size_t *size);

/*!
 * \brief Processes NOTIFY response packet.
 *
 * \param nameserver Name server structure to provide the needed data.
 * \param from Address of the response sender.
 * \param packet Parsed response packet.
 * \param response_wire Place for the response in wire format.
 * \param rsize Input: maximum acceptable size of the response. Output: real
 *              size of the response.
 *
 * \retval KNOT_EOK if a valid response was created.
 * \retval KNOT_EINVAL on invalid parameters or packet.
 * \retval KNOT_EMALF if an error occured and the response is not valid.
 */
int notify_process_response(knot_nameserver_t *nameserver,
                            knot_packet_t *notify,
                            sockaddr_t *from,
                            uint8_t *buffer, size_t *size);

#endif /* _KNOTD_NOTIFY_H_ */

/*! @} */
