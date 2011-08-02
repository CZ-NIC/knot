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
#include "common/lists.h"
#include "common/sockaddr.h"
#include "knot/server/name-server.h"

/*!
 * \brief Pending NOTIFY event.
 * \see dnslib_zone_t.notify_pending
 */
typedef struct notify_ev_t {
	node n;
	int timeout;           /*!< Timeout for events. */
	int retries;           /*!< Number of retries. */
	int msgid;             /*!< ID of pending NOTIFY. */
	sockaddr_t addr;       /*!< Slave server address. */
	struct event_t *timer; /*!< Event timer. */
	dnslib_zone_t *zone;   /*!< Associated zone. */
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
int notify_create_request(const dnslib_zone_contents_t *zone, uint8_t *buffer,
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
int notify_process_request(const dnslib_nameserver_t *nameserver,
                           dnslib_packet_t *notify,
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
int notify_process_response(const dnslib_nameserver_t *nameserver,
                            dnslib_packet_t *notify,
                            sockaddr_t *from,
                            uint8_t *buffer, size_t *size);

#endif /* _KNOT_NOTIFY_H_ */

/*! @} */
