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

#include "knot/zone/zone.h"
#include "libknot/packet/pkt.h"
#include "knot/zone/zonedb.h"
#include "common/lists.h"
#include "common/sockaddr.h"
#include "knot/nameserver/name-server.h"

struct query_data;

#define NOTIFY_TIMEOUT 3 /*!< Interval between NOTIFY retries. */

/*!
 * \brief Creates a NOTIFY request message for SOA RR of the given zone.
 *
 * \param zone Zone for which a query should be created.
 * \param pkt Packet to be written.
 *
 * \retval KNOT_EOK
 * \retval KNOT_ESPACE
 * \retval KNOT_ERROR
 */
int notify_create_request(const zone_t *zone, knot_pkt_t *pkt);

/*!
 * \brief Processes NOTIFY response packet.
 *
 * \param notify Parsed response packet.
 * \param msgid Expected message ID.
 *
 * \retval KNOT_EOK if a valid response was created.
 * \retval KNOT_EINVAL on invalid parameters or packet.
 * \retval KNOT_ERROR on message ID mismatch
 */
int notify_process_response(knot_pkt_t *notify, int msgid);

/*!
 * \brief Answer IN class zone NOTIFY message (RFC1996).
 * \param response
 * \param ns
 * \param qdata
 * \return
 */
int internet_notify(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata);


#endif /* _KNOTD_NOTIFY_H_ */

/*! @} */
