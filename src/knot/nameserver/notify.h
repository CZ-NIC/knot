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

struct query_data;

#define NOTIFY_TIMEOUT 3 /*!< Interval between NOTIFY retries. */

/*!
 * \brief Creates a NOTIFY request message for SOA RR of the given zone.
 *
 * \param zone Zone for which a query should be created.
 *
 * \return new packet
 */
knot_pkt_t *notify_create_query(const zone_t *zone, mm_ctx_t *mm);

/*!
 * \brief Answer IN class zone NOTIFY message (RFC1996).
 *
 * \retval FAIL if it encountered an error.
 * \retval DONE if finished.
 */
int internet_notify(knot_pkt_t *pkt, struct query_data *qdata);


#endif /* _KNOTD_NOTIFY_H_ */

/*! @} */
