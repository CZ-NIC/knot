/*!
 * \file internet.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief IN zone lookup.
 *
 * \addtogroup query_processing
 * @{
 */
/*  Copyright (C) 2013 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#ifndef _KNOT_INTERNET_H_
#define _KNOT_INTERNET_H_

#include "libknot/packet/pkt.h"
#include "libknot/zone/zonedb.h"
#include "libknot/nameserver/name-server.h"

/* Query data (from query processing). */
struct query_data;

/*!
 * \brief Answer query from IN class zone.
 */
int internet_answer(knot_pkt_t *resp, struct query_data *qdata);

/*!
 * \brief Answer IN class zone NOTIFY message (RFC1996).
 * \param response
 * \param ns
 * \param qdata
 * \return
 */
int internet_notify(knot_pkt_t *pkt, knot_nameserver_t *ns, struct query_data *qdata);

#endif /* _KNOT_INTERNET_H_ */

/*! @} */
