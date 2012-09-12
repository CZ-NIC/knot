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
 * \file remote.h
 *
 * \author Marek Vavrusa <marek.vavrusa@nic.cz>
 *
 * \brief Functions for remote control interface.
 *
 * \addtogroup ctl
 * @{
 */

#ifndef _KNOTD_REMOTE_H_
#define _KNOTD_REMOTE_H_

#include "libknot/nameserver/name-server.h"
#include "libknot/packet/packet.h"
#include "knot/conf/conf.h"

int remote_bind(conf_iface_t *desc);
int remote_unbind(int r);
int remote_poll(int r);
int remote_recv(knot_nameserver_t *ns, int r);
int remote_answer(knot_packet_t *pkt);

int remote_query(knot_packet_t **dst, const char *query);
int remote_query_append(knot_packet_t *qry, knot_rrset_t *data);
int remote_query_sign(knot_packet_t *qry, knot_key_t *key);


#endif // _KNOTD_REMOTE_H_

/*! @} */
