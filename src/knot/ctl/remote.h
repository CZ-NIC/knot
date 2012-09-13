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

#include "knot/conf/conf.h"
#include "knot/server/server.h"
#include "libknot/packet/packet.h"
#include "libknot/rrset.h"
#include "libknot/rdata.h"

int remote_bind(conf_iface_t *desc);
int remote_unbind(int r);
int remote_poll(int r);
int remote_recv(server_t *s, sockaddr_t *a, int r, uint8_t* buf, size_t buflen);
int remote_answer(server_t *s, knot_packet_t *pkt);

knot_packet_t* remote_query(const char *query);
int remote_query_append(knot_packet_t *qry, knot_rrset_t *data);
int remote_query_sign(knot_packet_t *qry, knot_key_t *key);

knot_rrset_t* remote_build_rr(const char *k, uint16_t t);
knot_rdata_t* remote_create_txt(const char *v);
knot_rdata_t* remote_create_cname(const char *d);

//knot_rrset_t* remote_build_cname(const char *k, const char *v);

#endif // _KNOTD_REMOTE_H_

/*! @} */
