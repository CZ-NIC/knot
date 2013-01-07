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
 * \file netio.h
 *
 * \author Daniel Salzman <daniel.salzman@nic.cz>
 *
 * \brief Networking abstraction for utilities.
 *
 * \addtogroup utils
 * @{
 */

#ifndef _UTILS__NETIO_H_
#define _UTILS__NETIO_H_

#include <arpa/inet.h>			// inet_pton
#include <sys/socket.h>			// AF_INET (BSD)
#include <netinet/in.h>			// in_addr (BSD)

#include "utils/common/params.h"
#include "utils/common/resolv.h"

int get_socktype(const params_t *params, const uint16_t qtype);

int send_msg(const params_t *params, const query_t *query,
             const server_t *server, const uint8_t *data, size_t data_len);

int receive_msg(const params_t *params, const query_t *query,
                int sockfd, uint8_t *out, size_t out_len);

#endif // _UTILS__NETIO_H_
