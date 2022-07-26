/*  Copyright (C) 2022 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include <stdint.h>
#include <sys/socket.h>

/*!
 * \brief Get route to an IPv4/6 from system routing table.
 *
 * \param ip     IPv4 or IPv6 to search route to.
 * \param via    Out: gateway (first hop) on the route, or AF_UNSPEC if same subnet.
 * \param src    Out: local outgoing IP address on the route.
 * \param dev    Out: local network interface on the route (you must pre-allocate IFNAMSIZ bytes!).
 *
 * \return 0 on success, negative errno otherwise.
 */
int ip_route_get(const struct sockaddr_storage *ip,
                 struct sockaddr_storage *via,
                 struct sockaddr_storage *src,
                 char *dev);

/*!
 * \brief Obtain neighbour's MAC addr from system neighbour table.
 *
 * \param ip             IPv4 or IPv6 of the neighbour in question.
 * \param dummy_sendto   Attempt sendto() to target IP in order to let the system fill the neighbour table.
 * \param mac            Out: MAC address of the neighbour (you must pre-allocate ETH_ALEN bytes!).
 *
 * \return 0 on success, -ENOENT if neighbour not found, negative errno otherwise.
 */
int ip_neigh_get(const struct sockaddr_storage *ip, bool dummy_sendto, uint8_t *mac);
