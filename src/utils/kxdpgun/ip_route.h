/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
