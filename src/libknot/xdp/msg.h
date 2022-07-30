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

/*!
 * \file
 *
 * \brief XDP message description.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include <stdint.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <sys/uio.h>

/*! \brief Message flags. */
typedef enum {
	KNOT_XDP_MSG_IPV6  = (1 << 0), /*!< This packet is a IPv6 (IPv4 otherwise). */
	KNOT_XDP_MSG_TCP   = (1 << 1), /*!< This packet is a TCP (UDP otherwise). */
	KNOT_XDP_MSG_SYN   = (1 << 2), /*!< SYN flag set (TCP only). */
	KNOT_XDP_MSG_ACK   = (1 << 3), /*!< ACK flag set (TCP only). */
	KNOT_XDP_MSG_FIN   = (1 << 4), /*!< FIN flag set (TCP only). */
	KNOT_XDP_MSG_RST   = (1 << 5), /*!< RST flag set (TCP only). */
	KNOT_XDP_MSG_MSS   = (1 << 6), /*!< MSS option in TCP header (TCP only). */
	KNOT_XDP_MSG_WSC   = (1 << 7), /*!< Window Scale option in TCP header. */
} knot_xdp_msg_flag_t;

/*! \brief Packet description with src & dst MAC & IP addrs + DNS payload. */
typedef struct knot_xdp_msg {
	struct sockaddr_in6 ip_from;
	struct sockaddr_in6 ip_to;
	uint8_t eth_from[ETH_ALEN];
	uint8_t eth_to[ETH_ALEN];
	knot_xdp_msg_flag_t flags;
	struct iovec payload;
	uint32_t seqno;
	uint32_t ackno;
	uint16_t mss;
	uint16_t win;
	uint8_t win_scale;
} knot_xdp_msg_t;

/*! @} */
