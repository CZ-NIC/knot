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
 * \brief XDP filter configuration constants.
 *
 * \addtogroup xdp
 * @{
 */

#pragma once

#include <linux/types.h>

/*! \brief XDP filter configuration flags. */
typedef enum {
	KNOT_XDP_FILTER_UDP   = 1 << 1,  /*!< Apply filter to UDP. */
	KNOT_XDP_FILTER_TCP   = 1 << 2,  /*!< Apply filter to TCP. */
	KNOT_XDP_FILTER_QUIC  = 1 << 3,  /*!< Apply filter to QUIC/UDP. */
	KNOT_XDP_FILTER_PASS  = 1 << 4,  /*!< Pass incoming messages to ports >= port value. */
	KNOT_XDP_FILTER_DROP  = 1 << 5,  /*!< Drop incoming messages to ports >= port value. */
	KNOT_XDP_FILTER_ROUTE = 1 << 6,  /*!< Consider routing information from kernel. */
} knot_xdp_filter_flag_t;

/*! \brief XDP map item for the filter configuration. */
typedef struct knot_xdp_opts knot_xdp_opts_t;
struct knot_xdp_opts {
	__u16 flags;     /*!< XDP filter flags \a knot_xdp_filter_flag_t. */
	__u16 udp_port;  /*!< UDP/TCP port to listen on. */
	__u16 quic_port; /*!< QUIC/UDP port to listen on. */
} __attribute__((packed));

/*! @} */
