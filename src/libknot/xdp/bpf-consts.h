/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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

#define KNOT_XDP_PKT_ALIGNMENT	2 /*!< Fix for misaligned access to packet structures. */

/*! \brief XDP filter configuration flags. */
typedef enum {
	KNOT_XDP_FILTER_ON    = 1 << 0,  /*!< Filter enabled. */
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

/*! \brief Additional information from the filter. */
typedef struct knot_xdp_info knot_xdp_info_t;
struct knot_xdp_info {
	__u16 out_if_index; /*!< Index of the output interface (if routing enabled). */
};

/*! @} */
