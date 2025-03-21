/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

#pragma once

#include "knot/query/layer.h"
#include "libknot/packet/pkt.h"

/*!
 * \brief Processing module for packet capture.
 */
const knot_layer_api_t *query_capture_api(void);

/*!
 * \brief Processing module parameters.
 */
struct capture_param {
	knot_pkt_t *sink; /*!< Container for captured response. */
};
