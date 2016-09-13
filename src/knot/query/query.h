/*  Copyright (C) 2016 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#pragma once

#include "knot/nameserver/log.h"
#include "libknot/packet/pkt.h"

/*!
 * \brief EDNS data.
 */
struct query_edns_data {
	uint16_t max_payload;

	// Custom EDNS option:
	uint16_t custom_code;
	const uint8_t *custom_data;
	uint16_t custom_len;
};

/*!
 * \brief Initialize new packet.
 *
 * Clear the packet and generate random transaction ID.
 *
 * \param pkt  Packet to initialize.
 *
 * \return Always KNOT_EOK if valid parameters supplied.
 */
int query_init_pkt(knot_pkt_t *pkt);

/*!
 * \brief Initialize EDNS parameters from server configuration.
 *
 * \param[out] edns           EDNS parameters to initialize.
 * \param[in]  conf           Server configuration.
 * \param[in]  zone           Zone name.
 * \param[in]  remote_family  Address family for remote host.
 *
 * \return KNOT_E*
 */
int query_edns_data_init(struct query_edns_data *edns, conf_t *conf,
                         const knot_dname_t *zone, int remote_family);

/*!
 * \brief Append EDNS into the packet.
 *
 * \param pkt   Packet to add EDNS into.
 * \param edns  EDNS data.
 *
 * \return KNOT_E*
 */
int query_put_edns(knot_pkt_t *pkt, const struct query_edns_data *edns);
