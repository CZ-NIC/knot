/*  Copyright (C) 2023 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/conf/conf.h"
#include "knot/nameserver/log.h"
#include "libknot/packet/pkt.h"

/*!
 * \brief EDNS data.
 */
typedef struct {
	uint16_t max_payload;
	bool no_edns;
	bool do_flag;
	bool expire_option;
} query_edns_data_t;

typedef enum {
	QUERY_EDNS_OPT_DO     = 1 << 0,
	QUERY_EDNS_OPT_EXPIRE = 1 << 1,
} query_edns_opt_t;

/*!
 * \brief Initialize new packet.
 *
 * Clear the packet and generate random transaction ID.
 *
 * \param pkt  Packet to initialize.
 */
void query_init_pkt(knot_pkt_t *pkt);

/*!
 * \brief Initialize EDNS parameters from server configuration.
 *
 * \param[in]  conf     Server configuration.
 * \param[in]  remote   Remote parameters.
 * \param[in]  opts     EDNS options.
 *
 * \return EDNS parameters.
 */
query_edns_data_t query_edns_data_init(conf_t *conf, const conf_remote_t *remote,
                                       query_edns_opt_t opts);

/*!
 * \brief Append EDNS into the packet.
 *
 * \param pkt       Packet to add EDNS into.
 * \param edns      EDNS data.
 * \param padding   Add EDNS padding option beforehand.
 *
 * \return KNOT_E*
 */
int query_put_edns(knot_pkt_t *pkt, const query_edns_data_t *edns,
                   bool padding);
