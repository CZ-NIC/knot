/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
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
