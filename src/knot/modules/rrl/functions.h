/*  Copyright (C) 2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <pthread.h>
#include <sys/socket.h>

#include "libknot/libknot.h"
#include "knot/include/module.h"
#include "contrib/openbsd/siphash.h"
#include "knot/modules/rrl/kru.h"


typedef struct rrl_table rrl_table_t;

/*! \brief RRL request flags. */
typedef enum {
	RRL_REQ_NOFLAG    = 0 << 0, /*!< No flags. */
	RRL_REQ_WILDCARD  = 1 << 1  /*!< Query to wildcard name. */
} rrl_req_flag_t;

/*!
 * \brief RRL request descriptor.
 */
typedef struct {
	const uint8_t *wire;
	uint16_t len;
	rrl_req_flag_t flags;
	knot_pkt_t *query;
} rrl_req_t;

/*!
 * \brief Create a RRL table.
 * \param size Fixed table size.
 * \param rate Rate (in pkts/sec).
 * \return created table or NULL.
 */
rrl_table_t *rrl_create(size_t size, uint32_t instant_limit, uint32_t rate_limit);

/*!
 * \brief Query the RRL table for accept or deny, when the rate limit is reached.
 *
 * \param rrl RRL table.
 * \param remote Source address.
 * \param req RRL request (containing resp., flags and question).
 * \param zone Zone name related to the response (or NULL).
 * \param mod Query module (needed for logging).
 * \retval KNOT_EOK if passed.
 * \retval KNOT_ELIMIT when the limit is reached.
 */
int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *remote,
              rrl_req_t *req, const knot_dname_t *zone, knotd_mod_t *mod);

/*!
 * \brief Roll a dice whether answer slips or not.
 * \param n_slip Number represents every Nth answer that is slipped.
 * \return true or false
 */
bool rrl_slip_roll(int n_slip);

/*!
 * \brief Destroy RRL table.
 * \param rrl RRL table.
 */
void rrl_destroy(rrl_table_t *rrl);
