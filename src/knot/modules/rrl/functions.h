/*  Copyright (C) 2024 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include "knot/include/module.h"

typedef struct rrl_table rrl_table_t;

/*!
 * \brief Create a RRL table.
 *
 * \param size Fixed table size.
 * \param instant_limit Instant limit.
 * \param rate_limit Rate limit.
 * \param rw_mode If disabled, RW operation is divided into R and W operations.
 * \param log_period If nonzero, maximum logging period (in milliseconds).
 *
 * \return created table or NULL.
 */
rrl_table_t *rrl_create(size_t size, uint32_t instant_limit, uint32_t rate_limit,
                        bool rw_mode, uint32_t log_period);

typedef struct {
	knotd_mod_t *mod;
	knotd_qdata_t *qdata;      // For rate limiting.
	knotd_query_proto_t proto; // For time limiting.
} rrl_log_params_t;

/*!
 * \brief Query the RRL table for accept or deny, when the rate limit is reached.
 *
 * \note This function is common to both RW and non-RW modes!
 *
 * \param rrl RRL table.
 * \param remote Source address.
 * \param log Logging parameters (can be NULL).
 *
 * \retval KNOT_EOK if passed.
 * \retval KNOT_ELIMIT when the limit is reached.
 */
int rrl_query(rrl_table_t *rrl, const struct sockaddr_storage *remote, rrl_log_params_t *log);

/*!
 * \brief Update the RRL table.
 *
 * \note This function is only for the non-RW mode!
 *
 * \param rrl RRL table.
 * \param remote Source address.
 * \param value Value with which the table is updated.
 */
void rrl_update(rrl_table_t *rrl, const struct sockaddr_storage *remote, size_t value);

/*!
 * \brief Roll a dice whether answer slips or not.
 *
 * \param n_slip Number represents every Nth answer that is slipped.
 *
 * \return true or false
 */
bool rrl_slip_roll(int n_slip);

/*!
 * \brief Destroy RRL table.
 *
 * \param rrl RRL table.
 */
void rrl_destroy(rrl_table_t *rrl);
