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

#include "knot/server/server.h"

typedef uint64_t (*stats_val_f)(server_t *server);

/*!
 * \brief Statistics metrics item.
 */
typedef struct {
	const char *name; /*!< Metrics name. */
	stats_val_f val;  /*!< Metrics value getter. */
} stats_item_t;

/*!
 * \brief Basic server metrics.
 */
extern const stats_item_t server_stats[];

/*!
 * \brief Reconfigures the statistics facility.
 */
void stats_reconfigure(conf_t *conf, server_t *server);

/*!
 * \brief Deinitializes the statistics facility.
 */
void stats_deinit(void);
