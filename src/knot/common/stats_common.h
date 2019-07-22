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

#include "knot/server/server.h"
#include "knot/nameserver/query_module.h"

typedef uint64_t (*stats_val_f)(server_t *server);

/*!
 * \brief Statistics metrics item.
 */
typedef struct {
	const char *name; /*!< Metrics name. */
	stats_val_f val;  /*!< Metrics value getter. */
} stats_item_t;

typedef struct {
	FILE *fd;
	const list_t *query_modules;
	const knot_dname_t *zone;
	bool zone_emitted;
} dump_ctx_t;

uint64_t server_zone_count(server_t *server);

/*!
 * \brief Basic server metrics.
 */
extern const stats_item_t server_stats[];