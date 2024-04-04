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

/*!
 * \brief Server statistics general API.
 */

#pragma once

#include "contrib/atomic.h"
#include "knot/server/server.h"

/*!
 * \brief Parameters for a statistic metric dump callback.
 */
typedef struct {
	const char *section;
	const char *item;
	const char *id;
	const char *zone;
	uint64_t value;
	unsigned value_pos; // Counted from 0.

	bool module_begin; // Indication of a new module.
	bool item_begin; // Indication of a new item.
} stats_dump_params_t;

/*!
 * \brief Statistic metric context.
 */
typedef struct {
	server_t *server;
	zone_t *zone;
	const list_t *query_modules;

	const char *section; // Optional section specification.
	const char *item; // Optional item specification.
	bool match; // Indication of non-empty [[section[.item]] selection.

	unsigned threads; // Internal cache for the number of workers.

	void *ctx;
} stats_dump_ctx_t;

/*!
 * \brief Statistic metric dump callback.
 */
typedef int (*stats_dump_ctr_f)(stats_dump_params_t *, stats_dump_ctx_t *);

/*!
 * \brief XDP metrics.
 */
int stats_xdp(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx);

/*!
 * \brief Server metrics.
 */
int stats_server(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx);

/*!
 * \brief Zone metrics.
 */
int stats_zone(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx);

/*!
 * \brief Modules metrics.
 */
int stats_modules(stats_dump_ctr_f fcn, stats_dump_ctx_t *ctx);

/*!
 * \brief Reconfigures the statistics facility.
 */
void stats_reconfigure(conf_t *conf, server_t *server);

/*!
 * \brief Deinitializes the statistics facility.
 */
void stats_deinit(void);
