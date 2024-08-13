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

#include <stddef.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>

#include "utils/kxdpgun/main.h"

#define RCODE_MAX (0x0F + 1)

typedef struct {
	size_t		collected;
	uint64_t	duration;
	uint64_t	qry_sent;
	uint64_t	synack_recv;
	uint64_t	ans_recv;
	uint64_t	finack_recv;
	uint64_t	rst_recv;
	uint64_t	size_recv;
	uint64_t	wire_recv;
	uint64_t	errors;
	uint64_t	lost;
	uint64_t	rcodes_recv[RCODE_MAX];
	pthread_mutex_t	mutex;
} kxdpgun_stats_t;

void clear_stats(kxdpgun_stats_t *st);
size_t collect_stats(kxdpgun_stats_t *into, const kxdpgun_stats_t *what);

void print_stats_header(const xdp_gun_ctx_t *ctx);

void print_thrd_summary(const xdp_gun_ctx_t *ctx, const kxdpgun_stats_t *st);

void print_stats(kxdpgun_stats_t *st, const xdp_gun_ctx_t *ctx);
