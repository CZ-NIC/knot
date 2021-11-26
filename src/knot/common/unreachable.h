/*  Copyright (C) 2021 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>

#include "contrib/sockaddr.h"

#define KNOT_UNREACHABLE_COUNT 16

typedef struct {
	struct sockaddr_storage addr;
	uint32_t time;
} knot_unreachable_t;

typedef struct {
	pthread_mutex_t mutex;
	uint32_t ttl;
	knot_unreachable_t urs[];
} knot_unreachables_t;

extern knot_unreachables_t *global_unreachables;

/*!
 * \brief Allocate Unreachables structure.
 *
 * \param ttl   TTL for unreachable in usecs.
 *
 * \return Allocated structure, or NULL.
 */
knot_unreachables_t *knot_unreachables_init(uint32_t ttl);

/*!
 * \brief Free Unreachables structure.
 */
void knot_unreachables_deinit(knot_unreachables_t **urs);

/*!
 * \brief Determine if given address is unreachable.
 *
 * \param urs     Unreachables structure.
 * \param addr    Address and port in question.
 *
 * \return True iff unreachable within TTL.
 */
bool knot_unreachable_is(knot_unreachables_t *urs,
                         const struct sockaddr_storage *addr);

/*!
 * \brief Add an unreachable into Unreachables structure.
 *
 * \param urs     Unreachables structure.
 * \param addr    Address and port being unreachable.
 */
void knot_unreachable_add(knot_unreachables_t *urs,
                          const struct sockaddr_storage *addr);
