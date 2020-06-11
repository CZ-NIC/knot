/*  Copyright (C) 2020 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
#include <stddef.h>
#include <poll.h>
#include <sys/un.h>

#include "libknot/probe/common.h"

typedef struct knot_probe_pollfd {
	struct pollfd *pfds;
	uint16_t nfds;
} knot_probe_pollfd_t;

/*!
 * \brief Initialize structure that stores connection to probe channels
 * 
 * \param p             Context storage
 * \param channel_count Number of channels
 * 
 * \retval KNOT_EOK    Success
 * \retval KNOT_ENOMEM Not enough memory
 */ 
int knot_probe_init(knot_probe_pollfd_t *p, const uint16_t channel_count);

/*!
 * \brief Bind each channel to unix socket based on path prefix
 * 
 * \param p      Context storage
 * \param prefix Prefix of unix socket path
 * 
 * \retval KNOT_EOK    Success
 * \retval KNOT_EINVAL Wrong prefix
 * \retval KNOT_ECONN  Unable to bind
 */
int knot_probe_bind(knot_probe_pollfd_t *p, const char *prefix);

/*!
 * \brief Close all opened sockets
 * 
 * \param p Context storage
 */
void knot_probe_close(knot_probe_pollfd_t *p);

/*!
 * \brief Free allocated memory
 * 
 * \param p Context storage
 */
void knot_probe_deinit(knot_probe_pollfd_t *p);

