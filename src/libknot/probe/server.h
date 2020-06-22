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

#include "libknot/probe/data.h"

typedef struct knot_probe_channel_wo {
	struct sockaddr_un path;
	int socket;
} knot_probe_channel_t;

/*!
 * \brief Initialize probe channel
 *
 * \param s    Channel context
 * \param path Unix socket path
 * \param id   Channel ID
 *
 * \retval KNOT_EOK   Success
 * \retval KNOT_ECONN Unable to connect
 */
int knot_probe_channel_init(knot_probe_channel_t *s, const char *path, const uint16_t id);

/*!
 * \brief Send data over channel
 *
 * \param s     Channel context
 * \param base  Data base
 * \param len   Data base length
 * \param flags Optional flags
 *
 * \retval Number of sent bytes if grather equals 0, errorcode if negative
 */
int knot_probe_channel_send(const knot_probe_channel_t *s, const uint8_t *base, const size_t len, const int flags);

/*!
 * \brief Close channel
 *
 * \param s Channel context
 */
void knot_probe_channel_close(knot_probe_channel_t *s);
