/*  Copyright (C) 2017 Farsight Security, Inc. <software@farsightsecurity.com>

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
 * \author Robert Edmonds <edmonds@fsi.io>
 *
 * \brief Dnstap message interface.
 */

#pragma once

#include <sys/socket.h>
#include <sys/time.h>
#include <stddef.h>

#include "contrib/dnstap/dnstap.pb-c.h"

/*!
 * \brief Fill a Dnstap__Message structure with the given parameters.
 *
 * \param[out] m
 *      Dnstap__Message structure to fill. Will be zeroed first.
 * \param type
 *      One of the DNSTAP__MESSAGE__TYPE__* values.
 * \param query_sa
 *      sockaddr_in or sockaddr_in6 to use when filling the 'socket_family',
 *      'query_address', 'query_port' fields.
 * \param response_sa
 *      sockaddr_in or sockaddr_in6 to use when filling the 'socket_family',
 *      'response_address', 'response_port' fields.
 * \param protocol
 *      \c IPPROTO_UDP or \c IPPROTO_TCP.
 * \param wire
 *	Wire-format query message or response message (depending on 'type').
 * \param len_wire
 *	Length in bytes of 'wire'.
 * \param mtime
 *	Message time. May be NULL.
 * \param wire2
 * Wire-format request message received (used only when logging query and response in same message)
 * \param len_wire2
 * Length in bytes of 'wire2'.
 * \param mtime2
 * Request message time.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int dt_message_fill(Dnstap__Message             *m,
                    const Dnstap__Message__Type type,
                    const struct sockaddr       *query_sa,
                    const struct sockaddr       *response_sa,
                    const int                   protocol,
                    const void                  *wire,
                    const size_t                len_wire,
                    const struct timespec       *mtime,
                    const void                  *wire2,
                    const size_t                len_wire2,
                    const struct timespec       *mtime2);
