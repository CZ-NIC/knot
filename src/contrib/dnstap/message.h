/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
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
                    const struct timespec       *mtime);
