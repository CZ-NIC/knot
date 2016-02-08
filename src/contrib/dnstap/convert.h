/*  Copyright (C) 2014 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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
/*!
 * \file
 *
 * \brief Dnstap identifiers conversions.
 *
 * \addtogroup dnstap
 * @{
 */

#pragma once

#include <stdbool.h>

#include "contrib/dnstap/dnstap.pb-c.h"

/*!
 * \brief Get Dnstap socket family from the real one.
 */
Dnstap__SocketFamily dt_family_encode(int family);

/*!
 * \brief Get real socket family from the Dnstap one.
 */
int dt_family_decode(Dnstap__SocketFamily dnstap_family);

/*!
 * \brief Get Dnstap protocol from a real one.
 */
Dnstap__SocketProtocol dt_protocol_encode(int protocol);

/*!
 * \brief Get real protocol from the Dnstap one.
 */
int dt_protocol_decode(Dnstap__SocketProtocol dnstap_protocol);

/*!
 * Check if a message type is any type of a query.
 */
bool dt_message_type_is_query(Dnstap__Message__Type type);

/*!
 * Check if a message type is a ny type of a response.
 */
bool dt_message_type_is_response(Dnstap__Message__Type type);

/*! @} */
