/*  Copyright (C) CZ.NIC, z.s.p.o. and contributors
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  For more information, see <https://www.knot-dns.cz/>
 */

/*!
 * \brief Dnstap identifiers conversions.
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
 * Check if a message type is any type of a response.
 */
bool dt_message_type_is_response(Dnstap__Message__Type type);

/*!
 * Check if a message role is any type of an initiator.
 */
bool dt_message_role_is_initiator(Dnstap__Message__Type type);
